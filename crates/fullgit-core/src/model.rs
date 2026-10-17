//! Typed entities. A [`Model`] folds an entity's operations, in replay
//! order, into its current state. Each entity lives at
//! `refs/fullgit/<NAMESPACE>/<id>`, where `<id>` is its root operation's oid.

use std::time::{SystemTime, UNIX_EPOCH};

use git2::{Oid, Repository};

use crate::entity::{self, MERGE_KIND};
use crate::op::{StoredOp, write_op};
use crate::refs;
use crate::sign::Signer;
use crate::{Error, Result};

pub trait Model: Default {
    /// Ref namespace under `refs/fullgit/`, e.g. `issues`.
    const NAMESPACE: &'static str;

    /// Applies one operation. `op.parents.is_empty()` marks the root.
    /// Returning `Err` rejects the operation; every replica rejects the same
    /// operations, so state stays identical everywhere.
    fn apply(&mut self, op: &StoredOp) -> Result<(), String>;
}

/// An operation that was skipped during replay, and why.
#[derive(Debug, Clone)]
pub struct Rejected {
    pub op: Oid,
    pub reason: String,
}

#[derive(Debug)]
pub struct Loaded<M> {
    pub id: Oid,
    pub head: Oid,
    pub model: M,
    pub ops: Vec<StoredOp>,
    pub rejected: Vec<Rejected>,
}

pub fn refname<M: Model>(id: Oid) -> String {
    format!("{}{}/{id}", refs::PREFIX, M::NAMESPACE)
}

/// Creates a new entity from a root operation and returns its id.
pub fn create<M: Model>(
    repo: &Repository,
    signer: &dyn Signer,
    kind: &str,
    mut payload: serde_json::Value,
) -> Result<Oid> {
    // Two identical creations in the same second would otherwise produce the
    // same commit, and so the same entity.
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("nonce".into(), nonce().into());
    }
    let id = write_op(repo, signer, &[], kind, payload)?;
    let root = crate::op::read_op(repo, id)?;
    M::default()
        .apply(&root)
        .map_err(|reason| Error::Rejected { op: id, reason })?;
    repo.reference(&refname::<M>(id), id, false, &format!("fullgit: {kind}"))?;
    Ok(id)
}

/// Appends an operation to an existing entity. The operation is applied to
/// the current state first, so one that every replica would reject is never
/// written.
pub fn update<M: Model>(
    repo: &Repository,
    id: Oid,
    signer: &dyn Signer,
    kind: &str,
    payload: serde_json::Value,
) -> Result<Oid> {
    let mut current = load::<M>(repo, id)?;
    let op_id = write_op(repo, signer, &[current.head], kind, payload)?;
    let op = crate::op::read_op(repo, op_id)?;
    current
        .model
        .apply(&op)
        .map_err(|reason| Error::Rejected { op: op_id, reason })?;
    repo.reference_matching(
        &refname::<M>(id),
        op_id,
        true,
        current.head,
        &format!("fullgit: {kind}"),
    )
    .map_err(|e| match e.code() {
        git2::ErrorCode::Modified => Error::Conflict(refname::<M>(id)),
        _ => e.into(),
    })?;
    Ok(op_id)
}

pub fn load<M: Model>(repo: &Repository, id: Oid) -> Result<Loaded<M>> {
    let head = repo
        .refname_to_id(&refname::<M>(id))
        .map_err(|_| Error::NotFound(id.to_string()))?;
    let ops = entity::load(repo, &[head])?;
    if ops.first().map(|o| o.id) != Some(id) {
        return Err(Error::Malformed {
            oid: head,
            reason: format!("entity root is not {id}"),
        });
    }

    let mut model = M::default();
    let mut rejected = Vec::new();
    for op in &ops {
        if op.op.kind == MERGE_KIND {
            continue;
        }
        if let Err(reason) = model.apply(op) {
            if op.id == id {
                return Err(Error::Rejected { op: id, reason });
            }
            rejected.push(Rejected { op: op.id, reason });
        }
    }
    Ok(Loaded {
        id,
        head,
        model,
        ops,
        rejected,
    })
}

/// Ids of all local entities of this type, sorted.
pub fn list<M: Model>(repo: &Repository) -> Result<Vec<Oid>> {
    let prefix = format!("{}{}/", refs::PREFIX, M::NAMESPACE);
    let mut ids = Vec::new();
    for r in repo.references_glob(&format!("{prefix}*"))? {
        let r = r?;
        if let Some(id) = r.name().ok().and_then(|n| n.strip_prefix(&prefix))
            && let Ok(id) = Oid::from_str(id)
        {
            ids.push(id);
        }
    }
    ids.sort();
    Ok(ids)
}

/// Resolves a full id or a unique hex prefix (at least 4 characters).
pub fn resolve<M: Model>(repo: &Repository, prefix: &str) -> Result<Oid> {
    let prefix = prefix.to_ascii_lowercase();
    if prefix.len() < 4 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::NotFound(prefix));
    }
    let matches: Vec<_> = list::<M>(repo)?
        .into_iter()
        .filter(|id| id.to_string().starts_with(&prefix))
        .collect();
    match matches.as_slice() {
        [id] => Ok(*id),
        [] => Err(Error::NotFound(prefix)),
        _ => Err(Error::Ambiguous(prefix)),
    }
}

fn nonce() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:x}{:x}", t.as_nanos(), std::process::id())
}
