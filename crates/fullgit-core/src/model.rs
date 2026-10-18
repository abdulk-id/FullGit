//! Typed entities. A [`Model`] folds an entity's operations, in replay
//! order, into its current state. Each entity lives at
//! `refs/fullgit/<NAMESPACE>/<id>`, where `<id>` is its root operation's oid.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use git2::{Oid, Repository};

use crate::entity::{self, MERGE_KIND};
use crate::op::{StoredOp, write_op};
use crate::refs;
use crate::sign::Signer;
use crate::trust::{Actor, Trust};
use crate::{Error, Result};

pub trait Model: Default {
    /// Ref namespace under `refs/fullgit/`, e.g. `issues`.
    const NAMESPACE: &'static str;

    /// Whether this kind of entity exists only under a policy. Identities
    /// and the policy itself don't: the policy is made from them.
    const NEEDS_POLICY: bool = true;

    /// Applies one operation. `op.parents.is_empty()` marks the root.
    /// Returning `Err` rejects the operation, and must leave the state
    /// unchanged. Every replica rejects the same operations, so state stays
    /// identical everywhere.
    fn apply(&mut self, op: &StoredOp, ctx: &Ctx) -> Result<(), String>;

    /// Re-checks an applied operation against the final state. Only models
    /// whose own state grants authority (identities, the policy) need this:
    /// a later revocation can take back an operation that was valid when it
    /// was applied.
    fn still_valid(&self, _op: &StoredOp, _ctx: &Ctx) -> Result<(), String> {
        Ok(())
    }
}

/// What a model may consult besides its own state.
pub struct Ctx<'a> {
    pub repo: &'a Repository,
    pub trust: &'a Trust,
    /// The entity being replayed.
    pub entity: Oid,
}

impl Ctx<'_> {
    /// Who signed `op`, and the role they held for it.
    pub fn actor(&self, op: &StoredOp) -> Actor {
        self.trust.actor(self.repo, self.entity, op)
    }
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
    trust: &Trust,
    signer: &dyn Signer,
    kind: &str,
    mut payload: serde_json::Value,
) -> Result<Oid> {
    // Two identical creations in the same second would otherwise produce the
    // same commit, and so the same entity.
    needs_policy::<M>(trust)?;
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("nonce".into(), nonce().into());
    }
    let id = write_op(repo, signer, &[], kind, payload)?;
    let root = crate::op::read_op(repo, id)?;
    let ctx = Ctx {
        repo,
        trust,
        entity: id,
    };
    M::default()
        .apply(&root, &ctx)
        .map_err(|reason| Error::Rejected { op: id, reason })?;
    repo.reference(&refname::<M>(id), id, false, &format!("fullgit: {kind}"))?;
    Ok(id)
}

/// Appends an operation to an existing entity. The operation is applied to
/// the current state first, so one that every replica would reject is never
/// written.
pub fn update<M: Model>(
    repo: &Repository,
    trust: &Trust,
    id: Oid,
    signer: &dyn Signer,
    kind: &str,
    payload: serde_json::Value,
) -> Result<Oid> {
    needs_policy::<M>(trust)?;
    let mut current = load::<M>(repo, trust, id)?;
    let op_id = write_op(repo, signer, &[current.head], kind, payload)?;
    let op = crate::op::read_op(repo, op_id)?;
    let ctx = Ctx {
        repo,
        trust,
        entity: id,
    };
    current
        .model
        .apply(&op, &ctx)
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

/// Fails if `M` needs a policy and the repository has none.
pub fn needs_policy<M: Model>(trust: &Trust) -> Result<()> {
    match M::NEEDS_POLICY && trust.policy.is_none() {
        true => Err(Error::NoPolicy),
        false => Ok(()),
    }
}

pub fn load<M: Model>(repo: &Repository, trust: &Trust, id: Oid) -> Result<Loaded<M>> {
    needs_policy::<M>(trust)?;
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
    let ctx = Ctx {
        repo,
        trust,
        entity: id,
    };

    // Replay, then re-check what was applied against the final state. If an
    // op no longer holds, drop the last such op and replay without it: it
    // may be the revocation that invalidated the others, and is itself
    // invalid. Each round drops one op, so this ends.
    let mut dropped: HashMap<Oid, String> = HashMap::new();
    loop {
        let mut model = M::default();
        let mut rejected = Vec::new();
        let mut applied = Vec::new();
        for op in &ops {
            if op.op.kind == MERGE_KIND {
                continue;
            }
            let result = match dropped.get(&op.id) {
                Some(reason) => Err(reason.clone()),
                None => model.apply(op, &ctx),
            };
            match result {
                Ok(()) => applied.push(op),
                Err(reason) if op.id == id => return Err(Error::Rejected { op: id, reason }),
                Err(reason) => rejected.push(Rejected { op: op.id, reason }),
            }
        }
        let invalid = applied
            .iter()
            .rev()
            .filter(|op| op.id != id)
            .find_map(|op| model.still_valid(op, &ctx).err().map(|r| (op.id, r)));
        match invalid {
            Some((op, reason)) => {
                dropped.insert(op, reason);
            }
            None => {
                return Ok(Loaded {
                    id,
                    head,
                    model,
                    ops,
                    rejected,
                });
            }
        }
    }
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

/// Shortest unique prefixes of a set of ids, the way git abbreviates
/// commits: at least [`Abbrev::MIN`] characters, more where ids share a
/// start. [`resolve`] accepts them.
#[derive(Debug, Clone, Default)]
pub struct Abbrev {
    ids: Vec<String>,
}

impl Abbrev {
    pub const MIN: usize = 4;

    pub fn new(ids: impl IntoIterator<Item = Oid>) -> Self {
        let mut ids: Vec<String> = ids.into_iter().map(|id| id.to_string()).collect();
        ids.sort();
        ids.dedup();
        Abbrev { ids }
    }

    /// `id`'s prefix: one character past what it shares with any other id.
    pub fn of(&self, id: Oid) -> String {
        let id = id.to_string();
        let at = self.ids.partition_point(|x| *x < id);
        let shared = |x: &String| {
            x.bytes()
                .zip(id.bytes())
                .take_while(|(a, b)| a == b)
                .count()
        };
        let neighbours = [at.checked_sub(1), Some(at), Some(at + 1)];
        let len = neighbours
            .into_iter()
            .flatten()
            .filter_map(|i| self.ids.get(i))
            .filter(|x| **x != id)
            .map(|x| shared(x) + 1)
            .fold(Self::MIN, usize::max);
        id[..len.min(id.len())].to_owned()
    }
}

/// Abbreviations for all local entities of this type.
pub fn abbrev<M: Model>(repo: &Repository) -> Result<Abbrev> {
    Ok(Abbrev::new(list::<M>(repo)?))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abbreviations_are_short_and_unique() {
        let id = |s: &str| Oid::from_str(&format!("{s:0<40}")).unwrap();
        let a = Abbrev::new([id("ea14358c"), id("ea15"), id("6a43"), id("ea14359")]);
        assert_eq!(a.of(id("6a43")), "6a43");
        assert_eq!(a.of(id("ea15")), "ea15");
        assert_eq!(a.of(id("ea14358c")), "ea14358");
        assert_eq!(a.of(id("ea14359")), "ea14359");
        // Not in the set: still unique against it.
        assert_eq!(a.of(id("ea1435")), "ea14350");
        assert_eq!(Abbrev::default().of(id("12345678")), "1234");
    }
}
