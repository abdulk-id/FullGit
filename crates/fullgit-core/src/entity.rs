//! An entity is a DAG of operations reachable from one ref. Replay order is
//! deterministic: topological, ties broken by `(lamport, oid)`.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};

use git2::{Oid, Repository};

use crate::op::{StoredOp, read_op, write_op};
use crate::refs;
use crate::sign::Signer;
use crate::{Error, Result};

pub const MERGE_KIND: &str = "merge";

/// Appends an operation to the entity at `refname`, creating the ref if
/// needed. Fails with [`Error::Conflict`] if the ref moves underneath us.
pub fn append(
    repo: &Repository,
    refname: &str,
    signer: &dyn Signer,
    kind: &str,
    payload: serde_json::Value,
) -> Result<Oid> {
    let refname = refs::qualify(refname);
    let head = head_of(repo, &refname)?;
    let id = write_op(repo, signer, head.as_slice(), kind, payload)?;
    update_ref(repo, &refname, id, head, kind)?;
    Ok(id)
}

/// Joins a diverged head (e.g. from a remote) into the entity at `refname`
/// with a signed `merge` operation. Fast-forwards instead when possible.
pub fn merge(repo: &Repository, refname: &str, signer: &dyn Signer, other: Oid) -> Result<Oid> {
    let refname = refs::qualify(refname);
    let Some(local) = head_of(repo, &refname)? else {
        update_ref(repo, &refname, other, None, "fast-forward")?;
        return Ok(other);
    };
    if local == other || repo.graph_descendant_of(local, other)? {
        return Ok(local);
    }
    if repo.graph_descendant_of(other, local)? {
        update_ref(repo, &refname, other, Some(local), "fast-forward")?;
        return Ok(other);
    }
    // Sorted parents keep the merge commit independent of who performs it.
    let mut parents = [local, other];
    parents.sort();
    let id = write_op(repo, signer, &parents, MERGE_KIND, serde_json::Value::Null)?;
    update_ref(repo, &refname, id, Some(local), MERGE_KIND)?;
    Ok(id)
}

/// Loads every operation reachable from `heads` in replay order. Every
/// operation's signature and lamport clock are checked.
pub fn load(repo: &Repository, heads: &[Oid]) -> Result<Vec<StoredOp>> {
    let mut ops: HashMap<Oid, StoredOp> = HashMap::new();
    let mut stack = heads.to_vec();
    while let Some(id) = stack.pop() {
        if ops.contains_key(&id) {
            continue;
        }
        let op = read_op(repo, id)?;
        stack.extend(&op.parents);
        ops.insert(id, op);
    }

    let mut pending: HashMap<Oid, usize> = HashMap::new();
    let mut children: BTreeMap<Oid, Vec<Oid>> = BTreeMap::new();
    for op in ops.values() {
        let expected = 1 + op
            .parents
            .iter()
            .map(|p| ops[p].op.lamport)
            .max()
            .unwrap_or(0);
        if op.op.lamport != expected {
            return Err(Error::Malformed {
                oid: op.id,
                reason: format!("lamport {} but expected {expected}", op.op.lamport),
            });
        }
        pending.insert(op.id, op.parents.len());
        for p in &op.parents {
            children.entry(*p).or_default().push(op.id);
        }
    }

    // Kahn's algorithm with a min-heap so concurrent operations always come
    // out in the same order.
    let mut ready: BinaryHeap<Reverse<(u64, Oid)>> = pending
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(id, _)| Reverse((ops[id].op.lamport, *id)))
        .collect();
    let mut order = Vec::with_capacity(ops.len());
    while let Some(Reverse((_, id))) = ready.pop() {
        for child in children.get(&id).into_iter().flatten() {
            let n = pending.get_mut(child).expect("child is loaded");
            *n -= 1;
            if *n == 0 {
                ready.push(Reverse((ops[child].op.lamport, *child)));
            }
        }
        order.push(ops.remove(&id).expect("each op is emitted once"));
    }
    Ok(order)
}

fn head_of(repo: &Repository, refname: &str) -> Result<Option<Oid>> {
    match repo.refname_to_id(refname) {
        Ok(id) => Ok(Some(id)),
        Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn update_ref(
    repo: &Repository,
    refname: &str,
    new: Oid,
    expected: Option<Oid>,
    msg: &str,
) -> Result<()> {
    let msg = format!("fullgit: {msg}");
    let res = match expected {
        Some(old) => repo.reference_matching(refname, new, true, old, &msg),
        None => repo.reference(refname, new, false, &msg),
    };
    res.map(|_| ()).map_err(|e| match e.code() {
        git2::ErrorCode::Modified | git2::ErrorCode::Exists => Error::Conflict(refname.to_owned()),
        _ => e.into(),
    })
}
