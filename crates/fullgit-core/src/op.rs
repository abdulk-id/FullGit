//! A single operation, stored as one signed git commit whose tree holds `op.json`.

use git2::{Oid, Repository};
use serde::{Deserialize, Serialize};
use ssh_key::public::KeyData;

use crate::sign::{self, Signer};
use crate::{Error, Result};

pub const OP_FILE: &str = "op.json";
pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Op {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub lamport: u64,
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// An operation read back from the repository, with its verified signer.
#[derive(Debug, Clone)]
pub struct StoredOp {
    pub id: Oid,
    pub parents: Vec<Oid>,
    pub op: Op,
    /// Key material only; a key's comment isn't part of its identity.
    pub signer: KeyData,
}

/// Writes a signed operation commit on top of `parents`. Does not move any
/// ref; see [`crate::entity::append`].
pub fn write_op(
    repo: &Repository,
    signer: &dyn Signer,
    parents: &[Oid],
    kind: &str,
    payload: serde_json::Value,
) -> Result<Oid> {
    let parent_commits = parents
        .iter()
        .map(|id| repo.find_commit(*id))
        .collect::<Result<Vec<_>, _>>()?;
    let mut lamport = 0;
    for id in parents {
        lamport = lamport.max(read_op(repo, *id)?.op.lamport);
    }
    let op = Op {
        v: FORMAT_VERSION,
        kind: kind.to_owned(),
        lamport: lamport + 1,
        payload,
    };

    let blob = repo.blob(&serde_json::to_vec_pretty(&op)?)?;
    let mut tree = repo.treebuilder(None)?;
    tree.insert(OP_FILE, blob, git2::FileMode::Blob.into())?;
    let tree = repo.find_tree(tree.write()?)?;

    let who = repo
        .signature()
        .or_else(|_| git2::Signature::now("fullgit", "fullgit@localhost"))?;
    let parent_refs: Vec<_> = parent_commits.iter().collect();
    let buf = repo.commit_create_buffer(&who, &who, kind, &tree, &parent_refs)?;
    let content = std::str::from_utf8(&buf)
        .map_err(|e| Error::Signature(format!("commit buffer is not UTF-8: {e}")))?;
    let signature = signer.sign(content.as_bytes())?;
    Ok(repo.commit_signed(content, &signature, None)?)
}

/// Reads an operation and verifies its signature. Unsigned or tampered
/// commits are errors.
pub fn read_op(repo: &Repository, id: Oid) -> Result<StoredOp> {
    let malformed = |reason: String| Error::Malformed { oid: id, reason };

    let (signature, signed) = repo
        .extract_signature(&id, None)
        .map_err(|_| malformed("commit is not signed".into()))?;
    let signature = signature
        .as_str()
        .map_err(|_| malformed("signature is not UTF-8".into()))?;
    let signer =
        sign::verify(&signed, signature).map_err(|e| malformed(format!("bad signature: {e}")))?;

    let commit = repo.find_commit(id)?;
    let tree = commit.tree()?;
    if tree.len() != 1 {
        return Err(malformed(format!("expected only {OP_FILE} in tree")));
    }
    let entry = tree
        .get_name(OP_FILE)
        .ok_or_else(|| malformed(format!("missing {OP_FILE}")))?;
    let blob = repo.find_blob(entry.id())?;
    let op: Op = serde_json::from_slice(blob.content())
        .map_err(|e| malformed(format!("invalid {OP_FILE}: {e}")))?;
    if op.v != FORMAT_VERSION {
        return Err(malformed(format!("unsupported format version {}", op.v)));
    }

    Ok(StoredOp {
        id,
        parents: commit.parent_ids().collect(),
        op,
        signer,
    })
}
