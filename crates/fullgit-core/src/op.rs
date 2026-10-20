//! A single operation, stored as one signed git commit whose tree holds `op.json`.

use git2::{Buf, Oid, Repository};
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
    let parent_commits: Vec<git2::Commit> = parents
        .iter()
        .map(|id| repo.find_commit(*id))
        .collect::<Result<Vec<_>, _>>()?;
    let mut lamport: u64 = 0;
    for id in parents {
        lamport = lamport.max(read_op(repo, *id)?.op.lamport);
    }
    let op: Op = Op {
        v: FORMAT_VERSION,
        kind: kind.to_owned(),
        lamport: lamport + 1,
        payload,
    };

    let blob: Oid = repo.blob(&serde_json::to_vec_pretty(&op)?)?;
    let mut tree: git2::TreeBuilder = repo.treebuilder(None)?;
    tree.insert(OP_FILE, blob, git2::FileMode::Blob.into())?;
    let tree: git2::Tree = repo.find_tree(tree.write()?)?;

    let who: git2::Signature = repo
        .signature()
        .or_else(|_| git2::Signature::now("fullgit", "fullgit@localhost"))?;
    let parent_refs: Vec<&git2::Commit> = parent_commits.iter().collect();
    let buf: Buf = repo.commit_create_buffer(&who, &who, kind, &tree, &parent_refs)?;
    let content: &str = std::str::from_utf8(&buf)
        .map_err(|e| Error::Signature(format!("commit buffer is not UTF-8: {e}")))?;
    let signature: String = signer.sign(content.as_bytes())?;
    Ok(repo.commit_signed(content, &signature, None)?)
}

/// Reads an operation and verifies its signature. Unsigned or tampered
/// commits are errors.
pub fn read_op(repo: &Repository, id: Oid) -> Result<StoredOp> {
    let malformed = |reason: String| Error::Malformed { oid: id, reason };

    let (signature, signed): (Buf, Buf) = repo
        .extract_signature(&id, None)
        .map_err(|_| malformed("commit is not signed".into()))?;
    let signature: &str = signature
        .as_str()
        .map_err(|_| malformed("signature is not UTF-8".into()))?;
    let signer: KeyData = sign::verify(&signed, signature)
        .map_err(|e| malformed(format!("bad signature: {e}")))?;

    let commit: git2::Commit = repo.find_commit(id)?;
    let tree: git2::Tree = commit.tree()?;
    if tree.len() != 1 {
        return Err(malformed(format!("expected only {OP_FILE} in tree")));
    }
    let entry: git2::TreeEntry = tree
        .get_name(OP_FILE)
        .ok_or_else(|| malformed(format!("missing {OP_FILE}")))?;
    let blob: git2::Blob = repo.find_blob(entry.id())?;
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
