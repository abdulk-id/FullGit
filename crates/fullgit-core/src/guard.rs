//! What the pre-commit and pre-push hooks refuse: secrets that aren't
//! sealed, and per-user files, which belong in their owner's snapshot.
//! Files are classified by the current `.gitattributes`.

use std::path::Path;

use git2::{Oid, Repository};

use crate::Result;
use crate::local;
use crate::secret::{DRIVER, Sealed};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leak {
    /// A secret stored in plaintext.
    Unsealed,
    /// A per-user file.
    Local,
}

impl Leak {
    pub fn describe(self) -> &'static str {
        match self {
            Leak::Unsealed => "unencrypted secret",
            Leak::Local => "per-user file",
        }
    }
}

/// Whether storing `blob` at `path` would leak it.
fn classify(repo: &Repository, path: &Path, blob: Oid) -> Result<Option<Leak>> {
    if local::is_local(repo, path)? {
        return Ok(Some(Leak::Local));
    }
    let flags = git2::AttrCheckFlags::FILE_THEN_INDEX;
    if repo.get_attr(path, "filter", flags)? == Some(DRIVER)
        && !Sealed::is_sealed(repo.find_blob(blob)?.content())
    {
        return Ok(Some(Leak::Unsealed));
    }
    Ok(None)
}

/// Leaks staged in the index, e.g. because the filter wasn't configured
/// when a secret was added.
pub fn in_index(repo: &Repository) -> Result<Vec<(String, Leak)>> {
    let index = repo.index()?;
    let mut out = Vec::new();
    for e in index.iter() {
        let path = String::from_utf8_lossy(&e.path).into_owned();
        if let Some(leak) = classify(repo, Path::new(&path), e.id)? {
            out.push((path, leak));
        }
    }
    out.dedup_by(|a, b| a.0 == b.0); // conflicted paths have several stages
    Ok(out)
}

/// Leaks added by the commits reachable from `tip` but not from `hide`
/// (refs or globs, e.g. what the remote already has). Each commit is
/// compared with its first parent.
pub fn in_commits(
    repo: &Repository,
    tip: Oid,
    hide: &[Oid],
    hide_globs: &[&str],
) -> Result<Vec<(Oid, String, Leak)>> {
    let mut walk = repo.revwalk()?;
    walk.push(tip)?;
    for id in hide {
        // The remote may know commits we don't.
        if repo.find_commit(*id).is_ok() {
            walk.hide(*id)?;
        }
    }
    for glob in hide_globs {
        walk.hide_glob(glob)?;
    }
    let mut out = Vec::new();
    for id in walk {
        let commit = repo.find_commit(id?)?;
        let tree = commit.tree()?;
        let parent = match commit.parents().next() {
            Some(p) => Some(p.tree()?),
            None => None,
        };
        let diff = repo.diff_tree_to_tree(parent.as_ref(), Some(&tree), None)?;
        for delta in diff.deltas() {
            let file = delta.new_file();
            let (Some(path), false) = (file.path(), file.id().is_zero()) else {
                continue;
            };
            if let Some(leak) = classify(repo, path, file.id())? {
                out.push((commit.id(), path.display().to_string(), leak));
            }
        }
    }
    Ok(out)
}
