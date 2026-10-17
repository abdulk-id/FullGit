//! Remote configuration. Network transfer itself is done by the system `git`.

use git2::Repository;

use crate::Result;
use crate::refs;

/// Adds the fullgit fetch refspec to `remote` so plain `git fetch` also
/// fetches `refs/fullgit/*`, and moves a clone off the old layout. Returns
/// `false` if it was already present.
///
/// No push refspec is added: setting `remote.<name>.push` would change what a
/// bare `git push` pushes.
pub fn install_fetch_refspec(repo: &Repository, remote: &str) -> Result<bool> {
    drop_legacy(repo, remote)?;
    let spec = refs::fetch_refspec(remote);
    if has_refspec(repo, remote, &spec)? {
        return Ok(false);
    }
    repo.remote_add_fetch(remote, &spec)?;
    Ok(true)
}

pub fn has_refspec(repo: &Repository, remote: &str, spec: &str) -> Result<bool> {
    Ok(repo
        .find_remote(remote)?
        .fetch_refspecs()?
        .iter()
        .any(|s| matches!(s, Ok(Some(s)) if s == spec)))
}

/// Whether `remote` still fetches fullgit's refs into remote branches.
pub fn is_legacy(repo: &Repository, remote: &str) -> Result<bool> {
    Ok(
        has_refspec(repo, remote, &refs::legacy_fetch_refspec(remote))?
            || repo
                .references_glob(&format!("{}*", refs::legacy_tracking_prefix(remote)))?
                .next()
                .is_some(),
    )
}

/// Removes the old refspec and the remote branches it fetched. They only
/// mirror the remote, so nothing is lost: the next fetch fills the new
/// place.
fn drop_legacy(repo: &Repository, remote: &str) -> Result<()> {
    let legacy = refs::legacy_fetch_refspec(remote);
    if has_refspec(repo, remote, &legacy)? {
        let pattern: String = legacy
            .chars()
            .flat_map(|c| match c {
                '.' | '[' | ']' | '{' | '}' | '(' | ')' | '\\' | '*' | '+' | '?' | '^' | '$'
                | '|' => vec!['\\', c],
                c => vec![c],
            })
            .collect();
        repo.config()?
            .remove_multivar(&format!("remote.{remote}.fetch"), &format!("^{pattern}$"))?;
    }
    let mut names = Vec::new();
    for r in repo.references_glob(&format!("{}*", refs::legacy_tracking_prefix(remote)))? {
        names.push(r?.name()?.to_owned());
    }
    for name in names {
        repo.find_reference(&name)?.delete()?;
    }
    Ok(())
}
