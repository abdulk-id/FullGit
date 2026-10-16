//! Remote configuration. Network transfer itself is done by the system `git`.

use git2::Repository;

use crate::Result;
use crate::refs;

/// Adds the fullgit fetch refspec to `remote` so plain `git fetch` also
/// fetches `refs/fullgit/*`. Returns `false` if it was already present.
///
/// No push refspec is added: setting `remote.<name>.push` would change what a
/// bare `git push` pushes.
pub fn install_fetch_refspec(repo: &Repository, remote: &str) -> Result<bool> {
    let spec = refs::fetch_refspec(remote);
    let existing = repo.find_remote(remote)?.fetch_refspecs()?;
    if existing
        .iter()
        .any(|s| matches!(s, Ok(Some(s)) if s == spec))
    {
        return Ok(false);
    }
    repo.remote_add_fetch(remote, &spec)?;
    Ok(true)
}
