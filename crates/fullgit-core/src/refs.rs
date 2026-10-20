//! Ref namespace layout.

pub const PREFIX: &str = "refs/fullgit/";

/// Accepts either a full ref (`refs/...`) or a path relative to
/// `refs/fullgit/` (e.g. `issues/abc`).
pub fn qualify(name: &str) -> String {
    if name.starts_with("refs/") {
        name.to_owned()
    } else {
        format!("{PREFIX}{name}")
    }
}

/// Where `git fetch <remote>` stores the remote's `refs/fullgit/*`. Not
/// under `refs/remotes/`: git and the tools around it list everything
/// there as a remote branch.
/// Prefix for locally stored copies of a remote's `refs/fullgit/*` heads.
pub fn remote_tracking_prefix(remote: &str) -> String {
    format!("refs/fullgit-remotes/{remote}/")
}

/// Fetch refspec that maps a remote's fullgit refs into [`remote_tracking_prefix`].
pub fn fetch_refspec(remote: &str) -> String {
    format!("+{PREFIX}*:{}*", remote_tracking_prefix(remote))
}

/// Where earlier versions stored them, which showed as remote branches
/// named `fullgit/...`.
pub fn legacy_tracking_prefix(remote: &str) -> String {
    format!("refs/remotes/{remote}/fullgit/")
}

pub fn legacy_fetch_refspec(remote: &str) -> String {
    format!("+{PREFIX}*:{}*", legacy_tracking_prefix(remote))
}

/// Push refspec for mirroring local fullgit refs to the same names on a remote.
pub const PUSH_REFSPEC: &str = "refs/fullgit/*:refs/fullgit/*";

/// Refs that keep a pull request's commits: `refs/fullgit/code/<oid>`
/// points at `<oid>`. Content-addressed, so they never move, and sync
/// accepts one only if its name is its target.
pub const CODE_PREFIX: &str = "refs/fullgit/code/";

/// Content-addressed ref that pins pull-request commit `commit`.
pub fn code_refname(commit: git2::Oid) -> String {
    format!("{CODE_PREFIX}{commit}")
}
