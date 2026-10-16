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

/// Where `git fetch <remote>` stores the remote's `refs/fullgit/*`.
pub fn remote_tracking_prefix(remote: &str) -> String {
    format!("refs/remotes/{remote}/fullgit/")
}

pub fn fetch_refspec(remote: &str) -> String {
    format!("+{PREFIX}*:{}*", remote_tracking_prefix(remote))
}

pub const PUSH_REFSPEC: &str = "refs/fullgit/*:refs/fullgit/*";
