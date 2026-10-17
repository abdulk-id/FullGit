//! Where a clone keeps the remote's copy of fullgit's refs.

mod cli;

use cli::common::{Fixture, git};
use cli::{fg, fg_ok, user};

/// The remote's refs live outside `refs/remotes/`, so git doesn't list
/// them as branches; `fullgit init` moves a clone set up the old way.
#[test]
fn the_remotes_refs_are_not_branches() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let alice = user(&fx, &remote, "alice");
    fg_ok(&alice, &["issue", "new", "-t", "Hello", "-m", "Hi"]);
    fg_ok(&alice, &["sync"]);
    let branches = git(&alice, &["branch", "-r"]);
    assert!(!branches.contains("fullgit"), "{branches}");
    let ours = git(&alice, &["for-each-ref", "refs/fullgit-remotes/origin/"]);
    assert!(
        ours.contains("refs/fullgit-remotes/origin/issues/"),
        "{ours}"
    );

    // A clone set up by an earlier fullgit.
    let (bob, _) = fx.clone(&remote, "bob");
    git(
        &bob,
        &[
            "config",
            "--add",
            "remote.origin.fetch",
            "+refs/fullgit/*:refs/remotes/origin/fullgit/*",
        ],
    );
    git(&bob, &["fetch", "-q", "origin"]);
    assert!(git(&bob, &["branch", "-r"]).contains("origin/fullgit/issues/"));
    let doctor = fg(&bob, &["doctor"]).stdout;
    assert!(
        doctor.contains("warn  remote origin fetches refs/fullgit/* as remote branches"),
        "{doctor}"
    );

    fg_ok(&bob, &["init"]);
    let specs = git(&bob, &["config", "--get-all", "remote.origin.fetch"]);
    assert_eq!(
        specs.lines().collect::<Vec<_>>(),
        [
            "+refs/heads/*:refs/remotes/origin/*",
            "+refs/fullgit/*:refs/fullgit-remotes/origin/*"
        ],
    );
    git(&bob, &["fetch", "-q", "origin"]);
    let branches = git(&bob, &["branch", "-r"]);
    assert!(!branches.contains("fullgit"), "{branches}");
    fg_ok(&bob, &["sync"]);
    let issues = fg_ok(&bob, &["issue", "list"]);
    assert!(issues.contains("Hello"), "{issues}");
    let doctor = fg(&bob, &["doctor"]).stdout;
    assert!(
        doctor.contains("ok    remote origin fetches refs/fullgit/*"),
        "{doctor}"
    );
}
