//! Phase 5, end to end: issues shared between clones.

mod cli;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use cli::common::{Fixture, git};
use cli::{fg, fg_ok, user};

/// Makes `dir`'s git editor write `text` into the file it's given.
fn editor(fx: &Fixture, dir: &Path, text: &str) {
    let script = fx.path("editor.sh");
    std::fs::write(&script, format!("#!/bin/sh\nprintf '{text}' > \"$1\"\n")).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    git(dir, &["config", "core.editor", script.to_str().unwrap()]);
}

#[test]
fn issues_are_shared_discussed_and_closed() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let alice = user(&fx, &remote, "alice");
    let bob = user(&fx, &remote, "bob");
    fg_ok(&alice, &["sync"]);

    let out = fg_ok(
        &alice,
        &[
            "issue",
            "new",
            "-t",
            "Sync loses ops",
            "-m",
            "Steps",
            "-l",
            "bug",
        ],
    );
    let id = out.split_whitespace().nth(2).unwrap().trim_end_matches(';');
    // Named, like git's commits, by the shortest unique start of the id.
    assert_eq!(id.len(), 4, "{out}");
    editor(
        &fx,
        &alice,
        "Docs are out of date\\n\\nThe README predates Phase 4.\\n",
    );
    fg_ok(&alice, &["issue", "new"]);
    fg_ok(&alice, &["sync"]);
    fg_ok(&bob, &["sync"]);

    let list = fg_ok(&bob, &["issue", "list"]);
    assert!(
        list.contains(&format!("{id}  open    Sync loses ops  [bug]  (alice)")),
        "{list}"
    );
    assert!(list.contains("Docs are out of date"), "{list}");
    let list = fg_ok(&bob, &["issue", "list", "--label", "bug"]);
    assert_eq!(list.lines().count(), 1, "{list}");

    editor(&fx, &bob, "Seen it on Linux too.\\n# not part of it\\n");
    fg_ok(&bob, &["issue", "comment", id]);
    fg_ok(&bob, &["issue", "assign", id, "me"]);
    fg_ok(&bob, &["sync"]);
    fg_ok(&alice, &["sync"]);

    fg_ok(&alice, &["issue", "close", id, "-m", "Fixed in master"]);
    let out = fg(&alice, &["issue", "close", id]);
    assert!(
        !out.ok && out.stderr.contains("already closed"),
        "{}",
        out.stderr
    );
    let show = fg_ok(&alice, &["issue", "show", id]);
    for want in [
        "Sync loses ops",
        "closed · ",
        "opened by alice",
        "labels:    bug",
        "assignees: bob",
        "── bob commented",
        "    Seen it on Linux too.",
        "· bob assigned bob",
        "    Fixed in master",
        "· alice closed this",
    ] {
        assert!(show.contains(want), "missing {want:?} in\n{show}");
    }
    assert!(!show.contains("not part of it"), "{show}");

    let list = fg_ok(&alice, &["issue", "list"]);
    assert!(!list.contains("Sync loses ops"), "{list}");
    let list = fg_ok(&alice, &["issue", "list", "--closed"]);
    assert!(list.contains("Sync loses ops"), "{list}");
}
