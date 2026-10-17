//! Phase 4, end to end: per-user files saved by `git push` and restored on
//! another device of the same person.

mod cli;

use std::path::{Path, PathBuf};

use cli::common::{Fixture, git, keygen};
use cli::{fg, fg_ok, read, run, user};

/// Another clone for an existing person: its own key, no identity yet.
fn device(fx: &Fixture, remote: &Path, name: &str) -> PathBuf {
    let (path, _) = fx.clone(remote, name);
    let key = keygen(fx.dir.path(), name);
    git(&path, &["config", "user.signingkey", key.to_str().unwrap()]);
    fg_ok(&path, &["init"]);
    fg_ok(&path, &["sync"]);
    path
}

fn remote() -> (Fixture, PathBuf) {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    git(&remote, &["symbolic-ref", "HEAD", "refs/heads/master"]);
    (fx, remote)
}

const FILE: &str = "mise.local.toml";

#[test]
fn per_user_files_follow_their_owner_across_devices() {
    let (fx, remote) = remote();
    let laptop = user(&fx, &remote, "alice");
    let set = |dir: &Path, value: &str| std::fs::write(dir.join(FILE), value).unwrap();
    let get = |dir: &Path| read(&dir.join(FILE));

    // Declaring a file ignores it, and pushing saves it.
    set(&laptop, "A = 1\n");
    fg_ok(&laptop, &["local", "add", FILE]);
    assert_eq!(
        git(&laptop, &["status", "--porcelain"]),
        "?? .gitattributes\n?? .gitignore\n"
    );
    git(&laptop, &["add", ".gitattributes", ".gitignore"]);
    git(&laptop, &["commit", "-q", "-m", "Per-user mise config"]);
    let push = run(&laptop, "git", &["push", "-q", "origin", "HEAD:master"]);
    assert!(
        push.ok && push.stderr.contains("saved 1 per-user file"),
        "{}",
        push.stderr
    );
    let snapshot_ref = git(
        &remote,
        &["for-each-ref", "--format=%(refname)", "refs/fullgit/users/"],
    );
    let snapshot_ref = snapshot_ref.trim();
    assert!(snapshot_ref.ends_with("/local"), "{snapshot_ref}");
    assert!(fg_ok(&laptop, &["local", "save"]).contains("up to date"));

    // The remote holds neither the contents nor the file's name.
    let op = git(&remote, &["show", &format!("{snapshot_ref}:op.json")]);
    assert!(!op.contains("A = 1") && !op.contains("mise.local"), "{op}");

    // A second device, whose key Alice adds to her identity.
    let desktop = device(&fx, &remote, "alice-desktop");
    let proof = fg_ok(&desktop, &["id", "prove", "alice@example.com"]);
    std::fs::write(fx.path("proof"), proof).unwrap();
    let proof = fx.path("proof");
    fg_ok(
        &laptop,
        &["id", "add-key", "--proof", proof.to_str().unwrap()],
    );
    fg_ok(&laptop, &["sync"]);
    let sync = fg_ok(&desktop, &["sync"]);
    assert!(sync.contains("fullgit local restore"), "{sync}");
    git(&desktop, &["pull", "-q", "origin", "master"]);

    // The snapshot predates the desktop's key, until the laptop saves again
    // to all of Alice's keys.
    let out = fg(&desktop, &["local", "restore"]);
    assert!(
        !out.ok && out.stderr.contains("not encrypted to your key"),
        "{}",
        out.stderr
    );
    assert!(fg_ok(&laptop, &["local", "save"]).contains("saved 1 file"));
    fg_ok(&laptop, &["sync"]);
    fg_ok(&desktop, &["sync"]);
    fg_ok(&desktop, &["local", "restore"]);
    assert_eq!(get(&desktop), "A = 1\n");

    // Both change it. The desktop saves first; the laptop may neither
    // replace that unseen, nor have its change overwritten.
    set(&desktop, "A = 2\n");
    fg_ok(&desktop, &["local", "save"]);
    fg_ok(&desktop, &["sync"]);
    set(&laptop, "A = 3\n");
    fg_ok(&laptop, &["sync"]);
    let out = fg(&laptop, &["local", "save"]);
    assert!(
        !out.ok && out.stderr.contains("another device"),
        "{}",
        out.stderr
    );
    let out = fg(&laptop, &["local", "restore"]);
    assert!(
        !out.ok && out.stderr.contains("conflict  mise.local.toml"),
        "{}",
        out.stderr
    );
    assert_eq!(get(&laptop), "A = 3\n");
    fg_ok(&laptop, &["local", "restore", "--force"]);
    assert_eq!(get(&laptop), "A = 2\n");

    // Files unchanged since the last restore just follow along.
    set(&desktop, "A = 4\n");
    fg_ok(&desktop, &["local", "save"]);
    fg_ok(&desktop, &["sync"]);
    fg_ok(&laptop, &["sync"]);
    fg_ok(&laptop, &["local", "restore"]);
    assert_eq!(get(&laptop), "A = 4\n");

    // Earlier snapshots stay available.
    let log = fg_ok(&laptop, &["local", "log"]);
    assert_eq!(log.lines().count(), 4, "{log}");
    let previous = log
        .lines()
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    fg_ok(&laptop, &["local", "restore", "--from", previous]);
    assert_eq!(get(&laptop), "A = 2\n");
    drop(fx);
}

#[test]
fn per_user_files_are_neither_committed_nor_pushed() {
    let (fx, remote) = remote();
    let alice = user(&fx, &remote, "alice");
    std::fs::write(alice.join(FILE), "TOKEN = 1\n").unwrap();
    fg_ok(&alice, &["local", "add", FILE]);
    git(&alice, &["add", ".gitattributes", ".gitignore"]);
    git(&alice, &["commit", "-q", "-m", "Per-user mise config"]);
    git(&alice, &["push", "-q", "origin", "HEAD:master"]);
    let before = git(&remote, &["rev-parse", "master"]);

    git(&alice, &["add", "--force", FILE]);
    let out = run(&alice, "git", &["commit", "-q", "-m", "oops"]);
    assert!(!out.ok, "pre-commit should refuse");
    assert!(
        out.stderr.contains("mise.local.toml (per-user file)"),
        "{}",
        out.stderr
    );
    let out = fg(&alice, &["doctor"]);
    assert!(
        !out.ok && out.stdout.contains("tracked by git"),
        "{}",
        out.stdout
    );

    git(&alice, &["commit", "-q", "--no-verify", "-m", "oops"]);
    let out = run(&alice, "git", &["push", "-q", "origin", "HEAD:master"]);
    assert!(!out.ok, "pre-push should refuse");
    assert!(out.stderr.contains("refusing to push"), "{}", out.stderr);
    assert_eq!(git(&remote, &["rev-parse", "master"]), before);
}
