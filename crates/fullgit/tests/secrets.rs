//! Phase 3, end to end: the `fullgit` binary as git's filter, diff driver
//! and hooks, across clones of one remote.

mod cli;

use std::path::{Path, PathBuf};

use cli::common::{Fixture, git};
use cli::{fg, fg_ok, read, run, user};

const MAGIC: &str = "fullgit-secret v1";

fn is_sealed(path: &Path) -> bool {
    read(path).starts_with(MAGIC)
}

struct Team {
    fx: Fixture,
    remote: PathBuf,
    alice: PathBuf,
    bob: PathBuf,
    carol: PathBuf,
}

/// Alice owns the policy; Alice and Bob are in group `dev`, Carol isn't.
/// Alice commits `.env` (TOKEN=one) as a `dev` secret; everyone pulls it.
fn team() -> Team {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    git(&remote, &["symbolic-ref", "HEAD", "refs/heads/master"]);
    let alice = user(&fx, &remote, "alice");
    let bob = user(&fx, &remote, "bob");
    let carol = user(&fx, &remote, "carol");

    fg_ok(&alice, &["sync"]);
    fg_ok(&alice, &["policy", "init"]);
    for who in ["bob", "carol"] {
        let email = format!("{who}@example.com");
        fg_ok(&alice, &["policy", "grant", &email, "contributor"]);
    }
    for who in ["alice", "bob"] {
        let email = format!("{who}@example.com");
        fg_ok(&alice, &["policy", "group", "add", "dev", &email]);
    }
    std::fs::write(alice.join(".env"), "TOKEN=one\n").unwrap();
    fg_ok(&alice, &["secret", "add", ".env", "--group", "dev"]);
    git(&alice, &["add", ".gitattributes", ".env", ".fullgit/root"]);
    git(&alice, &["commit", "-q", "-m", "Add .env"]);
    git(&alice, &["push", "-q", "origin", "HEAD:master"]);
    fg_ok(&alice, &["sync"]);

    for path in [&bob, &carol] {
        git(path, &["pull", "-q", "origin", "master"]);
        fg_ok(path, &["init"]); // pins the policy root that just arrived
        fg_ok(path, &["sync"]);
    }
    Team {
        fx,
        remote,
        alice,
        bob,
        carol,
    }
}

#[test]
fn members_read_secrets_and_others_cannot() {
    let t = team();
    let (alice, bob, carol) = (&t.alice, &t.bob, &t.carol);

    // The repository holds ciphertext, the working tree plaintext, and
    // nothing looks modified, even after rewriting the same content.
    let blob = git(alice, &["show", "HEAD:.env"]);
    assert!(blob.starts_with(MAGIC) && !blob.contains("TOKEN"), "{blob}");
    assert_eq!(read(&alice.join(".env")), "TOKEN=one\n");
    std::fs::write(alice.join(".env"), "TOKEN=one\n").unwrap();
    assert_eq!(git(alice, &["status", "--porcelain"]), "");

    // `git diff` shows plaintext.
    std::fs::write(alice.join(".env"), "TOKEN=two\n").unwrap();
    let diff = git(alice, &["diff"]);
    assert!(
        diff.contains("-TOKEN=one") && diff.contains("+TOKEN=two"),
        "{diff}"
    );
    git(alice, &["commit", "-q", "-am", "Rotate token"]);
    git(alice, &["push", "-q", "origin", "HEAD:master"]);

    // Bob pulled before he had the policy, so his copy is still sealed;
    // `secret checkout` opens it. Later pulls decrypt on their own.
    assert!(is_sealed(&bob.join(".env")));
    fg_ok(bob, &["secret", "checkout"]);
    assert_eq!(read(&bob.join(".env")), "TOKEN=one\n");
    git(bob, &["pull", "-q", "origin", "master"]);
    assert_eq!(read(&bob.join(".env")), "TOKEN=two\n");
    assert_eq!(git(bob, &["status", "--porcelain"]), "");
    let list = fg_ok(bob, &["secret", "list"]);
    assert!(
        list.contains(".env") && list.contains("readable by you"),
        "{list}"
    );

    // Carol isn't in the group: the file stays sealed, and git stays clean.
    let out = fg(carol, &["secret", "checkout"]);
    assert!(
        !out.ok && out.stderr.contains("still sealed"),
        "{}",
        out.stderr
    );
    git(carol, &["pull", "-q", "origin", "master"]);
    assert!(is_sealed(&carol.join(".env")));
    assert_eq!(git(carol, &["status", "--porcelain"]), "");

    // Nor can she write it: anyone could encrypt to the group's public
    // keys, so her clone refuses, and checkouts would refuse to open it.
    std::fs::write(carol.join(".env"), "TOKEN=evil\n").unwrap();
    let out = run(carol, "git", &["add", ".env"]);
    assert!(!out.ok, "git add should fail");
    assert!(
        out.stderr.contains("neither in dev nor an owner"),
        "{}",
        out.stderr
    );
}

#[test]
fn unencrypted_secrets_are_neither_committed_nor_pushed() {
    let t = team();
    let alice = &t.alice;
    let before = git(&t.remote, &["rev-parse", "master"]);

    // Without the filter, `git add` stores plaintext.
    git(alice, &["config", "--unset", "filter.fullgit.process"]);
    git(alice, &["config", "--unset", "filter.fullgit.required"]);
    std::fs::write(alice.join(".env"), "TOKEN=leaked\n").unwrap();
    git(alice, &["add", ".env"]);

    let out = run(alice, "git", &["commit", "-q", "-m", "oops"]);
    assert!(!out.ok, "pre-commit should refuse");
    assert!(
        out.stderr.contains(".env (unencrypted secret)"),
        "{}",
        out.stderr
    );

    // Skipping the hook still doesn't get it pushed.
    git(alice, &["commit", "-q", "--no-verify", "-m", "oops"]);
    let out = run(alice, "git", &["push", "-q", "origin", "HEAD:master"]);
    assert!(!out.ok, "pre-push should refuse");
    assert!(out.stderr.contains("refusing to push"), "{}", out.stderr);
    assert_eq!(git(&t.remote, &["rev-parse", "master"]), before);

    // `fullgit doctor` notices the broken setup.
    let out = fg(alice, &["doctor"]);
    assert!(!out.ok);
    assert!(
        out.stdout.contains("secret filter not configured"),
        "{}",
        out.stdout
    );
}

#[test]
fn rekey_after_someone_leaves_the_group() {
    let t = team();
    let (alice, bob) = (&t.alice, &t.bob);
    fg_ok(bob, &["secret", "checkout"]);
    assert_eq!(read(&bob.join(".env")), "TOKEN=one\n");

    fg_ok(
        alice,
        &["policy", "group", "remove", "dev", "bob@example.com"],
    );
    let list = fg_ok(alice, &["secret", "list"]);
    assert!(list.contains("needs rekey"), "{list}");
    let out = fg_ok(alice, &["secret", "rekey"]);
    assert!(out.contains("resealed") && out.contains("rotate"), "{out}");
    assert!(out.contains("bob <bob@example.com>"), "{out}");
    assert_eq!(
        read(&alice.join(".env")),
        "TOKEN=one\n",
        "working tree untouched"
    );
    git(alice, &["commit", "-q", "-m", "Rekey .env"]);
    git(alice, &["push", "-q", "origin", "HEAD:master"]);
    fg_ok(alice, &["sync"]);
    assert!(fg_ok(alice, &["secret", "rekey"]).contains("up to date"));

    // Bob gets the new version, which he can no longer open.
    fg_ok(bob, &["sync"]);
    let pull = run(bob, "git", &["pull", "-q", "origin", "master"]);
    assert!(pull.ok, "{}", pull.stderr);
    assert!(
        pull.stderr.contains("left these secrets encrypted"),
        "{}",
        pull.stderr
    );
    assert!(is_sealed(&bob.join(".env")));
    drop(t.fx);
}
