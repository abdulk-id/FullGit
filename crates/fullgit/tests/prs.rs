//! Phase 6, end to end: a pull request reviewed and merged between clones.

mod cli;

use std::path::{Path, PathBuf};

use cli::common::{Fixture, git};
use cli::{fg, fg_ok, user};
use serde_json::{Value, json};

fn commit(dir: &Path, file: &str, content: &str) {
    std::fs::write(dir.join(file), content).unwrap();
    git(dir, &["add", file]);
    git(dir, &["commit", "-q", "-m", &format!("Change {file}")]);
}

/// The id in parentheses at the end of the first line containing `marker`.
fn comment_id(show: &str, marker: &str) -> String {
    let line = show.lines().find(|l| l.contains(marker)).unwrap();
    let start = line.rfind('(').unwrap() + 1;
    line[start..].trim_end_matches(')').to_owned()
}

fn json(dir: &Path, args: &[&str]) -> Value {
    let out = fg_ok(dir, args);
    serde_json::from_str(&out).unwrap_or_else(|e| panic!("{args:?}: {e}\n{out}"))
}

/// Alice owns the repo; Bob contributes; master takes one approval.
/// Returns the remote, Alice's clone and Bob's.
fn setup(fx: &Fixture) -> (PathBuf, PathBuf, PathBuf) {
    let remote = fx.bare("remote.git");
    git(&remote, &["symbolic-ref", "HEAD", "refs/heads/master"]);
    let alice = user(fx, &remote, "alice");
    let bob = user(fx, &remote, "bob");
    commit(&alice, "lib.rs", "fn a() {}\n");
    fg_ok(&alice, &["policy", "init"]);
    git(&alice, &["add", ".fullgit/root"]);
    git(&alice, &["commit", "-q", "-m", "Policy"]);
    git(&alice, &["push", "-q", "origin", "HEAD:master"]);
    fg_ok(&alice, &["sync"]);
    fg_ok(
        &alice,
        &["policy", "grant", "bob@example.com", "contributor"],
    );
    fg_ok(&alice, &["policy", "protect", "master", "--approvals", "1"]);
    fg_ok(&alice, &["sync"]);
    git(&bob, &["pull", "-q", "origin", "master"]);
    git(&bob, &["remote", "set-head", "origin", "--auto"]);
    fg_ok(&bob, &["init"]);
    fg_ok(&bob, &["sync"]);
    (remote, alice, bob)
}

#[test]
fn pull_requests_are_reviewed_revised_and_merged() {
    let fx = Fixture::new();
    let (remote, alice, bob) = setup(&fx);

    git(&bob, &["checkout", "-q", "-b", "retry"]);
    commit(&bob, "lib.rs", "fn a() {}\nfn retry() {}\n");
    let out = fg_ok(&bob, &["pr", "new", "-t", "Retry sync", "-m", "Flaky"]);
    assert!(out.contains("retry → master, 1 commit(s)"), "{out}");
    let id = out.split_whitespace().nth(3).unwrap().to_owned();
    fg_ok(&bob, &["sync"]);

    // Alice reviews: a line comment, and a request for changes.
    fg_ok(&alice, &["sync"]);
    let list = fg_ok(&alice, &["pr", "list"]);
    assert!(
        list.contains(&format!(
            "{id}  open    Retry sync  [retry → master, r1, needs 1 approval(s)]  (bob)"
        )),
        "{list}"
    );
    assert!(fg_ok(&alice, &["pr", "diff", &id]).contains("+fn retry() {}"));
    let out = fg(
        &alice,
        &[
            "pr", "comment", &id, "--file", "lib.rs", "--line", "9", "-m", "x",
        ],
    );
    assert!(
        !out.ok && out.stderr.contains("has 2 lines"),
        "{}",
        out.stderr
    );
    fg_ok(
        &alice,
        &[
            "pr", "comment", &id, "--file", "lib.rs", "--line", "2", "-m", "Backoff?",
        ],
    );
    fg_ok(
        &alice,
        &["pr", "review", &id, "--request-changes", "-m", "See above"],
    );
    let out = fg(&alice, &["pr", "merge", &id]);
    assert!(
        !out.ok && out.stderr.contains("changes requested by alice"),
        "{}",
        out.stderr
    );

    // Bob can't merge; he answers and revises.
    let out = fg(&bob, &["pr", "merge", &id]);
    assert!(
        !out.ok && out.stderr.contains("maintainer"),
        "{}",
        out.stderr
    );
    let show = fg_ok(&bob, &["pr", "show", &id]);
    for want in [
        "── alice on lib.rs:2 (r1)",
        "  >    2 │ fn retry() {}",
        "    Backoff?",
        "· alice requested changes on r1",
        "not ready to merge: 0 of 1 approval(s); changes requested by alice",
    ] {
        assert!(show.contains(want), "missing {want:?} in\n{show}");
    }
    let c = comment_id(&show, "lib.rs:2");
    fg_ok(&bob, &["pr", "comment", &id, "--reply", &c, "-m", "Done"]);
    commit(&bob, "lib.rs", "fn a() {}\nfn retry() { backoff() }\n");
    assert!(fg_ok(&bob, &["pr", "revise", "-m", "Backoff"]).contains("revision 2"));
    fg_ok(&bob, &["sync"]);

    // Alice sees what changed since her review, approves, and merges.
    fg_ok(&alice, &["sync"]);
    let since = fg_ok(&alice, &["pr", "diff", &id, "--since", "1"]);
    assert!(since.contains("+fn retry() { backoff() }"), "{since}");
    fg_ok(&alice, &["pr", "review", &id, "--approve"]);
    let show = fg_ok(&alice, &["pr", "show", &id]);
    for want in [
        &format!("── bob replied to {c}"),
        "  r2  ",
        ": Backoff",
        "ready to merge: 1 of 1 approval(s)",
    ] {
        assert!(show.contains(want), "missing {want:?} in\n{show}");
    }
    fg_ok(&alice, &["pr", "checkout", &id]);
    assert_eq!(git(&alice, &["branch", "--show-current"]), "retry\n");
    assert!(fg_ok(&alice, &["pr", "merge", &id]).contains("merged pull request"));

    let parents = git(&remote, &["log", "-1", "--format=%P", "master"]);
    let head = git(&bob, &["rev-parse", "retry"]);
    assert_eq!(parents.split_whitespace().nth(1), Some(head.trim()));
    let message = git(&remote, &["log", "-1", "--format=%B", "master"]);
    assert!(
        message.contains("Approved-by: alice <alice@example.com>")
            && message.contains("Fullgit-PR: "),
        "{message}"
    );

    fg_ok(&bob, &["sync"]);
    assert_eq!(fg_ok(&bob, &["pr", "list"]), "no pull requests\n");
    assert!(fg_ok(&bob, &["pr", "list", "--merged"]).contains("Retry sync"));
    let show = fg_ok(&bob, &["pr", "show", &id]);
    assert!(
        show.contains("· alice merged r2 as ") && show.contains("approved by alice"),
        "{show}"
    );

    // Pushing to master directly is possible, but `verify` finds it.
    let out = fg_ok(&alice, &["verify", "master"]);
    assert!(out.contains("all 1 commit(s)"), "{out}");
    git(&bob, &["checkout", "-q", "master"]);
    git(&bob, &["pull", "-q", "origin", "master"]);
    commit(&bob, "notes", "unreviewed\n");
    git(&bob, &["push", "-q", "origin", "master"]);
    git(&alice, &["fetch", "-q", "origin"]);
    let out = fg(&alice, &["verify", "master"]);
    assert!(
        !out.ok && out.stderr.contains("1 of 2 commit(s)") && out.stderr.contains("Change notes"),
        "{}",
        out.stderr
    );

    // A pull request that no longer merges cleanly is refused.
    git(&bob, &["checkout", "-q", "-b", "clash", "HEAD~2"]);
    commit(&bob, "lib.rs", "fn b() {}\n");
    let out = fg_ok(&bob, &["pr", "new", "-t", "Rename"]);
    let clash = out.split_whitespace().nth(3).unwrap().to_owned();
    fg_ok(&bob, &["sync"]);
    fg_ok(&alice, &["sync"]);
    fg_ok(&alice, &["pr", "review", &clash, "--approve"]);
    let out = fg(&alice, &["pr", "merge", &clash]);
    assert!(
        !out.ok && out.stderr.contains("conflicts with master in:\n  lib.rs"),
        "{}",
        out.stderr
    );
}

#[test]
fn pull_requests_print_json_for_scripts() {
    let fx = Fixture::new();
    let (_remote, alice, bob) = setup(&fx);
    assert_eq!(json(&bob, &["pr", "list", "--json"]), json!([]));

    git(&bob, &["checkout", "-q", "-b", "retry"]);
    commit(&bob, "lib.rs", "fn a() {}\nfn retry() {}\n");
    let new = json(&bob, &["pr", "new", "-t", "Retry sync", "--json"]);
    let id = new["id"].as_str().unwrap().to_owned();
    assert_eq!(id.len(), 40, "{new}");
    assert_eq!(new["source"], "retry");
    assert_eq!(new["target"], "master");
    assert_eq!(new["revisions"][0]["number"], 1);
    assert_eq!(new["revisions"][0]["commits"], 1);
    assert_eq!(new["head"], git(&bob, &["rev-parse", "retry"]).trim());
    fg_ok(&bob, &["sync"]);
    fg_ok(&alice, &["sync"]);

    let line = json(
        &alice,
        &[
            "pr", "comment", &id, "--file", "lib.rs", "--line", "2", "-m", "Backoff?", "--json",
        ],
    );
    assert_eq!(line["pull_request"], id.as_str());
    assert_eq!(
        line["location"],
        json!({
            "revision": 1,
            "revision_id": id,
            "path": "lib.rs",
            "line": 2,
            "side": "new",
        })
    );
    let line_id = line["id"].as_str().unwrap();
    fg_ok(
        &alice,
        &["pr", "review", &id, "--request-changes", "-m", "See above"],
    );

    let list = json(&alice, &["pr", "list", "--json"]);
    let [p] = list.as_array().unwrap().as_slice() else {
        panic!("{list}");
    };
    assert_eq!(p["id"], id.as_str());
    assert_eq!(p["author"]["name"], "bob");
    assert_eq!(p["revisions"], 1);
    assert_eq!(p["comments"], 1);
    let r = &p["readiness"];
    assert_eq!(r["ready"], false);
    assert_eq!(r["approvals_required"], 1);
    assert_eq!(r["approvals_missing"], 1);
    assert_eq!(r["changes_requested"][0]["name"], "alice");

    let reply = json(
        &alice,
        &[
            "pr",
            "comment",
            &id[..8],
            "--reply",
            line_id,
            "-m",
            "Or a retry limit",
            "--json",
        ],
    );
    assert_eq!(reply["reply_to"], line_id);
    fg_ok(&alice, &["pr", "review", &id, "--approve"]);
    fg_ok(&alice, &["sync"]);
    fg_ok(&alice, &["pr", "merge", &id]);

    let show = json(&alice, &["pr", "show", &id, "--json"]);
    assert_eq!(show["status"], "merged");
    assert_eq!(show["readiness"], Value::Null);
    assert_eq!(show["merged"]["revision"], 1);
    assert_eq!(show["merged"]["approvals"][0]["name"], "alice");
    let verdicts: Vec<_> = show["reviews"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["verdict"].as_str().unwrap())
        .collect();
    assert_eq!(verdicts, ["changes", "approve"]);
    let types: Vec<_> = show["timeline"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        [
            "opened",
            "commented",
            "reviewed",
            "commented",
            "reviewed",
            "merged"
        ]
    );
    assert_eq!(show["ignored"], json!([]));
}
