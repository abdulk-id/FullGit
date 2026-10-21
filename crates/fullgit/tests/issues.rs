//! Phase 5, end to end: issues shared between clones.

mod cli;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use cli::common::{Fixture, git};
use cli::{adopt, fg, fg_ok, fg_with, user};
use serde_json::Value;

/// Runs fullgit with a GIT_EDITOR that writes `text` into the file it's
/// given. Tests have no terminal, so fullgit only runs an editor named so.
fn with_editor(fx: &Fixture, dir: &Path, args: &[&str], text: &str) -> String {
    let script = fx.path("editor.sh");
    std::fs::write(&script, format!("#!/bin/sh\nprintf '{text}' > \"$1\"\n")).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = fg_with(dir, args, &[("GIT_EDITOR", script.to_str().unwrap())]);
    assert!(
        out.ok,
        "fullgit {args:?} failed:\n{}{}",
        out.stdout, out.stderr
    );
    out.stdout
}

fn json(dir: &Path, args: &[&str]) -> Value {
    let out = fg_ok(dir, args);
    serde_json::from_str(&out).unwrap_or_else(|e| panic!("{args:?}: {e}\n{out}"))
}

#[test]
fn issues_are_shared_discussed_and_closed() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let alice = user(&fx, &remote, "alice");
    let bob = user(&fx, &remote, "bob");
    fg_ok(&alice, &["sync"]);
    adopt(&alice, &[(&bob, "maintainer")]);
    fg_ok(&alice, &["policy", "label", "add", "bug"]);
    fg_ok(&alice, &["sync"]);
    fg_ok(&bob, &["sync"]);

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
    with_editor(
        &fx,
        &alice,
        &["issue", "new"],
        "Docs are out of date\\n\\nThe README predates Phase 4.\\n",
    );
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

    with_editor(
        &fx,
        &bob,
        &["issue", "comment", id],
        "Seen it on Linux too.\\n# not part of it\\n",
    );
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

#[test]
fn labels_are_kept_in_the_policy() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let alice = user(&fx, &remote, "alice");
    fg_ok(&alice, &["policy", "init"]);
    fg_ok(&alice, &["policy", "label", "add", "bug", "docs"]);
    assert!(fg_ok(&alice, &["policy", "show"]).contains("labels: bug, docs"));

    // Labels may say what they are for.
    fg_ok(
        &alice,
        &["policy", "label", "describe", "bug", "Something is broken"],
    );
    let show = fg_ok(&alice, &["policy", "show"]);
    assert!(
        show.contains("Something is broken") && !show.contains("labels: bug, docs"),
        "{show}"
    );
    // Unquoted words become one description; an empty one clears it.
    fg_ok(
        &alice,
        &[
            "policy", "label", "describe", "docs", "Docs", "and", "guides",
        ],
    );
    assert!(fg_ok(&alice, &["policy", "show"]).contains("Docs and guides"));
    fg_ok(&alice, &["policy", "label", "describe", "docs", ""]);
    assert!(!fg_ok(&alice, &["policy", "show"]).contains("Docs and guides"));
    let out = fg(&alice, &["policy", "label", "describe", "p1", "x"]);
    assert!(
        !out.ok && out.stderr.contains("p1 is not a label"),
        "{}",
        out.stderr
    );

    let out = fg(&alice, &["issue", "new", "-t", "x", "-l", "wontfix"]);
    assert!(
        !out.ok
            && out
                .stderr
                .contains("no label \"wontfix\"; the labels are bug, docs"),
        "{}",
        out.stderr
    );
    let out = fg_ok(&alice, &["issue", "new", "-t", "Typo", "-l", "docs"]);
    let id = out.split_whitespace().nth(2).unwrap().trim_end_matches(';');
    fg_ok(&alice, &["policy", "label", "remove", "docs"]);
    let show = fg_ok(&alice, &["issue", "show", id]);
    assert!(!show.contains("labels:"), "{show}");
}

#[test]
fn issues_and_pull_requests_need_a_policy() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let alice = user(&fx, &remote, "alice");
    for args in [
        &["issue", "new", "-t", "Hi", "-m", "There"][..],
        &["issue", "list"],
        &["pr", "list"],
    ] {
        let out = fg(&alice, args);
        assert!(
            !out.ok && out.stderr.contains("no policy yet; `fullgit policy init`"),
            "{args:?}: {}",
            out.stderr
        );
    }
    let doctor = fg(&alice, &["doctor"]);
    assert!(
        !doctor.ok && doctor.stdout.contains("FAIL  no policy"),
        "{}",
        doctor.stdout
    );

    adopt(&alice, &[]);
    fg_ok(&alice, &["issue", "new", "-t", "Hi", "-m", "There"]);
    assert!(fg_ok(&alice, &["issue", "list"]).contains("Hi"));
}

#[test]
fn issues_print_json_for_scripts() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let alice = user(&fx, &remote, "alice");
    adopt(&alice, &[]);
    fg_ok(&alice, &["policy", "label", "add", "bug"]);
    assert_eq!(
        json(&alice, &["issue", "list", "--json"]),
        Value::Array(vec![])
    );

    let title = "Odd  [title] (with) \"quotes\"";
    let new = json(
        &alice,
        &[
            "issue", "new", "-t", title, "-m", "Steps", "-l", "bug", "--json",
        ],
    );
    let id = new["id"].as_str().unwrap();
    assert_eq!(id.len(), 40, "{new}");
    assert_eq!(new["title"], title);
    assert_eq!(new["author"]["name"], "alice");
    assert_eq!(new["author"]["email"], "alice@example.com");

    let comment = json(
        &alice,
        &["issue", "comment", &id[..8], "-m", "Me too", "--json"],
    );
    assert_eq!(comment["issue"], id);
    assert_eq!(comment["body"], "Me too");
    assert_eq!(comment["id"].as_str().unwrap().len(), 40, "{comment}");
    fg_ok(&alice, &["issue", "assign", id, "me"]);
    fg_ok(&alice, &["issue", "close", id]);

    let list = json(&alice, &["issue", "list", "--all", "--json"]);
    let [i] = list.as_array().unwrap().as_slice() else {
        panic!("{list}");
    };
    assert_eq!(i["id"], id);
    assert_eq!(i["status"], "closed");
    assert_eq!(i["labels"], serde_json::json!(["bug"]));
    assert_eq!(i["comments"], 1);
    assert_eq!(i["assignees"][0]["name"], "alice");
    assert!(i.get("body").is_none(), "{i}");

    let show = json(&alice, &["issue", "show", id, "--json"]);
    assert_eq!(show["body"], "Steps");
    assert_eq!(show["comments"][0]["id"], comment["id"]);
    assert_eq!(show["ignored"], Value::Array(vec![]));
    let types: Vec<_> = show["timeline"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["opened", "commented", "assigned", "closed"]);
    assert_eq!(show["timeline"][1]["comment"], comment["id"]);
    assert_eq!(show["timeline"][2]["add"][0]["name"], "alice");
}

#[test]
fn the_editor_needs_a_terminal() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let alice = user(&fx, &remote, "alice");
    adopt(&alice, &[]);
    git(&alice, &["config", "core.editor", "false"]);
    for args in [&["issue", "new"][..], &["issue", "new", "-m", "Body"]] {
        let out = fg(&alice, args);
        assert!(
            !out.ok && out.stderr.contains("not running in a terminal"),
            "{args:?}: {}",
            out.stderr
        );
    }
}
