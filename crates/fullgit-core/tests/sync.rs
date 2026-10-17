//! Phase 1: typed entities and `sync` between clones of one remote.

mod common;

use std::collections::BTreeSet;

use common::{Fixture, git};
use fullgit_core::model::{self, Model};
use fullgit_core::sync::{Outcome, sync};
use fullgit_core::{Error, StoredOp, entity};
use git2::Repository;
use serde_json::json;

/// A minimal entity: one last-writer-wins value and a grow-only tag set.
#[derive(Debug, Default, PartialEq)]
struct Register {
    value: String,
    tags: BTreeSet<String>,
}

impl Model for Register {
    const NAMESPACE: &'static str = "registers";

    fn apply(&mut self, op: &StoredOp) -> Result<(), String> {
        let field = |k: &str| {
            op.op.payload[k]
                .as_str()
                .map(str::to_owned)
                .ok_or(format!("missing {k}"))
        };
        match (op.parents.is_empty(), op.op.kind.as_str()) {
            (true, "reg.create") => self.value = field("value")?,
            (true, kind) => return Err(format!("{kind} cannot create a register")),
            (false, "reg.set") => self.value = field("value")?,
            (false, "reg.tag") => {
                self.tags.insert(field("tag")?);
            }
            (false, kind) => return Err(format!("unknown operation {kind}")),
        }
        Ok(())
    }
}

fn state(repo: &Repository, id: git2::Oid) -> (git2::Oid, Register) {
    let loaded = model::load::<Register>(repo, id).unwrap();
    (loaded.head, loaded.model)
}

#[test]
fn create_update_list_resolve() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let s = fx.signer();

    let a = model::create::<Register>(&repo, &s, "reg.create", json!({ "value": "x" })).unwrap();
    let b = model::create::<Register>(&repo, &s, "reg.create", json!({ "value": "x" })).unwrap();
    assert_ne!(a, b, "identical creations are distinct entities");

    let mut ids = vec![a, b];
    ids.sort();
    assert_eq!(model::list::<Register>(&repo).unwrap(), ids);

    model::update::<Register>(&repo, a, &s, "reg.set", json!({ "value": "y" })).unwrap();
    model::update::<Register>(&repo, a, &s, "reg.tag", json!({ "tag": "t" })).unwrap();
    let (_, reg) = state(&repo, a);
    assert_eq!(reg.value, "y");
    assert_eq!(reg.tags, BTreeSet::from(["t".to_owned()]));

    let prefix = &a.to_string()[..10];
    assert_eq!(model::resolve::<Register>(&repo, prefix).unwrap(), a);
    assert!(matches!(
        model::resolve::<Register>(&repo, "zzzz"),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn invalid_operations_are_refused_locally_and_skipped_in_replay() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let s = fx.signer();
    let id = model::create::<Register>(&repo, &s, "reg.create", json!({ "value": "x" })).unwrap();
    let (head, _) = state(&repo, id);

    // update() refuses to write an op the model would reject.
    let err = model::update::<Register>(&repo, id, &s, "reg.bogus", json!({})).unwrap_err();
    assert!(matches!(err, Error::Rejected { .. }), "{err}");
    assert_eq!(state(&repo, id).0, head, "ref unchanged");

    // An op written around the model (as another client might) is skipped.
    let bad = entity::append(
        &repo,
        &model::refname::<Register>(id),
        &s,
        "reg.bogus",
        json!({}),
    )
    .unwrap();
    model::update::<Register>(&repo, id, &s, "reg.set", json!({ "value": "y" })).unwrap();
    let loaded = model::load::<Register>(&repo, id).unwrap();
    assert_eq!(loaded.model.value, "y");
    assert_eq!(loaded.rejected.len(), 1);
    assert_eq!(loaded.rejected[0].op, bad);

    // A root the model rejects makes the entity unloadable.
    assert!(model::create::<Register>(&repo, &s, "reg.set", json!({ "value": "x" })).is_err());
}

#[test]
fn two_clones_converge() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let (_, alice) = fx.clone(&remote, "alice");
    let (_, bob) = fx.clone(&remote, "bob");
    let (sa, sb) = (fx.new_signer("alice"), fx.new_signer("bob"));

    let id =
        model::create::<Register>(&alice, &sa, "reg.create", json!({ "value": "v0" })).unwrap();
    assert!(sync(&alice, "origin", Some(&sa)).unwrap().pushed);

    let report = sync(&bob, "origin", Some(&sb)).unwrap();
    let r = model::refname::<Register>(id);
    assert_eq!(report.refs[&r], Outcome::New);
    assert_eq!(state(&bob, id), state(&alice, id));

    // Concurrent edits on both sides.
    model::update::<Register>(&alice, id, &sa, "reg.set", json!({ "value": "alice" })).unwrap();
    model::update::<Register>(&alice, id, &sa, "reg.tag", json!({ "tag": "a" })).unwrap();
    model::update::<Register>(&bob, id, &sb, "reg.set", json!({ "value": "bob" })).unwrap();
    model::update::<Register>(&bob, id, &sb, "reg.tag", json!({ "tag": "b" })).unwrap();

    assert_eq!(
        sync(&alice, "origin", Some(&sa)).unwrap().refs[&r],
        Outcome::UpToDate
    );
    assert_eq!(
        sync(&bob, "origin", Some(&sb)).unwrap().refs[&r],
        Outcome::Merged
    );
    assert_eq!(
        sync(&alice, "origin", Some(&sa)).unwrap().refs[&r],
        Outcome::FastForwarded
    );

    let (head, reg) = state(&alice, id);
    assert_eq!((head, reg), state(&bob, id));
    let (_, reg) = state(&alice, id);
    assert_eq!(reg.tags, BTreeSet::from(["a".to_owned(), "b".to_owned()]));
    assert!(reg.value == "alice" || reg.value == "bob");

    // Nothing left to do.
    for (repo, s) in [(&alice, &sa), (&bob, &sb)] {
        let report = sync(repo, "origin", Some(s)).unwrap();
        assert_eq!(report.refs[&r], Outcome::UpToDate);
    }
}

#[test]
fn both_sides_merging_still_converges() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let (_, alice) = fx.clone(&remote, "alice");
    let (_, bob) = fx.clone(&remote, "bob");
    let (_, carol) = fx.clone(&remote, "carol");
    let signers = [
        fx.new_signer("alice"),
        fx.new_signer("bob"),
        fx.new_signer("carol"),
    ];
    let repos = [&alice, &bob, &carol];

    let id = model::create::<Register>(&alice, &signers[0], "reg.create", json!({ "value": "v0" }))
        .unwrap();
    for (repo, s) in repos.iter().zip(&signers) {
        sync(repo, "origin", Some(s)).unwrap();
    }
    for (i, (repo, s)) in repos.iter().zip(&signers).enumerate() {
        model::update::<Register>(repo, id, s, "reg.tag", json!({ "tag": i.to_string() })).unwrap();
    }
    // Two rounds in each order is enough for everyone to see everything.
    for _ in 0..2 {
        for (repo, s) in repos.iter().zip(&signers) {
            sync(repo, "origin", Some(s)).unwrap();
        }
    }
    let expected = state(&alice, id);
    assert_eq!(expected.1.tags.len(), 3);
    assert_eq!(state(&bob, id), expected);
    assert_eq!(state(&carol, id), expected);
}

#[test]
fn forged_remote_operations_are_rejected_and_not_overwritten() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let (_, alice) = fx.clone(&remote, "alice");
    let (mallory_path, _) = fx.clone(&remote, "mallory");
    let (_, bob) = fx.clone(&remote, "bob");
    let (sa, sb) = (fx.new_signer("alice"), fx.new_signer("bob"));

    let id =
        model::create::<Register>(&alice, &sa, "reg.create", json!({ "value": "v0" })).unwrap();
    let other =
        model::create::<Register>(&alice, &sa, "reg.create", json!({ "value": "ok" })).unwrap();
    sync(&alice, "origin", Some(&sa)).unwrap();
    let r = model::refname::<Register>(id);
    let alice_head = state(&alice, id).0;

    // Mallory pushes an unsigned commit on top of the entity.
    git(
        &mallory_path,
        &["fetch", "-q", "origin", &format!("{r}:{r}")],
    );
    let tree = git(&mallory_path, &["rev-parse", &format!("{r}^{{tree}}")]);
    let forged = git(
        &mallory_path,
        &[
            "commit-tree",
            tree.trim(),
            "-p",
            &alice_head.to_string(),
            "-m",
            "reg.set",
        ],
    );
    git(
        &mallory_path,
        &["push", "-q", "origin", &format!("{}:{r}", forged.trim())],
    );

    // Bob never receives the entity; the other one still arrives.
    let report = sync(&bob, "origin", Some(&sb)).unwrap();
    assert!(
        matches!(report.refs[&r], Outcome::Rejected(_)),
        "{:?}",
        report.refs[&r]
    );
    assert!(model::load::<Register>(&bob, id).is_err());
    assert_eq!(
        report.refs[&model::refname::<Register>(other)],
        Outcome::New
    );

    // Alice keeps her version, and her sync neither fails nor overwrites
    // the remote.
    model::update::<Register>(&alice, other, &sa, "reg.set", json!({ "value": "new" })).unwrap();
    let report = sync(&alice, "origin", Some(&sa)).unwrap();
    assert!(report.pushed);
    assert!(matches!(report.refs[&r], Outcome::Rejected(_)));
    assert_eq!(state(&alice, id).0, alice_head);
    let remote_head = git(&mallory_path, &["ls-remote", "origin", &r]);
    assert!(remote_head.starts_with(forged.trim()));
    assert_eq!(state(&bob, other).1.value, "ok");
    sync(&bob, "origin", Some(&sb)).unwrap();
    assert_eq!(state(&bob, other).1.value, "new");
}

#[test]
fn diverged_entities_wait_for_a_signing_key() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let (_, alice) = fx.clone(&remote, "alice");
    let (_, bob) = fx.clone(&remote, "bob");
    let (sa, sb) = (fx.new_signer("alice"), fx.new_signer("bob"));

    let id =
        model::create::<Register>(&alice, &sa, "reg.create", json!({ "value": "v0" })).unwrap();
    sync(&alice, "origin", Some(&sa)).unwrap();
    sync(&bob, "origin", None).unwrap();
    model::update::<Register>(&alice, id, &sa, "reg.set", json!({ "value": "a" })).unwrap();
    model::update::<Register>(&bob, id, &sb, "reg.set", json!({ "value": "b" })).unwrap();
    sync(&alice, "origin", Some(&sa)).unwrap();

    let r = model::refname::<Register>(id);
    let report = sync(&bob, "origin", None).unwrap();
    assert!(matches!(report.refs[&r], Outcome::Rejected(_)));
    assert_eq!(state(&bob, id).1.value, "b", "local edit kept");

    assert_eq!(
        sync(&bob, "origin", Some(&sb)).unwrap().refs[&r],
        Outcome::Merged
    );
}

#[test]
fn rejected_push_is_retried() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let (_, alice) = fx.clone(&remote, "alice");
    let sa = fx.new_signer("alice");

    // The remote declines the first push it receives, as if another writer
    // had won the race.
    let hook = remote.join("hooks/pre-receive");
    let marker = fx.path("declined-once");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\n[ -e '{m}' ] && exit 0\ntouch '{m}'\necho busy >&2\nexit 1\n",
            m = marker.display()
        ),
    )
    .unwrap();
    let mut perms = std::fs::metadata(&hook).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(&hook, perms).unwrap();

    let id =
        model::create::<Register>(&alice, &sa, "reg.create", json!({ "value": "v0" })).unwrap();
    assert!(sync(&alice, "origin", Some(&sa)).unwrap().pushed);
    assert!(marker.exists(), "the first push was declined");
    let r = model::refname::<Register>(id);
    let remote_head = git(&remote, &["rev-parse", &r]);
    assert_eq!(remote_head.trim(), state(&alice, id).0.to_string());
}
