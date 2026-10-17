//! Phase 0: signed operation commits, deterministic replay, and transport
//! through a plain git remote. Uses the system `git` and `ssh-keygen`.

mod common;

use common::{Fixture, git};
use fullgit_core::{Error, Signer, entity, load, op, refs, remote};
use git2::{Oid, Repository};
use serde_json::json;

#[test]
fn ops_roundtrip_in_order_with_verified_signer() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let signer = fx.signer();

    for (i, body) in ["first", "second", "third"].iter().enumerate() {
        let kind = if i == 0 {
            "issue.create"
        } else {
            "issue.comment"
        };
        entity::append(&repo, "issues/t", &signer, kind, json!({ "body": body })).unwrap();
    }

    let head = repo.refname_to_id("refs/fullgit/issues/t").unwrap();
    let ops = load(&repo, &[head]).unwrap();
    let bodies: Vec<_> = ops.iter().map(|o| o.op.payload["body"].clone()).collect();
    assert_eq!(bodies, [json!("first"), json!("second"), json!("third")]);
    assert_eq!(
        ops.iter().map(|o| o.op.lamport).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(
        ops.iter()
            .all(|o| &o.signer == signer.public_key().key_data())
    );
}

#[test]
fn git_verify_commit_accepts_ops() {
    let fx = Fixture::new();
    let (path, repo) = fx.repo("r");
    let id = entity::append(&repo, "issues/t", &fx.signer(), "issue.create", json!({})).unwrap();

    let pubkey = std::fs::read_to_string(fx.key.with_extension("pub")).unwrap();
    let allowed = fx.dir.path().join("allowed_signers");
    std::fs::write(&allowed, format!("test@example.com {pubkey}")).unwrap();
    git(
        &path,
        &[
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!("gpg.ssh.allowedSignersFile={}", allowed.display()),
            "verify-commit",
            &id.to_string(),
        ],
    );
}

#[test]
fn tampered_op_is_rejected() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let id = entity::append(
        &repo,
        "issues/t",
        &fx.signer(),
        "issue.create",
        json!({ "title": "real" }),
    )
    .unwrap();

    // Swap in a different op.json, keeping the original signature.
    let (sig, signed) = repo.extract_signature(&id, None).unwrap();
    let forged = op::Op {
        v: op::FORMAT_VERSION,
        kind: "issue.create".into(),
        lamport: 1,
        payload: json!({ "title": "forged" }),
    };
    let blob = repo.blob(&serde_json::to_vec(&forged).unwrap()).unwrap();
    let mut tb = repo.treebuilder(None).unwrap();
    tb.insert(op::OP_FILE, blob, 0o100644).unwrap();
    let tree = tb.write().unwrap();
    let original_tree = repo.find_commit(id).unwrap().tree_id();
    let content =
        signed
            .as_str()
            .unwrap()
            .replacen(&original_tree.to_string(), &tree.to_string(), 1);
    let forged_id = repo
        .commit_signed(&content, sig.as_str().unwrap(), None)
        .unwrap();

    let err = op::read_op(&repo, forged_id).unwrap_err();
    assert!(matches!(err, Error::Malformed { .. }), "{err}");
}

#[test]
fn unsigned_commit_is_rejected() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let tree = repo
        .find_tree(repo.treebuilder(None).unwrap().write().unwrap())
        .unwrap();
    let who = repo.signature().unwrap();
    let id = repo.commit(None, &who, &who, "plain", &tree, &[]).unwrap();
    assert!(matches!(
        op::read_op(&repo, id),
        Err(Error::Malformed { .. })
    ));
}

#[test]
fn concurrent_ops_replay_deterministically() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let signer = fx.signer();

    let root = entity::append(&repo, "issues/t", &signer, "issue.create", json!({})).unwrap();
    // Two writers branch off the same head.
    let a = op::write_op(
        &repo,
        &signer,
        &[root],
        "issue.label",
        json!({ "add": "a" }),
    )
    .unwrap();
    let b = op::write_op(
        &repo,
        &signer,
        &[root],
        "issue.label",
        json!({ "add": "b" }),
    )
    .unwrap();

    let order =
        |heads: &[Oid]| -> Vec<Oid> { load(&repo, heads).unwrap().iter().map(|o| o.id).collect() };
    let expected = order(&[a, b]);
    assert_eq!(order(&[b, a]), expected);
    assert_eq!(expected[0], root);
    assert_eq!(expected[1], a.min(b), "ties break by oid");

    // Merging the second writer's head joins both branches.
    git2::Repository::reference(&repo, "refs/fullgit/issues/t", a, true, "test").unwrap();
    let m = entity::merge(&repo, "issues/t", Some(&signer), b)
        .unwrap()
        .head();
    let merged = load(&repo, &[m]).unwrap();
    assert_eq!(merged.len(), 4);
    assert_eq!(merged.last().unwrap().op.kind, entity::MERGE_KIND);
    assert_eq!(merged.last().unwrap().op.lamport, 3);

    // Merging something already included is a no-op.
    assert_eq!(
        entity::merge(&repo, "issues/t", Some(&signer), a)
            .unwrap()
            .head(),
        m
    );
}

#[test]
fn ops_survive_push_and_fetch_through_bare_remote() {
    let fx = Fixture::new();
    let (alice_path, alice) = fx.repo("alice");
    let bare = fx.dir.path().join("remote.git");
    git(
        fx.dir.path(),
        &["init", "-q", "--bare", bare.to_str().unwrap()],
    );
    git(
        &alice_path,
        &["remote", "add", "origin", bare.to_str().unwrap()],
    );

    let signer = fx.signer();
    entity::append(
        &alice,
        "issues/t",
        &signer,
        "issue.create",
        json!({ "title": "hi" }),
    )
    .unwrap();
    let head = entity::append(
        &alice,
        "issues/t",
        &signer,
        "issue.comment",
        json!({ "body": "yo" }),
    )
    .unwrap();
    git(&alice_path, &["push", "-q", "origin", refs::PUSH_REFSPEC]);

    // A fresh clone doesn't see refs/fullgit/* until the refspec is installed.
    let bob_path = fx.dir.path().join("bob");
    git(
        fx.dir.path(),
        &[
            "clone",
            "-q",
            bare.to_str().unwrap(),
            bob_path.to_str().unwrap(),
        ],
    );
    let bob = Repository::open(&bob_path).unwrap();
    assert!(
        bob.refname_to_id("refs/remotes/origin/fullgit/issues/t")
            .is_err()
    );

    assert!(remote::install_fetch_refspec(&bob, "origin").unwrap());
    assert!(
        !remote::install_fetch_refspec(&bob, "origin").unwrap(),
        "idempotent"
    );
    git(&bob_path, &["fetch", "-q", "origin"]);

    let fetched = bob
        .refname_to_id("refs/remotes/origin/fullgit/issues/t")
        .unwrap();
    assert_eq!(fetched, head);
    let ops = load(&bob, &[fetched]).unwrap();
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[1].op.payload, json!({ "body": "yo" }));
    assert_eq!(&ops[1].signer, signer.public_key().key_data());
}
