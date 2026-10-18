//! Phase 2: identities, the policy, and revocation.

mod common;

use std::path::Path;

use common::{Fixture, Register, git};
use fullgit_core::model::{self, Loaded};
use fullgit_core::sync::sync;
use fullgit_core::{
    Error, Identity, Policy, Role, Signer, SshKeygenSigner, Trust, entity, identity, policy,
    write_op,
};
use git2::{Oid, Repository};
use serde_json::json;

fn new_identity(repo: &Repository, s: &SshKeygenSigner, name: &str) -> Oid {
    identity::create(repo, s, name, &format!("{name}@example.com")).unwrap()
}

fn trust(repo: &Repository) -> Trust {
    Trust::load(repo).unwrap()
}

fn register(repo: &Repository, id: Oid) -> Loaded<Register> {
    model::load::<Register>(repo, &trust(repo), id).unwrap()
}

fn create_register(repo: &Repository, s: &dyn Signer, value: &str) -> fullgit_core::Result<Oid> {
    model::create::<Register>(
        repo,
        &trust(repo),
        s,
        "reg.create",
        json!({ "value": value }),
    )
}

fn set_register(
    repo: &Repository,
    id: Oid,
    s: &dyn Signer,
    value: &str,
) -> fullgit_core::Result<Oid> {
    model::update::<Register>(
        repo,
        &trust(repo),
        id,
        s,
        "reg.set",
        json!({ "value": value }),
    )
}

fn is_rejected<T: std::fmt::Debug>(r: fullgit_core::Result<T>) -> bool {
    matches!(r, Err(Error::Rejected { .. }))
}

/// Commits `.fullgit/root` and pushes it as `master`.
fn commit_root(path: &Path, repo: &Repository, root: Oid) {
    policy::write_root_file(repo, root).unwrap();
    git(path, &["add", policy::ROOT_FILE]);
    git(path, &["commit", "-q", "-m", "Add fullgit policy root"]);
    git(path, &["push", "-q", "origin", "HEAD:refs/heads/master"]);
}

#[test]
fn added_keys_need_proof_of_possession() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let (k1, k2, km) = (
        fx.new_signer("k1"),
        fx.new_signer("k2"),
        fx.new_signer("mallory"),
    );
    let alice = new_identity(&repo, &k1, "alice");
    let mallory = new_identity(&repo, &km, "mallory");

    let proof = identity::prove(&k2, alice).unwrap();
    identity::add_key(&repo, alice, &k1, k2.public_key().key_data(), &proof).unwrap();
    assert_eq!(identity::load(&repo, alice).unwrap().keys.len(), 2);
    assert_eq!(
        trust(&repo).identities_with_key(k2.public_key().key_data()),
        [alice]
    );

    // Mallory can't claim Alice's key: a proof signed by the wrong key, or
    // made for another identity, is refused.
    let k1_key = k1.public_key().key_data();
    let own = identity::prove(&km, mallory).unwrap();
    assert!(is_rejected(identity::add_key(
        &repo, mallory, &km, k1_key, &own
    )));
    let for_alice = identity::prove(&k2, alice).unwrap();
    let k2_key = k2.public_key().key_data();
    assert!(is_rejected(identity::add_key(
        &repo, mallory, &km, k2_key, &for_alice
    )));
    let right_message_wrong_key = km
        .sign_as(
            identity::PROOF_NAMESPACE,
            identity::proof_message(mallory, k1_key).as_bytes(),
        )
        .unwrap();
    let r = identity::add_key(&repo, mallory, &km, k1_key, &right_message_wrong_key);
    assert!(matches!(r, Err(Error::Rejected { .. })), "{r:?}");
    assert_eq!(trust(&repo).identities_with_key(k1_key), [alice]);

    // Only the identity's keys sign for it.
    assert!(is_rejected(identity::edit(
        &repo,
        alice,
        &km,
        Some("x"),
        None
    )));
    identity::edit(&repo, alice, &k2, Some("Alice"), None).unwrap();
    assert_eq!(identity::load(&repo, alice).unwrap().name, "Alice");

    // A removed key no longer signs for it; the last key can't be removed.
    identity::remove_key(&repo, alice, &k2, k1_key).unwrap();
    assert!(is_rejected(identity::edit(
        &repo,
        alice,
        &k1,
        Some("y"),
        None
    )));
    assert!(is_rejected(identity::remove_key(&repo, alice, &k2, k2_key)));
}

#[test]
fn roles_gate_operations() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let (sa, sb, sc, stranger) = (
        fx.new_signer("alice"),
        fx.new_signer("bob"),
        fx.new_signer("carol"),
        fx.new_signer("stranger"),
    );
    let alice = new_identity(&repo, &sa, "alice");
    let bob = new_identity(&repo, &sb, "bob");
    new_identity(&repo, &sc, "carol");

    // Without a policy, there are no issues.
    let refused = fullgit_core::issue::create(&repo, &trust(&repo), &sa, "Hi", "", &[]);
    assert!(matches!(refused, Err(Error::NoPolicy)), "{refused:?}");
    assert!(
        model::list::<fullgit_core::Issue>(&repo)
            .unwrap()
            .is_empty()
    );

    // Only an owner listed in the genesis can sign it.
    assert!(policy::genesis(&repo, &trust(&repo), &sb, &[alice]).is_err());
    let root = policy::genesis(&repo, &trust(&repo), &sa, &[alice]).unwrap();
    assert_eq!(policy::root(&repo).unwrap(), Some(root));
    assert!(trust(&repo).restricted());

    policy::grant(&repo, &trust(&repo), &sa, bob, Role::Contributor).unwrap();
    assert!(is_rejected(create_register(
        &repo,
        &sc,
        "carol has no role"
    )));
    assert!(is_rejected(create_register(
        &repo,
        &stranger,
        "no identity"
    )));
    let r = create_register(&repo, &sb, "bob").unwrap();
    let tag = |s: &dyn Signer| {
        model::update::<Register>(&repo, &trust(&repo), r, s, "reg.tag", json!({ "tag": "t" }))
    };
    assert!(is_rejected(tag(&sb)), "tagging takes a maintainer");
    policy::grant(&repo, &trust(&repo), &sa, bob, Role::Maintainer).unwrap();
    tag(&sb).unwrap();

    // Only owners change the policy, and the last owner stays.
    assert!(is_rejected(policy::grant(
        &repo,
        &trust(&repo),
        &sb,
        bob,
        Role::Owner
    )));
    assert!(is_rejected(policy::revoke(
        &repo,
        &trust(&repo),
        &sa,
        alice
    )));
    policy::grant(&repo, &trust(&repo), &sa, bob, Role::Owner).unwrap();
    policy::revoke(&repo, &trust(&repo), &sb, alice).unwrap();
    assert_eq!(trust(&repo).role(alice), None);

    policy::group_add(&repo, &trust(&repo), &sb, "secrets:prod", bob).unwrap();
    let t = trust(&repo);
    let groups = &t.policy.as_ref().unwrap().1.groups;
    assert!(groups["secrets:prod"].contains(&bob));
}

#[test]
fn revocation_keeps_what_the_revoker_had_seen() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let (alice_path, alice) = fx.clone(&remote, "alice");
    let (bob_path, bob) = fx.clone(&remote, "bob");
    let (sa, sb) = (fx.new_signer("alice"), fx.new_signer("bob"));

    let a = new_identity(&alice, &sa, "alice");
    let root = policy::genesis(&alice, &trust(&alice), &sa, &[a]).unwrap();
    commit_root(&alice_path, &alice, root);
    let b = new_identity(&bob, &sb, "bob");
    sync(&bob, "origin", Some(&sb)).unwrap();
    sync(&alice, "origin", Some(&sa)).unwrap();
    policy::grant(&alice, &trust(&alice), &sa, b, Role::Contributor).unwrap();
    sync(&alice, "origin", Some(&sa)).unwrap();

    // Bob's clone learns the policy from the committed root.
    git(&bob_path, &["pull", "-q", "origin", "master"]);
    sync(&bob, "origin", Some(&sb)).unwrap();
    assert_eq!(policy::root(&bob).unwrap(), Some(root));
    let r = create_register(&bob, &sb, "v1").unwrap();
    let seen = set_register(&bob, r, &sb, "v2").unwrap();
    sync(&bob, "origin", Some(&sb)).unwrap();

    // Alice revokes Bob after seeing v2. Concurrently, Bob (who hasn't
    // synced yet) writes v3 and creates another register.
    sync(&alice, "origin", Some(&sa)).unwrap();
    policy::revoke(&alice, &trust(&alice), &sa, b).unwrap();
    let late = set_register(&bob, r, &sb, "v3").unwrap();
    let r2 = create_register(&bob, &sb, "after").unwrap();

    // A backdated op, written on top of an op Alice had already seen.
    let backdated = write_op(&bob, &sb, &[seen], "reg.set", json!({ "value": "v4" })).unwrap();
    entity::merge(&bob, &model::refname::<Register>(r), Some(&sb), backdated).unwrap();

    for _ in 0..2 {
        sync(&alice, "origin", Some(&sa)).unwrap();
        sync(&bob, "origin", Some(&sb)).unwrap();
    }
    for repo in [&alice, &bob] {
        let reg = register(repo, r);
        assert_eq!(reg.model.value, "v2");
        let rejected: Vec<_> = reg.rejected.iter().map(|x| x.op).collect();
        assert!(rejected.contains(&late) && rejected.contains(&backdated));
        assert!(is_rejected(model::load::<Register>(repo, &trust(repo), r2)));
    }
    assert_eq!(register(&alice, r).head, register(&bob, r).head);

    // Bob's own client now refuses to write.
    assert!(is_rejected(set_register(&bob, r, &sb, "v5")));
}

#[test]
fn a_revoked_owners_concurrent_policy_changes_are_dropped() {
    let fx = Fixture::new();
    let (_, alice) = fx.repo("alice");
    let (sa, sb, sc) = (
        fx.new_signer("alice"),
        fx.new_signer("bob"),
        fx.new_signer("carol"),
    );
    let a = new_identity(&alice, &sa, "alice");
    let b = new_identity(&alice, &sb, "bob");
    let c = new_identity(&alice, &sc, "carol");
    let root = policy::genesis(&alice, &trust(&alice), &sa, &[a, b]).unwrap();
    let policy_ref = model::refname::<Policy>(root);
    let base = alice.refname_to_id(&policy_ref).unwrap();

    // Bob, offline, makes Carol a maintainer.
    let grant = write_op(
        &alice,
        &sb,
        &[base],
        "policy.grant",
        json!({ "identity": c.to_string(), "role": "maintainer" }),
    )
    .unwrap();

    // Alice, not having seen that, revokes Bob. Her group_add first gives
    // the revoke a higher clock, so Bob's grant replays *before* it and is
    // valid when applied; only the re-check takes it back.
    policy::group_add(&alice, &trust(&alice), &sa, "dev", a).unwrap();
    policy::revoke(&alice, &trust(&alice), &sa, b).unwrap();
    entity::merge(&alice, &policy_ref, Some(&sa), grant).unwrap();

    let loaded =
        model::load::<Policy>(&alice, &Trust::load_identities(&alice).unwrap(), root).unwrap();
    assert_eq!(loaded.model.role(b), None);
    assert_eq!(loaded.model.role(c), None, "Bob's unseen grant is dropped");
    assert!(loaded.rejected.iter().any(|r| r.op == grant));
    let order: Vec<_> = loaded.ops.iter().map(|o| o.id).collect();
    let revoke = loaded
        .ops
        .iter()
        .find(|o| o.op.kind == "policy.revoke")
        .unwrap()
        .id;
    assert!(
        order.iter().position(|o| *o == grant) < order.iter().position(|o| *o == revoke),
        "the grant replays before the revoke"
    );
}

#[test]
fn a_removed_key_cannot_backdate() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let (k1, k2, k3) = (
        fx.new_signer("k1"),
        fx.new_signer("k2"),
        fx.new_signer("k3"),
    );
    let a = new_identity(&repo, &k1, "alice");
    let proof = identity::prove(&k2, a).unwrap();
    identity::add_key(&repo, a, &k1, k2.public_key().key_data(), &proof).unwrap();
    let identity_ref = model::refname::<Identity>(a);
    let before_removal = repo.refname_to_id(&identity_ref).unwrap();

    let r = create_register(&repo, &k1, "by k1").unwrap();
    identity::remove_key(&repo, a, &k2, k1.public_key().key_data()).unwrap();
    let late = set_register(&repo, r, &k1, "k1 after removal").unwrap();

    // k1 backdates an add_key for a key its holder controls.
    let proof = identity::prove(&k3, a).unwrap();
    let add = write_op(
        &repo,
        &k1,
        &[before_removal],
        "identity.add_key",
        json!({
            "key": fullgit_core::sign::key_to_string(k3.public_key().key_data()),
            "proof": proof,
        }),
    )
    .unwrap();
    entity::merge(&repo, &identity_ref, Some(&k2), add).unwrap();

    let alice = identity::load(&repo, a).unwrap();
    assert_eq!(alice.keys, [k2.public_key().key_data().clone()]);

    // k1's ops from before the removal stay Alice's; later ones are nobody's.
    let t = trust(&repo);
    let ops = entity::load(
        &repo,
        &[repo.refname_to_id(&model::refname::<Register>(r)).unwrap()],
    )
    .unwrap();
    let actor = |id: Oid| {
        t.actor(&repo, r, ops.iter().find(|o| o.id == id).unwrap())
            .identity
    };
    assert_eq!(actor(r), Some(a));
    assert_eq!(actor(late), None);
}

#[test]
fn the_policy_root_is_pinned() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    git(&remote, &["symbolic-ref", "HEAD", "refs/heads/master"]);
    let (alice_path, alice) = fx.clone(&remote, "alice");
    let (mallory_path, mallory) = fx.clone(&remote, "mallory");
    let (sa, sm) = (fx.new_signer("alice"), fx.new_signer("mallory"));

    let a = new_identity(&alice, &sa, "alice");
    let root = policy::genesis(&alice, &trust(&alice), &sa, &[a]).unwrap();
    commit_root(&alice_path, &alice, root);
    sync(&alice, "origin", Some(&sa)).unwrap();

    // Mallory starts her own policy and commits its root on top.
    git(&mallory_path, &["pull", "-q", "origin", "master"]);
    let m = new_identity(&mallory, &sm, "mallory");
    let other = policy::genesis(
        &mallory,
        &Trust::load_identities(&mallory).unwrap(),
        &sm,
        &[m],
    )
    .unwrap();
    git(&mallory_path, &["config", "--unset", policy::ROOT_CONFIG]);
    policy::write_root_file(&mallory, other).unwrap();
    git(&mallory_path, &["commit", "-qam", "Take over"]);
    git(
        &mallory_path,
        &["push", "-q", "origin", "HEAD:refs/heads/master"],
    );
    sync(&mallory, "origin", Some(&sm)).unwrap();

    // Alice's clone pinned the original and refuses the swap.
    git(&alice_path, &["pull", "-q", "origin", "master"]);
    sync(&alice, "origin", Some(&sa)).unwrap();
    assert!(matches!(Trust::load(&alice), Err(Error::Policy(_))));

    // A fresh clone has nothing pinned and follows the committed root; that
    // first-use trust is what `fullgit init` asks the user to confirm.
    let (_, fresh) = fx.clone(&remote, "fresh");
    assert_eq!(policy::root(&fresh).unwrap(), Some(other));
}
