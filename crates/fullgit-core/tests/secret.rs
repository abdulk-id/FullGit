//! Phase 3: sealing secrets, and the filter's decisions.

mod common;

use common::Fixture;
use fullgit_core::filter::{Handler, SecretFilter};
use fullgit_core::secret::{self, DecryptionKey, Sealed};
use fullgit_core::{Trust, identity, policy};
use git2::Repository;

/// Alice owns the policy and is in `dev`; Bob is in `ops`; Carol has no
/// group. Returns their signers and decryption keys.
fn setup(fx: &Fixture, repo: &Repository) -> Vec<(fullgit_core::SshKeygenSigner, DecryptionKey)> {
    let mut people = Vec::new();
    let mut ids = Vec::new();
    for name in ["alice", "bob", "carol"] {
        let signer = fx.new_signer(name);
        ids.push(identity::create(repo, &signer, name, &format!("{name}@example.com")).unwrap());
        let key = DecryptionKey::from_file(&fx.path(&format!("id_{name}"))).unwrap();
        people.push((signer, key));
    }
    let alice = &people[0].0;
    policy::genesis(repo, &Trust::load(repo).unwrap(), alice, &[ids[0]]).unwrap();
    policy::group_add(repo, &Trust::load(repo).unwrap(), alice, "dev", ids[0]).unwrap();
    policy::group_add(repo, &Trust::load(repo).unwrap(), alice, "ops", ids[1]).unwrap();
    people
}

#[test]
fn only_recipients_open_and_only_members_seal() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let people = setup(&fx, &repo);
    let trust = Trust::load(&repo).unwrap();
    let [(alice, alice_key), (bob, bob_key), (carol, _)] = &people[..] else {
        unreachable!()
    };

    let sealed = secret::seal(&trust, alice, "dev", b"TOKEN=1\n").unwrap();
    let parsed = Sealed::parse(&sealed.to_bytes()).unwrap();
    assert_eq!(parsed.group, "dev");
    assert_eq!(parsed.recipients.len(), 1);
    assert!(parsed.verify(&trust).is_ok());
    assert_eq!(parsed.open(alice_key).unwrap(), b"TOKEN=1\n");
    let err = parsed.open(bob_key).unwrap_err();
    assert!(err.contains("not encrypted to your key"), "{err}");

    // Bob (ops) and Carol (no group) can encrypt to dev's public keys, but
    // the result is not trusted.
    for outsider in [bob, carol] {
        let forged = secret::seal(&trust, outsider, "dev", b"TOKEN=evil\n").unwrap();
        let err = forged.verify(&trust).unwrap_err();
        assert!(err.contains("neither in dev nor an owner"), "{err}");
    }

    // Changing the group line (or anything else signed) breaks the signature.
    let text = String::from_utf8(sealed.to_bytes()).unwrap();
    let moved = Sealed::parse(text.replace("group: dev", "group: ops").as_bytes()).unwrap();
    assert!(moved.verify(&trust).is_err());

    assert!(secret::seal(&trust, alice, "nobody", b"x").is_err());
}

#[test]
fn smudge_leaves_untrusted_or_unreadable_files_sealed() {
    let fx = Fixture::new();
    let (path, repo) = fx.repo("r");
    let people = setup(&fx, &repo);
    let trust = Trust::load(&repo).unwrap();
    let (alice, bob) = (&people[0].0, &people[1].0);
    common::git(
        &path,
        &[
            "config",
            "user.signingkey",
            fx.path("id_alice").to_str().unwrap(),
        ],
    );

    let good = secret::seal(&trust, alice, "dev", b"ok\n")
        .unwrap()
        .to_bytes();
    let forged = secret::seal(&trust, bob, "dev", b"evil\n")
        .unwrap()
        .to_bytes();
    let mut filter = SecretFilter::new(&repo);
    assert_eq!(filter.smudge(".env", good).unwrap(), b"ok\n");
    assert_eq!(filter.smudge(".evil", forged.clone()).unwrap(), forged);
    assert_eq!(filter.smudge("plain", b"plain".to_vec()).unwrap(), b"plain");
    assert_eq!(filter.left_sealed.len(), 1);
    assert_eq!(filter.left_sealed[0].0, ".evil");
}
