//! Phase 4: per-user snapshots.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::Fixture;
use fullgit_core::local::{self, File, Files, Saved};
use fullgit_core::secret::{self, DecryptionKey};
use fullgit_core::{Signer, Trust, entity, identity};
use serde_json::json;

#[test]
fn only_the_owner_saves_and_opens_snapshots() {
    let fx = Fixture::new();
    let (path, repo) = fx.repo("r");
    let alice = fx.new_signer("alice");
    let mallory = fx.new_signer("mallory");
    let a = identity::create(&repo, &alice, "alice", "alice@example.com").unwrap();
    identity::create(&repo, &mallory, "mallory", "mallory@example.com").unwrap();
    let trust = Trust::load_identities(&repo).unwrap();

    std::fs::write(
        path.join(".gitattributes"),
        "/notes.txt fullgit-local\nrun.sh fullgit-local\n",
    )
    .unwrap();
    let notes = b"line\n\n100644 3 fake header\n\0binary".to_vec();
    std::fs::write(path.join("notes.txt"), &notes).unwrap();
    std::fs::create_dir(path.join("bin")).unwrap();
    std::fs::write(path.join("bin/run.sh"), "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(
        path.join("bin/run.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    let saved = local::save(&repo, &trust, &alice, a, false).unwrap();
    assert!(matches!(saved, Saved::Saved { files: 2, .. }), "{saved:?}");
    assert_eq!(
        local::save(&repo, &trust, &alice, a, false).unwrap(),
        Saved::UpToDate
    );

    // Mallory can push to Alice's ref, but what she writes doesn't count.
    let fake: Files = [(
        "notes.txt".to_owned(),
        File {
            executable: false,
            content: b"evil".to_vec(),
        },
    )]
    .into();
    let armored = secret::encrypt(
        &[alice.public_key().key_data().clone()],
        &local::pack(&fake),
    )
    .unwrap();
    entity::append(
        &repo,
        &local::refname(a),
        &mallory,
        local::SAVE_KIND,
        json!({ "sealed": armored, "recipients": [] }),
    )
    .unwrap();
    assert!(local::save(&repo, &trust, &mallory, a, true).is_err());

    let history = local::history(&repo, &trust, a).unwrap();
    assert_eq!((history.snapshots.len(), history.ignored), (1, 1));
    let latest = history.latest().unwrap();
    let alice_key = DecryptionKey::from_file(&fx.path("id_alice")).unwrap();
    let files = latest.open(&alice_key).unwrap();
    assert_eq!(files["notes.txt"].content, notes);
    assert!(files["bin/run.sh"].executable && !files["notes.txt"].executable);
    let mallory_key = DecryptionKey::from_file(&fx.path("id_mallory")).unwrap();
    assert!(latest.open(&mallory_key).is_err());
}

#[test]
fn restore_writes_only_per_user_files_inside_the_working_tree() {
    let fx = Fixture::new();
    let (path, repo) = fx.repo("r");
    let alice = fx.new_signer("alice");
    let a = identity::create(&repo, &alice, "alice", "alice@example.com").unwrap();
    std::fs::write(path.join(".gitattributes"), "*.local fullgit-local\n").unwrap();

    let file = |s: &str| File {
        executable: false,
        content: s.as_bytes().to_vec(),
    };
    let files: Files = [
        ("a.local", "ok"),
        ("../escape.local", "no"),
        (".git/hooks/x.local", "no"),
        ("/etc/x.local", "no"),
        ("README.md", "no"),
    ]
    .into_iter()
    .map(|(p, c)| (p.to_owned(), file(c)))
    .collect();
    let r = local::restore(&repo, a, a, &files, true).unwrap();
    assert_eq!(r.written, ["a.local"]);
    assert_eq!(r.skipped.len(), 4, "{:?}", r.skipped);
    assert!(!fx.path("escape.local").exists());
    assert!(!path.join(".git/hooks/x.local").exists());
    assert!(!path.join("README.md").exists());
}

#[test]
fn unpack_rejects_damaged_snapshots() {
    let files: Files = [(
        "x".to_owned(),
        File {
            executable: true,
            content: b"abc\n".to_vec(),
        },
    )]
    .into();
    let packed = local::pack(&files);
    assert_eq!(local::unpack(&packed).unwrap(), files);
    // Cut right after the header it's an empty archive; age's own
    // authentication catches truncated ciphertext before this.
    let header = "fullgit-local v1\n".len();
    for n in (1..packed.len()).filter(|&n| n != header) {
        assert!(local::unpack(&packed[..n]).is_err(), "truncated at {n}");
    }
    assert!(local::unpack(b"fullgit-local v1\n100600 1 x\na\n").is_err());
}
