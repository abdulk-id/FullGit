//! Phase 5: issues.

mod common;

use common::Fixture;
use fullgit_core::issue::{self, Status, What};
use fullgit_core::sync::sync;
use fullgit_core::{Error, Role, SshKeygenSigner, Trust, identity, policy};
use git2::{Oid, Repository};

fn trust(repo: &Repository) -> Trust {
    Trust::load(repo).unwrap()
}

fn person(repo: &Repository, fx: &Fixture, name: &str) -> (SshKeygenSigner, Oid) {
    let s = fx.new_signer(name);
    let id = identity::create(repo, &s, name, &format!("{name}@example.com")).unwrap();
    (s, id)
}

fn rejected<T: std::fmt::Debug>(r: fullgit_core::Result<T>) -> bool {
    matches!(r, Err(Error::Rejected { .. }))
}

#[test]
fn roles_decide_who_may_do_what() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let (alice, a) = person(&repo, &fx, "alice");
    let (bob, b) = person(&repo, &fx, "bob");
    let (erin, e) = person(&repo, &fx, "erin");
    let (carol, c) = person(&repo, &fx, "carol");
    policy::genesis(&repo, &trust(&repo), &alice, &[a]).unwrap();
    for (id, role) in [
        (b, Role::Contributor),
        (e, Role::Contributor),
        (c, Role::Reader),
    ] {
        policy::grant(&repo, &trust(&repo), &alice, id, role).unwrap();
    }
    let t = trust(&repo);

    // Readers neither open issues nor comment.
    assert!(rejected(issue::create(&repo, &t, &carol, "x", "", &[])));
    let id = issue::create(&repo, &t, &bob, "Sync loses ops", "Steps", &["bug".into()]).unwrap();
    assert!(rejected(issue::comment(&repo, &t, &carol, id, "+1")));

    // Other contributors comment, but don't edit, label or close.
    let comment = issue::comment(&repo, &t, &erin, id, "Me too").unwrap();
    assert!(rejected(issue::edit(&repo, &t, &erin, id, Some("x"), None)));
    assert!(rejected(issue::label(
        &repo,
        &t,
        &erin,
        id,
        &["p1".into()],
        &[]
    )));
    assert!(rejected(issue::set_status(
        &repo,
        &t,
        &erin,
        id,
        Status::Closed
    )));

    // Comments are their author's alone, even against the issue's author.
    assert!(rejected(issue::edit_comment(
        &repo, &t, &bob, id, comment, "x"
    )));
    issue::edit_comment(&repo, &t, &erin, id, comment, "Me too, on Linux").unwrap();

    // The author and maintainers (owners included) manage the issue.
    issue::edit(&repo, &t, &bob, id, Some("Sync drops ops"), None).unwrap();
    issue::label(&repo, &t, &alice, id, &["p1".into()], &["bug".into()]).unwrap();
    issue::assign(&repo, &t, &alice, id, &[b], &[]).unwrap();
    issue::set_status(&repo, &t, &bob, id, Status::Closed).unwrap();

    let i = issue::load(&repo, &t, id).unwrap().model;
    assert_eq!(i.title, "Sync drops ops");
    assert_eq!(i.body, "Steps");
    assert_eq!(i.author, Some(b));
    assert_eq!(i.status, Status::Closed);
    assert_eq!(i.labels.iter().collect::<Vec<_>>(), ["p1"]);
    assert_eq!(i.assignees.iter().collect::<Vec<_>>(), [&b]);
    assert_eq!(i.comments.len(), 1);
    assert_eq!(i.comments[0].body, "Me too, on Linux");
    assert!(i.comments[0].edited);
    let kinds: Vec<_> = i
        .timeline
        .iter()
        .map(|e| std::mem::discriminant(&e.what))
        .collect();
    assert_eq!(
        kinds,
        [
            What::Opened,
            What::Commented(0),
            What::Edited,
            What::Labeled {
                add: vec![],
                remove: vec![]
            },
            What::Assigned {
                add: vec![],
                remove: vec![]
            },
            What::Status(Status::Open),
        ]
        .iter()
        .map(std::mem::discriminant)
        .collect::<Vec<_>>()
    );

    // Revoked, Bob can't reopen his own issue; what he did before stands.
    policy::revoke(&repo, &trust(&repo), &alice, b).unwrap();
    let t = trust(&repo);
    assert!(rejected(issue::set_status(
        &repo,
        &t,
        &bob,
        id,
        Status::Open
    )));
    let after = issue::load(&repo, &t, id).unwrap();
    assert_eq!(after.model, i);
    assert!(after.rejected.is_empty());
}

#[test]
fn concurrent_changes_converge() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let (_, ra) = fx.clone(&remote, "a");
    let (_, rb) = fx.clone(&remote, "b");
    let (sa, _) = person(&ra, &fx, "alice");
    let (sb, _) = person(&rb, &fx, "bob");
    let sync_all = || {
        for (repo, s) in [(&ra, &sa), (&rb, &sb), (&ra, &sa)] {
            sync(repo, "origin", Some(s)).unwrap();
        }
    };
    sync_all();
    let id = issue::create(&ra, &trust(&ra), &sa, "Flaky test", "", &[]).unwrap();
    sync_all();

    // Offline, both close it and relabel it; Bob also comments.
    let (ta, tb) = (trust(&ra), trust(&rb));
    issue::label(&ra, &ta, &sa, id, &["ci".into()], &[]).unwrap();
    issue::set_status(&ra, &ta, &sa, id, Status::Closed).unwrap();
    issue::comment(&rb, &tb, &sb, id, "Fixed by retrying").unwrap();
    issue::label(&rb, &tb, &sb, id, &["tests".into()], &["ci".into()]).unwrap();
    issue::set_status(&rb, &tb, &sb, id, Status::Closed).unwrap();
    sync_all();

    let ia = issue::load(&ra, &trust(&ra), id).unwrap();
    let ib = issue::load(&rb, &trust(&rb), id).unwrap();
    assert_eq!(ia.model, ib.model);
    assert!(ia.rejected.is_empty(), "{:?}", ia.rejected);
    assert_eq!(ia.model.status, Status::Closed);
    assert_eq!(ia.model.comments.len(), 1);
    assert!(ia.model.labels.contains("tests"));
}
