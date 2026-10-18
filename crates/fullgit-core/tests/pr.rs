//! Phase 6: pull requests.

mod common;

use std::path::Path;

use common::{Fixture, git};
use fullgit_core::pr::{self, Merging, Place, Side, Status, Verdict};
use fullgit_core::sync::{Outcome, sync};
use fullgit_core::{Error, Role, SshKeygenSigner, Trust, identity, policy, refs};
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

/// Commits `content` to `file` on the current branch.
fn commit(dir: &Path, file: &str, content: &str) -> Oid {
    std::fs::write(dir.join(file), content).unwrap();
    git(dir, &["add", file]);
    git(dir, &["commit", "-q", "-m", &format!("Change {file}")]);
    Oid::from_str(git(dir, &["rev-parse", "HEAD"]).trim()).unwrap()
}

#[test]
fn reviews_and_roles_decide_merging() {
    let fx = Fixture::new();
    let (path, repo) = fx.repo("r");
    let (alice, a) = person(&repo, &fx, "alice");
    let (bob, b) = person(&repo, &fx, "bob");
    let (erin, e) = person(&repo, &fx, "erin");
    let (mo, m) = person(&repo, &fx, "mo");
    let (carol, c) = person(&repo, &fx, "carol");
    policy::genesis(&repo, &trust(&repo), &alice, &[a]).unwrap();
    for (id, role) in [
        (b, Role::Contributor),
        (e, Role::Contributor),
        (m, Role::Maintainer),
        (c, Role::Reader),
    ] {
        policy::grant(&repo, &trust(&repo), &alice, id, role).unwrap();
    }
    let base = commit(&path, "lib.rs", "fn a() {}\n");
    git(&path, &["checkout", "-q", "-b", "retry"]);
    let h1 = commit(&path, "lib.rs", "fn a() {}\nfn retry() {}\n");
    let t = trust(&repo);

    let open =
        |s: &SshKeygenSigner| pr::create(&repo, &t, s, "Retry", "", "retry", "master", h1, base);
    assert!(rejected(open(&carol)));
    let id = open(&bob).unwrap();
    assert!(repo.refname_to_id(&refs::code_refname(h1)).is_ok());

    // Line comments point at a revision; replies join their thread.
    let loaded = pr::load(&repo, &t, id).unwrap().model;
    let r1 = loaded.latest().id;
    let line = |revision, line| Place::Line {
        revision,
        path: "lib.rs",
        line,
        side: Side::New,
    };
    let c1 = pr::comment(&repo, &t, &erin, id, "Backoff?", line(r1, 2)).unwrap();
    let reply = pr::comment(&repo, &t, &bob, id, "Added", Place::Reply(c1)).unwrap();
    pr::comment(&repo, &t, &erin, id, "Thanks", Place::Reply(reply)).unwrap();
    assert!(rejected(pr::comment(
        &repo,
        &t,
        &erin,
        id,
        "x",
        line(r1, 0)
    )));
    assert!(rejected(pr::comment(
        &repo,
        &t,
        &erin,
        id,
        "x",
        line(h1, 1)
    )));
    assert!(rejected(pr::comment(
        &repo,
        &t,
        &carol,
        id,
        "x",
        Place::General
    )));

    // Only the author or a maintainer revises; authors don't review their own.
    assert!(rejected(pr::revise(&repo, &t, &erin, id, h1, base, "")));
    assert!(rejected(pr::review(
        &repo,
        &t,
        &bob,
        id,
        r1,
        Verdict::Approve,
        ""
    )));

    policy::protect(&repo, &trust(&repo), &alice, "master", 1, None, None).unwrap();
    let t = trust(&repo);
    let ready = |t: &Trust| pr::load(&repo, t, id).unwrap().model.readiness(t);
    assert_eq!(ready(&t).missing(), 1);

    // A request for changes outlives new revisions, until its reviewer
    // approves; approvals count only on the latest revision.
    pr::review(&repo, &t, &erin, id, r1, Verdict::Changes, "Backoff").unwrap();
    let h2 = commit(&path, "lib.rs", "fn a() {}\nfn retry() { backoff() }\n");
    let r2 = pr::revise(&repo, &t, &bob, id, h2, base, "Backoff").unwrap();
    pr::review(&repo, &t, &mo, id, r2, Verdict::Approve, "").unwrap();
    let r = ready(&t);
    assert_eq!((r.approvals.clone(), r.changes.clone()), (vec![m], vec![e]));
    assert!(!r.ready());
    pr::review(&repo, &t, &erin, id, r2, Verdict::Approve, "").unwrap();
    assert!(ready(&t).ready());
    let h3 = commit(&path, "lib.rs", "fn a() {}\nfn retry() { backoff(); }\n");
    let r3 = pr::revise(&repo, &t, &bob, id, h3, base, "").unwrap();
    assert_eq!(ready(&t).missing(), 1);

    // A group rule counts its members only, and only while they hold a role.
    policy::group_add(&repo, &trust(&repo), &alice, "reviewers", e).unwrap();
    policy::protect(
        &repo,
        &trust(&repo),
        &alice,
        "master",
        1,
        Some("reviewers"),
        None,
    )
    .unwrap();
    let t = trust(&repo);
    pr::review(&repo, &t, &mo, id, r3, Verdict::Approve, "").unwrap();
    assert_eq!(ready(&t).missing(), 1);
    pr::review(&repo, &t, &erin, id, r3, Verdict::Approve, "").unwrap();
    assert_eq!(ready(&t).approvals, [e]);
    policy::revoke(&repo, &trust(&repo), &alice, e).unwrap();
    let t = trust(&repo);
    assert_eq!(ready(&t).missing(), 1);

    // Maintainers record merges, which are final.
    let merge = Oid::from_str(&"ab".repeat(20)).unwrap();
    assert!(rejected(pr::record_merge(&repo, &t, &bob, id, r3, merge)));
    pr::record_merge(&repo, &t, &mo, id, r3, merge).unwrap();
    assert!(rejected(pr::revise(&repo, &t, &bob, id, h1, base, "")));
    assert!(rejected(pr::set_status(&repo, &t, &bob, id, Status::Open)));
    assert!(rejected(pr::review(
        &repo,
        &t,
        &mo,
        id,
        r3,
        Verdict::Approve,
        ""
    )));
    pr::comment(&repo, &t, &bob, id, "Thanks all", Place::General).unwrap();

    let loaded = pr::load(&repo, &t, id).unwrap();
    assert!(loaded.rejected.is_empty(), "{:?}", loaded.rejected);
    let p = loaded.model;
    assert_eq!(p.status, Status::Merged);
    assert_eq!(p.revisions.len(), 3);
    assert_eq!(p.revisions[1].note, "Backoff");
    let m_ = p.merged.as_ref().unwrap();
    assert_eq!((m_.revision, m_.commit, m_.by), (2, merge, m));
    assert_eq!(m_.approvals, [e, m].into());
    assert_eq!(p.comments.len(), 4);
    for c in &p.comments[..3] {
        let l = c.location.as_ref().unwrap();
        assert_eq!((l.revision, l.path.as_str(), l.line), (0, "lib.rs", 2));
    }
    assert_eq!(p.comments[1].reply_to, Some(c1));
    assert_eq!(p.comments[2].reply_to, Some(c1));
}

#[test]
fn merge_commits_merge_or_report_conflicts() {
    let fx = Fixture::new();
    let (path, repo) = fx.repo("r");
    git(&path, &["checkout", "-q", "-b", "master"]);
    let base = commit(&path, "a", "1\n");
    git(&path, &["checkout", "-q", "-b", "topic"]);
    let topic = commit(&path, "b", "topic\n");
    git(&path, &["checkout", "-q", "master"]);
    let master = commit(&path, "c", "master\n");

    let Merging::Clean(merged) = pr::merge_commit(&repo, master, topic, "Merge").unwrap() else {
        panic!("expected a clean merge");
    };
    let merged = repo.find_commit(merged).unwrap();
    assert_eq!(merged.parent_ids().collect::<Vec<_>>(), [master, topic]);
    let tree = merged.tree().unwrap();
    assert!(["a", "b", "c"].iter().all(|f| tree.get_name(f).is_some()));

    git(&path, &["checkout", "-q", "-b", "other", &base.to_string()]);
    let other = commit(&path, "c", "other\n");
    assert_eq!(
        pr::merge_commit(&repo, master, other, "Merge").unwrap(),
        Merging::Conflicts(vec!["c".into()])
    );
}

#[test]
fn code_travels_with_sync_and_must_match_its_name() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let (pa, ra) = fx.clone(&remote, "a");
    let (_, rb) = fx.clone(&remote, "b");
    let (sa, a) = person(&ra, &fx, "alice");
    let (sb, b) = person(&rb, &fx, "bob");
    sync(&ra, "origin", Some(&sa)).unwrap();
    sync(&rb, "origin", Some(&sb)).unwrap();
    sync(&ra, "origin", Some(&sa)).unwrap();
    let root = policy::genesis(&ra, &trust(&ra), &sa, &[a, b]).unwrap();
    policy::pin(&rb, root).unwrap();
    sync(&ra, "origin", Some(&sa)).unwrap();
    sync(&rb, "origin", Some(&sb)).unwrap();

    let base = commit(&pa, "a", "1\n");
    let head = commit(&pa, "a", "2\n");
    let id = pr::create(
        &ra,
        &trust(&ra),
        &sa,
        "Two",
        "",
        "two",
        "master",
        head,
        base,
    )
    .unwrap();
    sync(&ra, "origin", Some(&sa)).unwrap();
    sync(&rb, "origin", Some(&sb)).unwrap();
    // The branch was never pushed; the commits came with the pull request.
    let p = pr::load(&rb, &trust(&rb), id).unwrap().model;
    assert!(rb.find_commit(p.latest().head).is_ok());

    // A code ref must name its own commit.
    let other = commit(&pa, "a", "3\n");
    let lie = refs::code_refname(Oid::from_str(&"cd".repeat(20)).unwrap());
    git(&pa, &["push", "-q", "origin", &format!("{other}:{lie}")]);
    let report = sync(&rb, "origin", Some(&sb)).unwrap();
    assert!(
        matches!(report.refs.get(&lie), Some(Outcome::Rejected(_))),
        "{:?}",
        report.refs
    );
    assert!(rb.refname_to_id(&lie).is_err());
}
