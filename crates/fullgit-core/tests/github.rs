//! GitHub bridge: issues and pull requests remade locally, one way.

mod common;

use common::Fixture;
use fullgit_core::github::{
    self, Change, Kind, Line, Note, RemoteIssue, RemotePr, RemoteState, Snapshot,
};
use fullgit_core::pr::Side;
use fullgit_core::{Error, Role, SshKeygenSigner, Trust, identity, issue, model, policy, pr, refs};
use git2::{Oid, Repository};
use std::path::Path;

fn person(repo: &Repository, fx: &Fixture, name: &str) -> (SshKeygenSigner, Oid) {
    let signer = fx.new_signer(name);
    let id = identity::create(repo, &signer, name, &format!("{name}@example.com")).unwrap();
    (signer, id)
}

fn trust(repo: &Repository) -> Trust {
    Trust::load(repo).unwrap()
}

fn rev(path: &Path) -> Oid {
    Oid::from_str(common::git(path, &["rev-parse", "HEAD"]).trim()).unwrap()
}

fn commit(path: &Path, message: &str) -> Oid {
    common::git(path, &["commit", "--allow-empty", "-q", "-m", message]);
    rev(path)
}

fn id_of(entry: &github::Entry) -> Oid {
    match entry.change {
        Change::Created(id) | Change::Updated(id) | Change::Unchanged(id) => id,
        Change::Skipped(ref why) => panic!("skipped: {why}"),
    }
}

fn note(key: &str, body: &str) -> Note {
    Note {
        key: key.into(),
        body: body.into(),
        line: None,
        reply_to: None,
    }
}

fn issue_snapshot(
    title: &str,
    body: &str,
    open: bool,
    labels: &[&str],
    comments: Vec<Note>,
) -> Snapshot {
    Snapshot {
        repo: "acme/widgets".into(),
        issues: vec![RemoteIssue {
            number: 4,
            title: title.into(),
            body: body.into(),
            open,
            author: "octocat".into(),
            url: "https://github.com/acme/widgets/issues/4".into(),
            labels: labels.iter().map(|s| (*s).to_owned()).collect(),
            assignees: vec!["hubot".into()],
            comments,
        }],
        prs: Vec::new(),
    }
}

#[test]
fn parses_github_remotes() {
    assert_eq!(
        github::repo_from_url("git@github.com:acme/widgets.git").as_deref(),
        Some("acme/widgets")
    );
    assert_eq!(
        github::repo_from_url("https://github.com/acme/widgets").as_deref(),
        Some("acme/widgets")
    );
    assert_eq!(
        github::repo_from_url("ssh://git@github.com/acme/widgets.git").as_deref(),
        Some("acme/widgets")
    );
    assert_eq!(
        github::repo_from_url("https://gitlab.com/acme/widgets"),
        None
    );
    assert_eq!(
        github::parse_repo("acme/widgets").as_deref(),
        Some("acme/widgets")
    );
}

#[test]
fn imports_issues_and_updates_them_in_place() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let (alice, a) = person(&repo, &fx, "alice");
    policy::genesis(&repo, &trust(&repo), &alice, &[a]).unwrap();
    policy::label_add(&repo, &trust(&repo), &alice, "bug").unwrap();

    let snap = issue_snapshot(
        "Sync loses ops",
        "Steps",
        true,
        &["bug", "good first issue"],
        vec![note("comment:1", "@ada: reproduced")],
    );
    let report = github::import(&repo, &alice, &snap).unwrap();
    assert_eq!(report.labels_added.len(), 1);
    assert_eq!(report.labels_added[0].label, "good-first-issue");
    assert_eq!(
        report.labels_added[0].github_name.as_deref(),
        Some("good first issue")
    );
    let id = id_of(&report.entries[0]);
    assert!(matches!(report.entries[0].change, Change::Created(_)));

    let t = trust(&repo);
    let loaded = issue::load(&repo, &t, id).unwrap().model;
    assert_eq!(loaded.title, "Sync loses ops");
    assert!(loaded.body.contains("Steps"));
    assert!(loaded.body.contains("by @octocat"));
    assert!(loaded.body.contains("@hubot"));
    assert_eq!(
        loaded.labels.iter().map(String::as_str).collect::<Vec<_>>(),
        ["bug", "good-first-issue"]
    );
    assert_eq!(loaded.comments.len(), 1);
    assert_eq!(loaded.comments[0].body, "@ada: reproduced");
    assert_eq!(loaded.author, Some(a));

    issue::comment(&repo, &t, &alice, id, "noted locally").unwrap();
    let before = repo
        .refname_to_id(&model::refname::<issue::Issue>(id))
        .unwrap();
    let again = github::import(&repo, &alice, &snap).unwrap();
    assert!(matches!(again.entries[0].change, Change::Unchanged(_)));
    assert!(again.labels_added.is_empty());
    assert_eq!(
        repo.refname_to_id(&model::refname::<issue::Issue>(id))
            .unwrap(),
        before,
        "importing the same issue again writes nothing"
    );
    let kept = issue::load(&repo, &trust(&repo), id).unwrap().model;
    assert_eq!(kept.comments.len(), 2);
    assert!(kept.comments.iter().any(|c| c.body == "noted locally"));

    let edited = issue_snapshot(
        "Sync loses ops",
        "Steps",
        true,
        &["bug", "good first issue"],
        vec![note("comment:1", "@ada: reproduced on Linux")],
    );
    let report = github::import(&repo, &alice, &edited).unwrap();
    assert!(matches!(report.entries[0].change, Change::Updated(_)));
    let loaded = issue::load(&repo, &trust(&repo), id).unwrap().model;
    let github_comment = loaded
        .comments
        .iter()
        .find(|c| c.body.contains("on Linux"))
        .unwrap();
    assert!(github_comment.edited);
    assert!(loaded.comments.iter().any(|c| c.body == "noted locally"));

    let snap = issue_snapshot(
        "Sync drops ops",
        "Steps",
        false,
        &["bug"],
        vec![note("comment:2", "@ada: still")],
    );
    let report = github::import(&repo, &alice, &snap).unwrap();
    assert!(matches!(report.entries[0].change, Change::Updated(_)));
    assert!(
        report.entries[0]
            .notes
            .iter()
            .any(|n| n.contains("kept 1 comment")),
        "{:?}",
        report.entries[0].notes
    );
    let loaded = issue::load(&repo, &trust(&repo), id).unwrap().model;
    assert_eq!(loaded.title, "Sync drops ops");
    assert_eq!(loaded.status, issue::Status::Closed);
    assert_eq!(loaded.labels.iter().collect::<Vec<_>>(), ["bug"]);
    assert_eq!(loaded.comments.len(), 3);
    assert!(loaded.comments.iter().any(|c| c.body.contains("on Linux")));
    assert!(loaded.comments.iter().any(|c| c.body == "@ada: still"));
    assert!(loaded.comments.iter().any(|c| c.body == "noted locally"));

    let same = github::import(&repo, &alice, &snap).unwrap();
    assert!(matches!(same.entries[0].change, Change::Unchanged(_)));
}

#[test]
fn imports_pull_requests_with_discussion_and_merge() {
    let fx = Fixture::new();
    let (path, repo) = fx.repo("r");
    let base = commit(&path, "base");
    let head = commit(&path, "head");
    let (alice, a) = person(&repo, &fx, "alice");
    policy::genesis(&repo, &trust(&repo), &alice, &[a]).unwrap();

    let mut snap = pr_snapshot(head, base, RemoteState::Open, None);
    let report = github::import(&repo, &alice, &snap).unwrap();
    let id = id_of(&report.entries[0]);
    assert!(matches!(report.entries[0].kind, Kind::PullRequest));

    let loaded = pr::load(&repo, &trust(&repo), id).unwrap().model;
    assert_eq!(loaded.source, "fork/master");
    assert_eq!(loaded.target, "master");
    assert_eq!(loaded.revisions[0].head, head);
    assert_eq!(loaded.revisions[0].base, base);
    assert!(
        loaded.reviews.is_empty(),
        "a GitHub approval is not a review"
    );
    assert_eq!(loaded.comments.len(), 3);
    assert_eq!(loaded.comments[0].body, "@ada: here");
    assert_eq!(
        loaded.comments[0]
            .location
            .as_ref()
            .map(|l| (l.path.as_str(), l.line, l.side)),
        Some(("src/lib.rs", 3, Side::New))
    );
    assert_eq!(loaded.comments[1].reply_to, Some(loaded.comments[0].id));
    assert!(
        loaded.comments[2]
            .body
            .contains("approved this pull request")
    );
    assert!(repo.refname_to_id(&refs::code_refname(head)).is_ok());

    let again = github::import(&repo, &alice, &snap).unwrap();
    assert!(matches!(again.entries[0].change, Change::Unchanged(_)));

    let head2 = commit(&path, "more");
    snap.prs[0].head = Some(head2);
    let report = github::import(&repo, &alice, &snap).unwrap();
    assert!(matches!(report.entries[0].change, Change::Updated(_)));
    let loaded = pr::load(&repo, &trust(&repo), id).unwrap().model;
    assert_eq!(loaded.revisions.len(), 2);
    assert_eq!(loaded.latest().head, head2);

    snap.prs[0].state = RemoteState::Merged;
    snap.prs[0].merge_commit = Some(head2);
    snap.prs[0].merged_by = Some("merger".into());
    let report = github::import(&repo, &alice, &snap).unwrap();
    assert!(matches!(report.entries[0].change, Change::Updated(_)));
    let loaded = pr::load(&repo, &trust(&repo), id).unwrap().model;
    assert_eq!(loaded.status, pr::Status::Merged);
    assert_eq!(loaded.merged.unwrap().commit, head2);
    assert!(loaded.body.contains("Merged on GitHub by @merger."));
    assert!(loaded.reviews.is_empty());

    let head3 = commit(&path, "after merge");
    snap.prs[0].head = Some(head3);
    let report = github::import(&repo, &alice, &snap).unwrap();
    assert!(
        report.entries[0]
            .notes
            .iter()
            .any(|n| n.contains("merged pull request stays")),
        "{:?}",
        report.entries[0].notes
    );
    let loaded = pr::load(&repo, &trust(&repo), id).unwrap().model;
    assert_eq!(loaded.revisions.len(), 2);
    assert_eq!(loaded.status, pr::Status::Merged);
}

#[test]
fn skips_a_pull_request_whose_commits_are_missing() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let (alice, a) = person(&repo, &fx, "alice");
    policy::genesis(&repo, &trust(&repo), &alice, &[a]).unwrap();
    let missing = Oid::from_str("0123456789abcdef0123456789abcdef01234567").unwrap();
    let snap = pr_snapshot(missing, missing, RemoteState::Open, None);
    let report = github::import(&repo, &alice, &snap).unwrap();
    match &report.entries[0].change {
        Change::Skipped(why) => assert!(why.contains("not in this clone"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_reader_cannot_import() {
    let fx = Fixture::new();
    let (_, repo) = fx.repo("r");
    let (alice, a) = person(&repo, &fx, "alice");
    let (carol, c) = person(&repo, &fx, "carol");
    policy::genesis(&repo, &trust(&repo), &alice, &[a]).unwrap();
    policy::grant(&repo, &trust(&repo), &alice, c, Role::Reader).unwrap();
    let snap = issue_snapshot("Title", "", true, &[], Vec::new());
    let err = github::import(&repo, &carol, &snap).unwrap_err();
    assert!(matches!(err, Error::Policy(_)), "{err}");
}

#[test]
fn fetch_pull_head_copies_the_pull_ref() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let (path, repo) = fx.clone(&remote, "alice");
    commit(&path, "base");
    common::git(&path, &["push", "-q", "origin", "HEAD:refs/heads/master"]);
    let oid = rev(&path);
    common::git(
        &remote,
        &["update-ref", "refs/pull/7/head", &oid.to_string()],
    );
    let got = github::fetch_pull_head(&repo, "origin", 7).unwrap();
    assert_eq!(got, oid);
    assert_eq!(
        repo.refname_to_id("refs/fullgit-github/pull/7/head")
            .unwrap(),
        oid
    );
}

fn pr_snapshot(head: Oid, base: Oid, state: RemoteState, merge: Option<Oid>) -> Snapshot {
    Snapshot {
        repo: "acme/widgets".into(),
        issues: Vec::new(),
        prs: vec![RemotePr {
            number: 5,
            title: "Retry sync".into(),
            body: "Back off".into(),
            state,
            author: "octocat".into(),
            url: "https://github.com/acme/widgets/pull/5".into(),
            source: "master".into(),
            source_owner: "fork".into(),
            target: "master".into(),
            draft: false,
            merged_by: None,
            labels: vec!["bug".into()],
            head: Some(head),
            base_sha: Some(base),
            target_tip: None,
            merge_commit: merge,
            notes: vec![
                Note {
                    key: "line:9".into(),
                    body: "@ada: here".into(),
                    line: Some(Line {
                        path: "src/lib.rs".into(),
                        line: 3,
                        side: Side::New,
                    }),
                    reply_to: None,
                },
                Note {
                    key: "line:10".into(),
                    body: "@bob: yes".into(),
                    line: Some(Line {
                        path: "src/lib.rs".into(),
                        line: 3,
                        side: Side::New,
                    }),
                    reply_to: Some("line:9".into()),
                },
                note("review:5", "@ada approved this pull request on GitHub."),
            ],
        }],
    }
}
