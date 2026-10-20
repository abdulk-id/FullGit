//! One-way GitHub bridge.
//!
//! [`import`] remakes a GitHub repository's issues and pull requests as
//! fullgit entities. Nothing is written back. Running it again updates the
//! entities it created (title, description, labels, status, and the comments
//! it imported). Comments added here, and comments GitHub has since deleted,
//! stay.
//!
//! The importer signs every operation, so they are the author where
//! permissions care. GitHub's author is named in the text. Review verdicts
//! are copied as comments, not as reviews: an approval has to be signed by
//! the reviewer.

use std::collections::{BTreeMap, BTreeSet};

use git2::{Oid, Repository};
use serde_json::{Value, json};

use crate::issue::{self, Status as IssueStatus};
use crate::model::{self, Model};
use crate::pr::{self, Place, Side, Status as PrStatus};
use crate::sign::Signer;
use crate::trust::{Role, Trust};
use crate::{Error, Result};

/// `owner/name` from a GitHub remote URL, or from `owner/name` itself.
pub fn parse_repo(text: &str) -> Option<String> {
    let text = text.trim();
    if let Some(repo) = repo_from_url(text) {
        return Some(repo);
    }
    let (owner, name) = text.split_once('/')?;
    if text.split('/').count() == 2 && component(owner) && component(name) {
        Some(format!("{owner}/{name}"))
    } else {
        None
    }
}

/// `owner/name` from a remote URL, when the host is GitHub.
pub fn repo_from_url(url: &str) -> Option<String> {
    let url = url.trim().trim_end_matches('/').trim_end_matches(".git");
    let rest = if let Some(rest) = url.strip_prefix("git@github.com:") {
        rest
    } else {
        let rest = url
            .strip_prefix("ssh://")
            .or_else(|| url.strip_prefix("git://"))
            .or_else(|| url.strip_prefix("https://"))
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        let rest = rest.strip_prefix("git@").unwrap_or(rest);
        rest.strip_prefix("github.com/")
            .or_else(|| rest.strip_prefix("www.github.com/"))?
    };
    let mut parts = rest.split('/');
    let owner = parts.next()?;
    let name = parts.next()?;
    if parts.next().is_some() || !component(owner) || !component(name) {
        return None;
    }
    Some(format!("{owner}/{name}"))
}

fn component(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !s.ends_with('.')
}

/// Fetches `refs/pull/<number>/head` into a local ref sync does not push.
pub fn fetch_pull_head(repo: &Repository, remote: &str, number: u64) -> Result<Oid> {
    let dst = format!("refs/fullgit-github/pull/{number}/head");
    let spec = format!("+refs/pull/{number}/head:{dst}");
    crate::sync::git(repo, &["fetch", "--quiet", remote, &spec])?;
    Ok(repo.refname_to_id(&dst)?)
}

/// Fetches `refs/heads/<branch>` into a local ref sync does not push.
pub fn fetch_branch_tip(repo: &Repository, remote: &str, branch: &str) -> Result<Oid> {
    if !git2::Reference::is_valid_name(&format!("refs/heads/{branch}")) {
        return Err(git2::Error::from_str(&format!("{branch:?} is not a branch name")).into());
    }
    let dst = format!("refs/fullgit-github/heads/{branch}");
    let spec = format!("+refs/heads/{branch}:{dst}");
    crate::sync::git(repo, &["fetch", "--quiet", remote, &spec])?;
    Ok(repo.refname_to_id(&dst)?)
}

/// Fetches one commit by its id. GitHub often refuses this; the pull and
/// branch refs are the ones that work.
pub fn fetch_sha(repo: &Repository, remote: &str, oid: Oid) -> Result<()> {
    crate::sync::git(repo, &["fetch", "--quiet", remote, &oid.to_string()])?;
    repo.find_commit(oid)?;
    Ok(())
}

/// How a copied comment should read. Empty text copies nothing.
pub fn attributed(author: &str, text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let author = author.trim().trim_start_matches('@');
    if author.is_empty() {
        Some(text.to_owned())
    } else {
        Some(format!("@{author}: {text}"))
    }
}

/// A GitHub issue or pull request, already fetched, ready to remake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// `owner/name`.
    pub repo: String,
    pub issues: Vec<RemoteIssue>,
    pub prs: Vec<RemotePr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIssue {
    pub number: u64,
    pub title: String,
    pub body: String,
    pub open: bool,
    pub author: String,
    pub url: String,
    pub labels: Vec<String>,
    pub assignees: Vec<String>,
    pub comments: Vec<Note>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteState {
    Open,
    Closed,
    Merged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePr {
    pub number: u64,
    pub title: String,
    pub body: String,
    pub state: RemoteState,
    pub author: String,
    pub url: String,
    /// Head branch on GitHub.
    pub source: String,
    /// Owner of the head repository, when it is a fork.
    pub source_owner: String,
    pub target: String,
    pub draft: bool,
    pub merged_by: Option<String>,
    /// Labels, named as on GitHub. Pull requests don't carry labels here;
    /// these are written into the description.
    pub labels: Vec<String>,
    pub head: Option<Oid>,
    /// The base branch's tip as GitHub reported it.
    pub base_sha: Option<Oid>,
    /// The target branch's tip in this clone, when it has been fetched.
    pub target_tip: Option<Oid>,
    pub merge_commit: Option<Oid>,
    pub notes: Vec<Note>,
}

/// One comment, review, or line comment. `key` is stable across imports
/// (`comment:1`, `review:2`, `line:3`). `body` is stored as given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub key: String,
    pub body: String,
    pub line: Option<Line>,
    /// `key` of the line comment this replies to.
    pub reply_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub path: String,
    pub line: u32,
    pub side: Side,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Issue,
    PullRequest,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Issue => "issue",
            Kind::PullRequest => "pull request",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Created(Oid),
    Updated(Oid),
    Unchanged(Oid),
    Skipped(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: Kind,
    pub number: u64,
    pub change: Change,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedLabel {
    pub label: String,
    /// GitHub's name, when it was rewritten to fit.
    pub github_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub labels_added: Vec<AddedLabel>,
    pub labels_skipped: Vec<(String, String)>,
    pub entries: Vec<Entry>,
}

impl Report {
    pub fn wrote(&self) -> bool {
        !self.labels_added.is_empty()
            || self
                .entries
                .iter()
                .any(|e| matches!(e.change, Change::Created(_) | Change::Updated(_)))
    }
}

/// Remakes `snapshot` in `repo`. The same snapshot a second time changes
/// nothing.
pub fn import(repo: &Repository, signer: &dyn Signer, snapshot: &Snapshot) -> Result<Report> {
    let trust = Trust::load(repo)?;
    model::needs_policy::<issue::Issue>(&trust)?;
    let me = signer_id(&trust, signer)?;
    if trust.role(me) < Some(Role::Contributor) {
        return Err(Error::Policy(
            "importing from GitHub needs a contributor".into(),
        ));
    }
    let prepared = ensure_labels(repo, &trust, signer, me, snapshot)?;
    let trust = prepared.trust;
    let mut index = index_all(repo)?;
    let ctx = Ctx {
        repo,
        trust: &trust,
        signer,
        repo_name: &snapshot.repo,
        labels: &prepared.labels,
    };
    let mut entries = Vec::new();
    for issue in &snapshot.issues {
        entries.push(import_issue(&ctx, &mut index, issue)?);
    }
    for pr in &snapshot.prs {
        entries.push(import_pr(&ctx, &mut index, pr)?);
    }
    Ok(Report {
        labels_added: prepared.added,
        labels_skipped: prepared.skipped,
        entries,
    })
}

struct Prepared {
    trust: Trust,
    labels: BTreeMap<String, String>,
    added: Vec<AddedLabel>,
    skipped: Vec<(String, String)>,
}

struct Ctx<'a> {
    repo: &'a Repository,
    trust: &'a Trust,
    signer: &'a dyn Signer,
    repo_name: &'a str,
    labels: &'a BTreeMap<String, String>,
}

fn signer_id(trust: &Trust, signer: &dyn Signer) -> Result<Oid> {
    match trust
        .identities_with_key(signer.public_key().key_data())
        .as_slice()
    {
        [id] => Ok(*id),
        [] => Err(Error::Policy(
            "your signing key belongs to no identity; run `fullgit id create`".into(),
        )),
        _ => Err(Error::Policy(
            "your signing key belongs to several identities".into(),
        )),
    }
}

fn ensure_labels(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    me: Oid,
    snapshot: &Snapshot,
) -> Result<Prepared> {
    let maintainer = trust.role(me) >= Some(Role::Maintainer);
    let mut have: BTreeSet<String> = issue::available(trust).cloned().unwrap_or_default();
    let mut added: Vec<AddedLabel> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for issue in &snapshot.issues {
        for name in &issue.labels {
            if !seen.insert(name) {
                continue;
            }
            let Some(label) = sanitize_label(name) else {
                skipped.push((name.clone(), "nothing left that can be a label".into()));
                continue;
            };
            if !have.contains(&label) {
                if !maintainer {
                    skipped.push((name.clone(), "adding a label needs a maintainer".into()));
                    continue;
                }
                match crate::policy::label_add(repo, trust, signer, &label) {
                    Ok(_) => {
                        have.insert(label.clone());
                        added.push(AddedLabel {
                            label: label.clone(),
                            github_name: (name != &label).then(|| name.clone()),
                        });
                    }
                    Err(e) => {
                        skipped.push((name.clone(), explain(e)));
                        continue;
                    }
                }
            } else if let Some(slot) = added.iter_mut().find(|a| a.label == label)
                && slot.github_name.is_none()
                && name != &label
            {
                slot.github_name = Some(name.clone());
            }
            map.insert(name.clone(), label);
        }
    }
    let trust = Trust::load(repo)?;
    let listed = issue::available(&trust).cloned().unwrap_or_default();
    map.retain(|_, label| listed.contains(label));
    added.retain(|a| listed.contains(&a.label));
    Ok(Prepared {
        trust,
        labels: map,
        added,
        skipped,
    })
}

/// Spaces and commas become hyphens. GitHub labels often have spaces;
/// fullgit labels can't.
fn sanitize_label(name: &str) -> Option<String> {
    let mut s = String::new();
    for c in name.trim().chars() {
        if c.is_whitespace() || c == ',' {
            if !s.ends_with('-') && !s.is_empty() {
                s.push('-');
            }
        } else {
            s.push(c);
        }
    }
    while s.ends_with('-') {
        s.pop();
    }
    if s.len() > 50 {
        let mut end = 50;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        while s.ends_with('-') {
            s.pop();
        }
    }
    issue::valid_label(&s).ok()?;
    Some(s)
}

fn mapped_labels(names: &[String], map: &BTreeMap<String, String>) -> Vec<String> {
    let mut out: Vec<String> = names.iter().filter_map(|n| map.get(n).cloned()).collect();
    out.sort();
    out.dedup();
    out
}

struct Index {
    issues: BTreeMap<(String, u64), Oid>,
    prs: BTreeMap<(String, u64), Oid>,
    /// Entity, note key → the comment operation.
    notes: BTreeMap<(Oid, String), Oid>,
}

fn index_all(repo: &Repository) -> Result<Index> {
    let mut index = Index {
        issues: BTreeMap::new(),
        prs: BTreeMap::new(),
        notes: BTreeMap::new(),
    };
    index_namespace::<issue::Issue>(repo, &mut index.issues, &mut index.notes)?;
    index_namespace::<pr::Pr>(repo, &mut index.prs, &mut index.notes)?;
    Ok(index)
}

fn index_namespace<M: Model>(
    repo: &Repository,
    origins: &mut BTreeMap<(String, u64), Oid>,
    notes: &mut BTreeMap<(Oid, String), Oid>,
) -> Result<()> {
    for id in model::list::<M>(repo)? {
        let head = repo.refname_to_id(&model::refname::<M>(id))?;
        let ops = crate::load(repo, &[head])?;
        if let Some(op) = ops.iter().find(|op| op.parents.is_empty())
            && let Some(origin) = github_origin(&op.op.payload)
        {
            origins.insert(origin, id);
        }
        for op in &ops {
            if let Some(key) = github_note(&op.op.payload) {
                notes.insert((id, key), op.id);
            }
        }
    }
    Ok(())
}

fn github_origin(payload: &Value) -> Option<(String, u64)> {
    let g = payload.get("github")?;
    let repo = g.get("repo")?.as_str()?.to_owned();
    let number = g.get("number")?.as_u64()?;
    if repo.is_empty() {
        return None;
    }
    Some((repo, number))
}

fn github_note(payload: &Value) -> Option<String> {
    payload
        .get("github")
        .and_then(|g| g.get("note"))
        .and_then(|n| n.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn import_issue(ctx: &Ctx<'_>, index: &mut Index, issue: &RemoteIssue) -> Result<Entry> {
    let key = (ctx.repo_name.to_owned(), issue.number);
    let title = match issue::title(&issue.title) {
        Ok(t) => t,
        Err(reason) => return Ok(skipped(Kind::Issue, issue.number, reason)),
    };
    let body = description(
        &issue.body,
        &origin_line(
            &issue.url,
            ctx.repo_name,
            issue.number,
            "issue",
            &issue.author,
        ),
        &extra_lines(&issue.assignees, &[], false, None),
    );
    let wanted = mapped_labels(&issue.labels, ctx.labels);
    let (id, created) = if let Some(id) = index.issues.get(&key).copied() {
        (id, false)
    } else {
        let id = match create_issue(ctx, issue.number, &title, &body, &wanted) {
            Ok(id) => id,
            Err(e @ Error::Rejected { .. } | e @ Error::Policy(_)) => {
                return Ok(skipped(Kind::Issue, issue.number, explain(e)));
            }
            Err(e) => return Err(e),
        };
        index.issues.insert(key, id);
        (id, true)
    };
    let loaded = match issue::load(ctx.repo, ctx.trust, id) {
        Ok(loaded) => loaded,
        Err(e @ Error::Rejected { .. } | e @ Error::Policy(_)) => {
            return Ok(skipped(Kind::Issue, issue.number, explain(e)));
        }
        Err(e) => return Err(e),
    };
    let mut notes_out = Vec::new();
    let mut wrote = false;
    let mut live_labels = loaded.model.labels.clone();
    let mut live_notes = note_bodies(id, &loaded.model.comments, index);
    if !created {
        let title_change = (loaded.model.title != title).then_some(title.as_str());
        let body_change = (loaded.model.body != body).then_some(body.as_str());
        if (title_change.is_some() || body_change.is_some())
            && soft(
                &mut notes_out,
                "description",
                issue::edit(
                    ctx.repo,
                    ctx.trust,
                    ctx.signer,
                    id,
                    title_change,
                    body_change,
                ),
            )?
            .is_some()
        {
            wrote = true;
        }
    }
    wrote |= sync_issue_notes(ctx, id, &issue.comments, &mut live_notes, &mut notes_out)?;
    wrote |= sync_labels(ctx, id, &wanted, &mut live_labels, &mut notes_out)?;
    let want = if issue.open {
        IssueStatus::Open
    } else {
        IssueStatus::Closed
    };
    if loaded.model.status != want
        && soft(
            &mut notes_out,
            "status",
            issue::set_status(ctx.repo, ctx.trust, ctx.signer, id, want),
        )?
        .is_some()
    {
        wrote = true;
    }
    remember_removed(&issue.comments, &live_notes, &mut notes_out);
    Ok(Entry {
        kind: Kind::Issue,
        number: issue.number,
        change: change_of(id, created, wrote),
        notes: notes_out,
    })
}

fn import_pr(ctx: &Ctx<'_>, index: &mut Index, pr: &RemotePr) -> Result<Entry> {
    let key = (ctx.repo_name.to_owned(), pr.number);
    let title = match issue::title(&pr.title) {
        Ok(t) => t,
        Err(reason) => return Ok(skipped(Kind::PullRequest, pr.number, reason)),
    };
    let source = match source_branch(&pr.source_owner, &pr.source, &pr.target) {
        Ok(s) => s,
        Err(reason) => return Ok(skipped(Kind::PullRequest, pr.number, reason)),
    };
    if !is_branch(&pr.target) {
        return Ok(skipped(
            Kind::PullRequest,
            pr.number,
            format!("{:?} is not a branch name", pr.target),
        ));
    }
    let (head, base) = match revision_points(ctx.repo, pr) {
        Ok(points) => points,
        Err(reason) => return Ok(skipped(Kind::PullRequest, pr.number, reason)),
    };
    let body = description(
        &pr.body,
        &origin_line(&pr.url, ctx.repo_name, pr.number, "pull", &pr.author),
        &extra_lines(&[], &pr.labels, pr.draft, pr.merged_by.as_deref()),
    );
    let (id, created) = if let Some(id) = index.prs.get(&key).copied() {
        (id, false)
    } else {
        let id = match create_pr(ctx, pr, &title, &body, &source, head, base) {
            Ok(id) => id,
            Err(e @ Error::Rejected { .. } | e @ Error::Policy(_)) => {
                return Ok(skipped(Kind::PullRequest, pr.number, explain(e)));
            }
            Err(e) => return Err(e),
        };
        index.prs.insert(key, id);
        (id, true)
    };
    let loaded = match pr::load(ctx.repo, ctx.trust, id) {
        Ok(loaded) => loaded,
        Err(e @ Error::Rejected { .. } | e @ Error::Policy(_)) => {
            return Ok(skipped(Kind::PullRequest, pr.number, explain(e)));
        }
        Err(e) => return Err(e),
    };
    let mut notes_out = Vec::new();
    let mut wrote = false;
    if !created && loaded.model.source != source {
        notes_out.push(format!(
            "GitHub's head branch is {source}; this pull request stays on {}",
            loaded.model.source
        ));
    }
    if !created && loaded.model.target != pr.target {
        notes_out.push(format!(
            "GitHub's base branch is {}; this pull request stays on {}",
            pr.target, loaded.model.target
        ));
    }
    if !created && (loaded.model.title != title || loaded.model.body != body) {
        let title_change = (loaded.model.title != title).then_some(title.as_str());
        let body_change = (loaded.model.body != body).then_some(body.as_str());
        if soft(
            &mut notes_out,
            "description",
            pr::edit(
                ctx.repo,
                ctx.trust,
                ctx.signer,
                id,
                title_change,
                body_change,
            ),
        )?
        .is_some()
        {
            wrote = true;
        }
    }
    let mut revision = loaded.model.latest().id;
    let mut status = loaded.model.status;
    if !created
        && status != PrStatus::Merged
        && (loaded.model.latest().head != head || loaded.model.latest().base != base)
    {
        if let Some(op) = soft(
            &mut notes_out,
            "revision",
            pr::revise(
                ctx.repo,
                ctx.trust,
                ctx.signer,
                id,
                head,
                base,
                "Updated from GitHub.",
            ),
        )? {
            revision = op;
            wrote = true;
        }
    } else if !created && status == PrStatus::Merged && loaded.model.latest().head != head {
        notes_out
            .push("GitHub has new commits; a merged pull request stays as it was recorded".into());
    }
    let mut live_notes = note_bodies_pr(id, &loaded.model.comments, index);
    wrote |= sync_pr_notes(
        ctx,
        id,
        revision,
        &pr.notes,
        &mut live_notes,
        &mut notes_out,
    )?;
    wrote |= sync_pr_state(ctx, id, pr, revision, &mut status, &mut notes_out)?;
    remember_removed(&pr.notes, &live_notes, &mut notes_out);
    Ok(Entry {
        kind: Kind::PullRequest,
        number: pr.number,
        change: change_of(id, created, wrote),
        notes: notes_out,
    })
}

fn revision_points(repo: &Repository, pr: &RemotePr) -> Result<(Oid, Oid), String> {
    let head = pr.head.ok_or("its head commit is not in this clone")?;
    if repo.find_commit(head).is_err() {
        return Err(format!("its head commit {head} is not in this clone"));
    }
    for anchor in [pr.target_tip, pr.base_sha].into_iter().flatten() {
        if repo.find_commit(anchor).is_err() {
            continue;
        }
        let base = repo.merge_base(head, anchor).unwrap_or(anchor);
        if repo.find_commit(base).is_ok() {
            return Ok((head, base));
        }
    }
    Err("its base commit is not in this clone".into())
}

fn create_issue(
    ctx: &Ctx<'_>,
    number: u64,
    title: &str,
    body: &str,
    labels: &[String],
) -> Result<Oid> {
    issue::check_labels(ctx.trust, labels)?;
    model::create::<issue::Issue>(
        ctx.repo,
        ctx.trust,
        ctx.signer,
        "issue.create",
        json!({
            "title": title,
            "body": body,
            "labels": labels,
            "github": { "repo": ctx.repo_name, "number": number },
        }),
    )
}

fn create_pr(
    ctx: &Ctx<'_>,
    pr: &RemotePr,
    title: &str,
    body: &str,
    source: &str,
    head: Oid,
    base: Oid,
) -> Result<Oid> {
    pr::keep_code(ctx.repo, &[head, base])?;
    model::create::<pr::Pr>(
        ctx.repo,
        ctx.trust,
        ctx.signer,
        "pr.create",
        json!({
            "title": title,
            "body": body,
            "source": source,
            "target": pr.target,
            "head": head.to_string(),
            "base": base.to_string(),
            "github": { "repo": ctx.repo_name, "number": pr.number },
        }),
    )
}

fn sync_issue_notes(
    ctx: &Ctx<'_>,
    id: Oid,
    notes: &[Note],
    live: &mut BTreeMap<String, (Oid, String)>,
    out: &mut Vec<String>,
) -> Result<bool> {
    let mut wrote = false;
    for note in notes {
        let body = note.body.trim();
        if body.is_empty() {
            continue;
        }
        wrote |= write_note(
            live,
            &note.key,
            body,
            out,
            |body| {
                model::update::<issue::Issue>(
                    ctx.repo,
                    ctx.trust,
                    id,
                    ctx.signer,
                    "issue.comment",
                    json!({ "body": body, "github": { "note": note.key } }),
                )
            },
            |comment, body| issue::edit_comment(ctx.repo, ctx.trust, ctx.signer, id, comment, body),
        )?;
    }
    Ok(wrote)
}

fn sync_pr_notes(
    ctx: &Ctx<'_>,
    id: Oid,
    revision: Oid,
    notes: &[Note],
    live: &mut BTreeMap<String, (Oid, String)>,
    out: &mut Vec<String>,
) -> Result<bool> {
    let mut wrote = false;
    for note in notes {
        let (place, body) = placement(note, revision, live);
        let body = body.trim();
        if body.is_empty() {
            continue;
        }
        let body = body.to_owned();
        wrote |= write_note(
            live,
            &note.key,
            &body,
            out,
            |body| {
                let mut payload = json!({ "body": body, "github": { "note": note.key } });
                match place {
                    Place::General => {}
                    Place::Line {
                        revision,
                        path,
                        line,
                        side,
                    } => {
                        payload["revision"] = revision.to_string().into();
                        payload["path"] = path.into();
                        payload["line"] = line.into();
                        payload["side"] = side.as_str().into();
                    }
                    Place::Reply(to) => payload["reply_to"] = to.to_string().into(),
                }
                model::update::<pr::Pr>(ctx.repo, ctx.trust, id, ctx.signer, "pr.comment", payload)
            },
            |comment, body| pr::edit_comment(ctx.repo, ctx.trust, ctx.signer, id, comment, body),
        )?;
    }
    Ok(wrote)
}

/// Where `note` goes, and the text to store. Decided from the note alone,
/// so a later import doesn't move a comment it already placed.
fn placement<'a>(
    note: &'a Note,
    revision: Oid,
    live: &BTreeMap<String, (Oid, String)>,
) -> (Place<'a>, String) {
    if let Some(parent) = note.reply_to.as_deref().and_then(|k| live.get(k)) {
        return (Place::Reply(parent.0), note.body.clone());
    }
    if let Some(line) = &note.line {
        let path = line.path.trim_start_matches('/');
        if line.line > 0 && !path.is_empty() && is_path(path) {
            return (
                Place::Line {
                    revision,
                    path,
                    line: line.line,
                    side: line.side,
                },
                note.body.clone(),
            );
        }
        return (
            Place::General,
            format!("{}\n\n({}:{})", note.body.trim(), line.path, line.line),
        );
    }
    (Place::General, note.body.clone())
}

fn is_path(path: &str) -> bool {
    !path.starts_with('/') && !path.contains('\0') && !path.contains('\n')
}

fn write_note<N, E>(
    live: &mut BTreeMap<String, (Oid, String)>,
    key: &str,
    body: &str,
    out: &mut Vec<String>,
    new: N,
    edit: E,
) -> Result<bool>
where
    N: FnOnce(&str) -> Result<Oid>,
    E: FnOnce(Oid, &str) -> Result<Oid>,
{
    if let Some((comment, current)) = live.get(key) {
        if current == body {
            return Ok(false);
        }
        let comment = *comment;
        if soft(out, key, edit(comment, body))?.is_some() {
            live.insert(key.to_owned(), (comment, body.to_owned()));
            Ok(true)
        } else {
            Ok(false)
        }
    } else if let Some(id) = soft(out, key, new(body))? {
        live.insert(key.to_owned(), (id, body.to_owned()));
        Ok(true)
    } else {
        Ok(false)
    }
}

fn sync_labels(
    ctx: &Ctx<'_>,
    id: Oid,
    wanted: &[String],
    live: &mut BTreeSet<String>,
    out: &mut Vec<String>,
) -> Result<bool> {
    let wanted: BTreeSet<String> = wanted.iter().cloned().collect();
    let add: Vec<String> = wanted.difference(live).cloned().collect();
    let remove: Vec<String> = live.difference(&wanted).cloned().collect();
    if add.is_empty() && remove.is_empty() {
        return Ok(false);
    }
    if soft(
        out,
        "labels",
        issue::label(ctx.repo, ctx.trust, ctx.signer, id, &add, &remove),
    )?
    .is_some()
    {
        *live = wanted;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn sync_pr_state(
    ctx: &Ctx<'_>,
    id: Oid,
    pr: &RemotePr,
    revision: Oid,
    status: &mut PrStatus,
    out: &mut Vec<String>,
) -> Result<bool> {
    match (pr.state, *status) {
        (RemoteState::Merged, PrStatus::Merged) | (RemoteState::Open, PrStatus::Open) => Ok(false),
        (RemoteState::Closed, PrStatus::Closed) => Ok(false),
        (RemoteState::Merged, _) => {
            if let Some(commit) = pr.merge_commit.filter(|c| ctx.repo.find_commit(*c).is_ok()) {
                if soft(
                    out,
                    "merge",
                    pr::record_merge(ctx.repo, ctx.trust, ctx.signer, id, revision, commit),
                )?
                .is_some()
                {
                    *status = PrStatus::Merged;
                    return Ok(true);
                }
                return Ok(false);
            }
            out.push(
                "GitHub merged this, and the merge commit is not in this clone, so it was closed"
                    .into(),
            );
            close_pr(ctx, id, status, out)
        }
        (RemoteState::Open, PrStatus::Closed) => set_pr(ctx, id, PrStatus::Open, status, out),
        (RemoteState::Open, PrStatus::Merged) => {
            out.push("GitHub has this open again; a merged pull request stays merged".into());
            Ok(false)
        }
        (RemoteState::Closed, PrStatus::Open) => set_pr(ctx, id, PrStatus::Closed, status, out),
        (RemoteState::Closed, PrStatus::Merged) => {
            out.push("GitHub has this closed; it stays merged".into());
            Ok(false)
        }
    }
}

fn close_pr(ctx: &Ctx<'_>, id: Oid, status: &mut PrStatus, out: &mut Vec<String>) -> Result<bool> {
    if *status == PrStatus::Closed {
        return Ok(false);
    }
    set_pr(ctx, id, PrStatus::Closed, status, out)
}

fn set_pr(
    ctx: &Ctx<'_>,
    id: Oid,
    want: PrStatus,
    status: &mut PrStatus,
    out: &mut Vec<String>,
) -> Result<bool> {
    if soft(
        out,
        "status",
        pr::set_status(ctx.repo, ctx.trust, ctx.signer, id, want),
    )?
    .is_some()
    {
        *status = want;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn soft(out: &mut Vec<String>, what: &str, result: Result<Oid>) -> Result<Option<Oid>> {
    match result {
        Ok(id) => Ok(Some(id)),
        Err(e @ Error::Rejected { .. } | e @ Error::Policy(_)) => {
            out.push(format!("{what}: {}", explain(e)));
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn note_bodies(
    id: Oid,
    comments: &[issue::Comment],
    index: &Index,
) -> BTreeMap<String, (Oid, String)> {
    let mut live = BTreeMap::new();
    for ((entity, key), op) in &index.notes {
        if *entity == id
            && let Some(c) = comments.iter().find(|c| c.id == *op)
        {
            live.insert(key.clone(), (c.id, c.body.clone()));
        }
    }
    live
}

fn note_bodies_pr(
    id: Oid,
    comments: &[pr::Comment],
    index: &Index,
) -> BTreeMap<String, (Oid, String)> {
    let mut live = BTreeMap::new();
    for ((entity, key), op) in &index.notes {
        if *entity == id
            && let Some(c) = comments.iter().find(|c| c.id == *op)
        {
            live.insert(key.clone(), (c.id, c.body.clone()));
        }
    }
    live
}

fn remember_removed(
    incoming: &[Note],
    live: &BTreeMap<String, (Oid, String)>,
    out: &mut Vec<String>,
) {
    let have: BTreeSet<&str> = incoming.iter().map(|n| n.key.as_str()).collect();
    let kept = live.keys().filter(|k| !have.contains(k.as_str())).count();
    if kept == 1 {
        out.push("kept 1 comment that was removed on GitHub".into());
    } else if kept > 1 {
        out.push(format!("kept {kept} comments that were removed on GitHub"));
    }
}

fn change_of(id: Oid, created: bool, wrote: bool) -> Change {
    if created {
        Change::Created(id)
    } else if wrote {
        Change::Updated(id)
    } else {
        Change::Unchanged(id)
    }
}

fn skipped(kind: Kind, number: u64, why: impl Into<String>) -> Entry {
    Entry {
        kind,
        number,
        change: Change::Skipped(why.into()),
        notes: Vec::new(),
    }
}

fn explain(err: Error) -> String {
    match err {
        Error::Rejected { reason, .. } => reason,
        err => err.to_string(),
    }
}

fn description(body: &str, origin: &str, extra: &[String]) -> String {
    let mut footer = origin.to_owned();
    for line in extra {
        footer.push('\n');
        footer.push_str(line);
    }
    let body = body.trim();
    if body.is_empty() {
        footer
    } else {
        format!("{body}\n\n{footer}")
    }
}

fn origin_line(url: &str, repo: &str, number: u64, kind: &str, author: &str) -> String {
    let place = if url.trim().is_empty() {
        format!("GitHub {repo} {kind} #{number}")
    } else {
        url.trim().to_owned()
    };
    let author = author.trim().trim_start_matches('@');
    if author.is_empty() {
        format!("Imported from {place}.")
    } else {
        format!("Imported from {place} by @{author}.")
    }
}

fn extra_lines(
    assignees: &[String],
    labels: &[String],
    draft: bool,
    merged_by: Option<&str>,
) -> Vec<String> {
    let mut lines = Vec::new();
    let mut names: Vec<&str> = assignees
        .iter()
        .map(|s| s.trim().trim_start_matches('@'))
        .filter(|s| !s.is_empty())
        .collect();
    names.sort_unstable();
    names.dedup();
    if !names.is_empty() {
        let listed = names
            .iter()
            .map(|n| format!("@{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("Assignees on GitHub: {listed}."));
    }
    let mut labels: Vec<&str> = labels
        .iter()
        .map(String::as_str)
        .filter(|s| !s.trim().is_empty())
        .collect();
    labels.sort_unstable();
    labels.dedup();
    if !labels.is_empty() {
        lines.push(format!("Labels on GitHub: {}.", labels.join(", ")));
    }
    if draft {
        lines.push("A draft on GitHub.".into());
    }
    if let Some(by) = merged_by.map(str::trim).filter(|s| !s.is_empty()) {
        let by = by.trim_start_matches('@');
        lines.push(format!("Merged on GitHub by @{by}."));
    }
    lines
}

fn source_branch(owner: &str, head: &str, target: &str) -> Result<String, String> {
    let candidates = [
        head.to_owned(),
        format!("{owner}/{head}"),
        format!("{owner}-{head}"),
    ];
    for candidate in candidates {
        let name = sanitize_branch(&candidate);
        if name != target && is_branch(&name) {
            return Ok(name);
        }
    }
    Err(format!(
        "no usable branch name for {owner}:{head} (the base is {target})"
    ))
}

fn is_branch(name: &str) -> bool {
    !name.is_empty() && git2::Reference::is_valid_name(&format!("refs/heads/{name}"))
}

fn sanitize_branch(raw: &str) -> String {
    let mut out = String::new();
    for c in raw.chars() {
        if c.is_control() || matches!(c, ' ' | '~' | '^' | ':' | '?' | '*' | '[' | '\\') {
            if !out.ends_with('-') && !out.is_empty() {
                out.push('-');
            }
        } else {
            out.push(c);
        }
    }
    while out.contains("..") {
        out = out.replace("..", ".");
    }
    out.replace("@{", "-")
        .trim_matches(|c: char| c == '.' || c == '/' || c == '-')
        .to_owned()
}
