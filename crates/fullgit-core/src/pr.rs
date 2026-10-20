//! Pull requests, at `refs/fullgit/prs/<id>`.
//!
//! A pull request asks to merge a source branch into a target branch. Each
//! revision is the commit range `base..head`, where `base` is where the
//! source left the target. The root operation is revision 1; `pr.revise`
//! adds the next. A revision's commits are kept under
//! `refs/fullgit/code/<oid>` ([`crate::refs::CODE_PREFIX`]) and travel with
//! `fullgit sync`, so reviewers get exactly what was reviewed even after the
//! branch is rewritten or deleted.
//!
//! Ops: `pr.create {title, body, source, target, head, base}`,
//! `pr.edit {title?, body?}`, `pr.revise {head, base, note?}`,
//! `pr.comment {body, revision?, path?, line?, side?}` or
//! `pr.comment {body, reply_to}`, `pr.comment_edit {comment, body}`,
//! `pr.review {revision, verdict, body?}`, `pr.status {status}`,
//! `pr.merge {revision, commit}`. Revisions are named by their operation.
//!
//! Contributors open pull requests, comment, and review other people's. The
//! author or a maintainer edits, revises, closes and reopens; maintainers
//! merge. Merged is final. The target branch's merge rule
//! ([`crate::policy::Rule`]) is checked by whoever merges, under the policy
//! of the day; replay records which approvals the merged revision had.

use std::collections::{BTreeMap, BTreeSet};

use git2::{Oid, Repository};
use serde_json::{Value, json};

use crate::issue::{text, time, title};
use crate::model::{self, Loaded, Model, ReplayContext};
use crate::op::StoredOp;
use crate::payload;
use crate::policy::Rule;
use crate::refs;
use crate::sign::Signer;
use crate::sync::{git_error, git_output};
use crate::trust::{Role, Trust};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Status {
    #[default]
    Open,
    Closed,
    Merged,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::Closed => "closed",
            Status::Merged => "merged",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

impl std::str::FromStr for Status {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "open" => Ok(Status::Open),
            "closed" => Ok(Status::Closed),
            "merged" => Ok(Status::Merged),
            _ => Err(format!("unknown status {s}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    /// The operation that recorded it; the pull request's id for the first.
    pub id: Oid,
    pub author: Oid,
    pub time: i64,
    pub head: Oid,
    pub base: Oid,
    pub note: String,
}

/// Which version of a file a line comment is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The revision's base.
    Old,
    /// The revision's head.
    New,
}

impl Side {
    pub fn as_str(self) -> &'static str {
        match self {
            Side::Old => "old",
            Side::New => "new",
        }
    }
}

impl std::str::FromStr for Side {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "old" => Ok(Side::Old),
            "new" => Ok(Side::New),
            _ => Err(format!("unknown side {s}")),
        }
    }
}

/// A line of a file in one revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// Index into [`Pr::revisions`].
    pub revision: usize,
    pub path: String,
    pub line: u32,
    pub side: Side,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    pub id: Oid,
    pub author: Oid,
    pub time: i64,
    pub body: String,
    pub edited: bool,
    /// Set for line comments, and replies to them.
    pub location: Option<Location>,
    /// The first comment of the thread this replies to.
    pub reply_to: Option<Oid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Approve,
    /// Changes requested.
    Changes,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Approve => "approve",
            Verdict::Changes => "changes",
        }
    }
}

impl std::str::FromStr for Verdict {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "approve" => Ok(Verdict::Approve),
            "changes" => Ok(Verdict::Changes),
            _ => Err(format!("unknown verdict {s}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    pub id: Oid,
    pub reviewer: Oid,
    pub time: i64,
    /// Index into [`Pr::revisions`].
    pub revision: usize,
    pub verdict: Verdict,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merge {
    pub by: Oid,
    pub time: i64,
    /// Index into [`Pr::revisions`].
    pub revision: usize,
    /// The commit on the target branch that brought the revision in.
    pub commit: Oid,
    /// Who had approved the merged revision.
    pub approvals: BTreeSet<Oid>,
}

/// Something that happened to a pull request, for its timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum What {
    Opened,
    Edited,
    /// Index into [`Pr::revisions`].
    Revised(usize),
    /// Index into [`Pr::comments`].
    Commented(usize),
    /// Index into [`Pr::reviews`].
    Reviewed(usize),
    Status(Status),
    Merged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub op: Oid,
    pub actor: Oid,
    pub time: i64,
    pub what: What,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pr {
    pub title: String,
    pub body: String,
    pub author: Option<Oid>,
    pub source: String,
    pub target: String,
    pub status: Status,
    /// Never empty once loaded.
    pub revisions: Vec<Revision>,
    pub comments: Vec<Comment>,
    pub reviews: Vec<Review>,
    pub merged: Option<Merge>,
    pub timeline: Vec<Event>,
}

/// Whether a pull request may be merged under its target's rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    pub rule: Option<Rule>,
    /// Approvals of the latest revision that count toward the rule.
    pub approvals: Vec<Oid>,
    /// Reviewers whose latest review requests changes.
    pub changes: Vec<Oid>,
}

impl Readiness {
    /// Approvals still needed.
    pub fn missing(&self) -> u32 {
        let required = self.rule.as_ref().map_or(0, |r| r.approvals);
        required.saturating_sub(u32::try_from(self.approvals.len()).unwrap_or(u32::MAX))
    }

    pub fn ready(&self) -> bool {
        self.missing() == 0 && self.changes.is_empty()
    }
}

impl Pr {
    pub fn latest(&self) -> &Revision {
        self.revisions
            .last()
            .expect("the root operation is revision 1")
    }

    pub fn created(&self) -> i64 {
        self.timeline.first().map_or(0, |e| e.time)
    }

    pub fn updated(&self) -> i64 {
        self.timeline.last().map_or(0, |e| e.time)
    }

    /// Each reviewer's latest review. A new review replaces the last,
    /// whichever revision either was on.
    pub fn verdicts(&self) -> BTreeMap<Oid, &Review> {
        self.reviews.iter().map(|r| (r.reviewer, r)).collect()
    }

    /// Who approved revision `revision` and hasn't reviewed since.
    pub fn approvers(&self, revision: usize) -> BTreeSet<Oid> {
        self.verdicts()
            .into_iter()
            .filter(|(_, r)| r.revision == revision && r.verdict == Verdict::Approve)
            .map(|(id, _)| id)
            .collect()
    }

    /// Checks the target branch's rule under the current policy. Approvals
    /// count from contributors and up, other than the pull request's author
    /// and the latest revision's, and from the rule's group if it names
    /// one. A request for changes blocks until its reviewer approves.
    pub fn readiness(&self, trust: &Trust) -> Readiness {
        let policy = trust.policy.as_ref().map(|(_, p)| p);
        let rule = policy.and_then(|p| p.rules.get(&self.target)).cloned();
        let member = |id: &Oid| match (&rule, policy) {
            (Some(Rule { group: Some(g), .. }), Some(p)) => {
                p.groups.get(g).is_some_and(|m| m.contains(id))
            }
            _ => true,
        };
        let latest = self.latest();
        let can_review = |id: &Oid| trust.role(*id) >= Some(Role::Contributor);
        let approvals = self
            .approvers(self.revisions.len() - 1)
            .into_iter()
            .filter(|id| Some(*id) != self.author && *id != latest.author)
            .filter(|id| can_review(id) && member(id))
            .collect();
        let changes = self
            .verdicts()
            .into_iter()
            .filter(|(id, r)| r.verdict == Verdict::Changes && can_review(id))
            .map(|(id, _)| id)
            .collect();
        Readiness {
            rule,
            approvals,
            changes,
        }
    }

    fn revision(&self, id: Oid) -> Result<usize, String> {
        self.revisions
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| format!("no revision {id}"))
    }

    /// A line comment's place, or `None` for a general comment.
    fn location(&self, p: &Value) -> Result<Option<Location>, String> {
        let Some(path) = payload::optional_string(p, "path")? else {
            if ["revision", "line", "side"]
                .iter()
                .any(|k| p.get(k).is_some())
            {
                return Err("a line comment needs a path".into());
            }
            return Ok(None);
        };
        if path.is_empty() || path.starts_with('/') {
            return Err(format!("{path:?} is not a path in the repository"));
        }
        let line = p["line"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n > 0)
            .ok_or("line is not a line number")?;
        Ok(Some(Location {
            revision: self.revision(payload::required_oid(p, "revision")?)?,
            path: path.to_owned(),
            line,
            side: payload::optional_string(p, "side")?.map_or(Ok(Side::New), str::parse)?,
        }))
    }
}

impl Model for Pr {
    const NAMESPACE: &'static str = "prs";

    fn apply(&mut self, op: &StoredOp, ctx: &ReplayContext) -> Result<(), String> {
        let actor = ctx.actor(op);
        actor.require(Role::Contributor)?;
        let who = actor
            .identity
            .ok_or("signed by a key that belongs to no identity")?;
        let author = self.author;
        let moderate = |verb: &str| {
            if Some(who) == author || actor.role >= Some(Role::Maintainer) {
                Ok(())
            } else {
                Err(format!("only the author or a maintainer may {verb} it"))
            }
        };
        let merged = self.status == Status::Merged;
        let unmerged = |verb: &str| {
            if merged {
                Err(format!("cannot {verb} a merged pull request"))
            } else {
                Ok(())
            }
        };
        let p = &op.op.payload;
        let time = time(ctx.repo, op.id);
        let what = match (op.parents.is_empty(), op.op.kind.as_str()) {
            (true, "pr.create") => {
                let title = title(payload::required_string(p, "title")?)?;
                let body = payload::optional_string(p, "body")?.unwrap_or_default();
                let (source, target) = (branch(p, "source")?, branch(p, "target")?);
                if source == target {
                    return Err("source and target are the same branch".into());
                }
                let (head, base) = (payload::required_oid(p, "head")?, payload::required_oid(p, "base")?);
                self.title = title;
                self.body = body.to_owned();
                self.source = source;
                self.target = target;
                self.author = Some(who);
                self.revisions.push(Revision {
                    id: op.id,
                    author: who,
                    time,
                    head,
                    base,
                    note: String::new(),
                });
                What::Opened
            }
            (true, kind) => return Err(format!("{kind} cannot open a pull request")),
            (false, "pr.edit") => {
                moderate("edit")?;
                let title = payload::optional_string(p, "title")?.map(title).transpose()?;
                let body = payload::optional_string(p, "body")?;
                if title.is_none() && body.is_none() {
                    return Err("nothing to edit".into());
                }
                if let Some(t) = title {
                    self.title = t;
                }
                if let Some(b) = body {
                    self.body = b.to_owned();
                }
                What::Edited
            }
            (false, "pr.revise") => {
                moderate("revise")?;
                unmerged("revise")?;
                let (head, base) = (payload::required_oid(p, "head")?, payload::required_oid(p, "base")?);
                let note = payload::optional_string(p, "note")?.unwrap_or_default();
                self.revisions.push(Revision {
                    id: op.id,
                    author: who,
                    time,
                    head,
                    base,
                    note: note.to_owned(),
                });
                What::Revised(self.revisions.len() - 1)
            }
            (false, "pr.comment") => {
                let body = text(payload::required_string(p, "body")?)?;
                let (location, reply_to) = match payload::optional_string(p, "reply_to")? {
                    None => (self.location(p)?, None),
                    Some(id) => {
                        if p.get("path").is_some() {
                            return Err("a reply is placed by its thread".into());
                        }
                        let id = payload::parse_oid(id)?;
                        let to = self
                            .comments
                            .iter()
                            .find(|c| c.id == id)
                            .ok_or_else(|| format!("no comment {id}"))?;
                        (to.location.clone(), Some(to.reply_to.unwrap_or(to.id)))
                    }
                };
                self.comments.push(Comment {
                    id: op.id,
                    author: who,
                    time,
                    body,
                    edited: false,
                    location,
                    reply_to,
                });
                What::Commented(self.comments.len() - 1)
            }
            (false, "pr.comment_edit") => {
                let id = payload::required_oid(p, "comment")?;
                let body = text(payload::required_string(p, "body")?)?;
                let comment = self
                    .comments
                    .iter_mut()
                    .find(|c| c.id == id)
                    .ok_or_else(|| format!("no comment {id}"))?;
                if comment.author != who {
                    return Err("only its author may edit a comment".into());
                }
                comment.body = body;
                comment.edited = true;
                return Ok(()); // not a timeline event
            }
            (false, "pr.review") => {
                if self.status != Status::Open {
                    return Err(format!("cannot review a {} pull request", self.status));
                }
                if Some(who) == author {
                    return Err("authors don't review their own pull requests".into());
                }
                let revision = self.revision(payload::required_oid(p, "revision")?)?;
                let verdict = payload::required_string(p, "verdict")?.parse()?;
                let body = payload::optional_string(p, "body")?.unwrap_or_default();
                self.reviews.push(Review {
                    id: op.id,
                    reviewer: who,
                    time,
                    revision,
                    verdict,
                    body: body.to_owned(),
                });
                What::Reviewed(self.reviews.len() - 1)
            }
            (false, "pr.status") => {
                let status: Status = payload::required_string(p, "status")?.parse()?;
                let verb = match status {
                    Status::Open => "reopen",
                    Status::Closed => "close",
                    Status::Merged => return Err("pr.merge merges".into()),
                };
                unmerged(verb)?;
                moderate(verb)?;
                self.status = status;
                What::Status(status)
            }
            (false, "pr.merge") => {
                actor.require(Role::Maintainer)?;
                unmerged("merge")?;
                let revision = self.revision(payload::required_oid(p, "revision")?)?;
                let commit = payload::required_oid(p, "commit")?;
                self.merged = Some(Merge {
                    by: who,
                    time,
                    revision,
                    commit,
                    approvals: self.approvers(revision),
                });
                self.status = Status::Merged;
                What::Merged
            }
            (false, kind) => return Err(format!("unknown operation {kind}")),
        };
        self.timeline.push(Event {
            op: op.id,
            actor: who,
            time,
            what,
        });
        Ok(())
    }
}

fn branch(p: &Value, key: &str) -> Result<String, String> {
    let name = payload::required_string(p, key)?;
    if !git2::Reference::is_valid_name(&format!("refs/heads/{name}")) {
        return Err(format!("{name:?} is not a branch name"));
    }
    Ok(name.to_owned())
}

/// Where a line comment goes.
#[derive(Debug, Clone, Copy)]
pub enum Place<'a> {
    General,
    Line {
        /// The revision's operation id.
        revision: Oid,
        path: &'a str,
        line: u32,
        side: Side,
    },
    /// Into the thread of this comment.
    Reply(Oid),
}

/// Keeps `commits` reachable under `refs/fullgit/code/`, so `fullgit sync`
/// carries them.
pub fn keep_code(repo: &Repository, commits: &[Oid]) -> Result<()> {
    for c in commits {
        repo.find_commit(*c)?;
        repo.reference(&refs::code_refname(*c), *c, true, "fullgit: code")?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn create(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    title: &str,
    body: &str,
    source: &str,
    target: &str,
    head: Oid,
    base: Oid,
) -> Result<Oid> {
    keep_code(repo, &[head, base])?;
    model::create::<Pr>(
        repo,
        trust,
        signer,
        "pr.create",
        json!({
            "title": title, "body": body, "source": source, "target": target,
            "head": head.to_string(), "base": base.to_string(),
        }),
    )
}

pub fn edit(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    id: Oid,
    title: Option<&str>,
    body: Option<&str>,
) -> Result<Oid> {
    let mut p = json!({});
    if let Some(t) = title {
        p["title"] = t.into();
    }
    if let Some(b) = body {
        p["body"] = b.into();
    }
    model::update::<Pr>(repo, trust, id, signer, "pr.edit", p)
}

pub fn revise(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    id: Oid,
    head: Oid,
    base: Oid,
    note: &str,
) -> Result<Oid> {
    keep_code(repo, &[head, base])?;
    model::update::<Pr>(
        repo,
        trust,
        id,
        signer,
        "pr.revise",
        json!({ "head": head.to_string(), "base": base.to_string(), "note": note }),
    )
}

pub fn comment(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    id: Oid,
    body: &str,
    place: Place,
) -> Result<Oid> {
    let mut p = json!({ "body": body });
    match place {
        Place::General => {}
        Place::Line {
            revision,
            path,
            line,
            side,
        } => {
            p["revision"] = revision.to_string().into();
            p["path"] = path.into();
            p["line"] = line.into();
            p["side"] = side.as_str().into();
        }
        Place::Reply(to) => p["reply_to"] = to.to_string().into(),
    }
    model::update::<Pr>(repo, trust, id, signer, "pr.comment", p)
}

pub fn edit_comment(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    id: Oid,
    comment: Oid,
    body: &str,
) -> Result<Oid> {
    model::update::<Pr>(
        repo,
        trust,
        id,
        signer,
        "pr.comment_edit",
        json!({ "comment": comment.to_string(), "body": body }),
    )
}

pub fn review(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    id: Oid,
    revision: Oid,
    verdict: Verdict,
    body: &str,
) -> Result<Oid> {
    model::update::<Pr>(
        repo,
        trust,
        id,
        signer,
        "pr.review",
        json!({ "revision": revision.to_string(), "verdict": verdict.as_str(), "body": body }),
    )
}

pub fn set_status(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    id: Oid,
    status: Status,
) -> Result<Oid> {
    model::update::<Pr>(
        repo,
        trust,
        id,
        signer,
        "pr.status",
        json!({ "status": status.as_str() }),
    )
}

/// Records that `commit` on the target branch merged `revision`.
pub fn record_merge(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    id: Oid,
    revision: Oid,
    commit: Oid,
) -> Result<Oid> {
    model::update::<Pr>(
        repo,
        trust,
        id,
        signer,
        "pr.merge",
        json!({ "revision": revision.to_string(), "commit": commit.to_string() }),
    )
}

pub fn load(repo: &Repository, trust: &Trust, id: Oid) -> Result<Loaded<Pr>> {
    model::load::<Pr>(repo, trust, id)
}

/// Every local pull request, or why it failed to load.
pub fn all(repo: &Repository, trust: &Trust) -> Result<Vec<(Oid, Result<Loaded<Pr>>)>> {
    model::needs_policy::<Pr>(trust)?;
    Ok(model::list::<Pr>(repo)?
        .into_iter()
        .map(|id| (id, load(repo, trust, id)))
        .collect())
}

/// Resolves a full id or a unique prefix.
pub fn resolve(repo: &Repository, prefix: &str) -> Result<Oid> {
    model::resolve::<Pr>(repo, prefix).map_err(|e| match e {
        Error::NotFound(p) => Error::NotFound(format!("pull request {p}")),
        e => e,
    })
}

/// The outcome of [`merge_commit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Merging {
    Clean(Oid),
    /// Paths that conflict.
    Conflicts(Vec<String>),
}

/// Writes a merge commit of `head` into `into`, without touching the
/// working tree. git writes it, so `commit.gpgSign` applies.
pub fn merge_commit(repo: &Repository, into: Oid, head: Oid, message: &str) -> Result<Merging> {
    let (into, head) = (into.to_string(), head.to_string());
    let out = git_output(
        repo,
        &[
            "merge-tree",
            "--write-tree",
            "--name-only",
            "--no-messages",
            &into,
            &head,
        ],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines();
    let tree = lines.next().unwrap_or_default().trim().to_owned();
    match out.status.code() {
        Some(0) => {}
        Some(1) => {
            let mut paths: Vec<String> =
                lines.filter(|l| !l.is_empty()).map(str::to_owned).collect();
            paths.dedup();
            return Ok(Merging::Conflicts(paths));
        }
        _ => return Err(git_error("merge-tree", &out)),
    }
    let out = git_output(
        repo,
        &[
            "commit-tree",
            &tree,
            "-p",
            &into,
            "-p",
            &head,
            "-m",
            message,
        ],
    )?;
    if !out.status.success() {
        return Err(git_error("commit-tree", &out));
    }
    let id = String::from_utf8_lossy(&out.stdout);
    Ok(Merging::Clean(Oid::from_str(id.trim())?))
}

/// Fetches `branch` from `remote` into its remote-tracking ref, and returns
/// its tip.
pub fn fetch_branch(repo: &Repository, remote: &str, branch: &str) -> Result<Oid> {
    let tracking = format!("refs/remotes/{remote}/{branch}");
    crate::sync::git(
        repo,
        &[
            "fetch",
            "--quiet",
            remote,
            &format!("+refs/heads/{branch}:{tracking}"),
        ],
    )?;
    Ok(repo.refname_to_id(&tracking)?)
}

/// What [`verify`] found on a protected branch.
#[derive(Debug, Default)]
pub struct Verified {
    /// First-parent commits since the branch was protected.
    pub checked: usize,
    /// Those no merged pull request records, newest first.
    pub unrecorded: Vec<Oid>,
}

/// Checks that each commit on `branch`'s first-parent history, from `tip`
/// back to where its rule began, is the recorded merge of a pull request. A
/// dumb host can't refuse direct pushes; this detects them.
pub fn verify(repo: &Repository, trust: &Trust, branch: &str, tip: Oid) -> Result<Verified> {
    let rule = trust
        .policy
        .as_ref()
        .and_then(|(_, p)| p.rules.get(branch))
        .ok_or_else(|| Error::Policy(format!("{branch} is not protected")))?;
    let recorded: BTreeSet<Oid> = all(repo, trust)?
        .into_iter()
        .filter_map(|(_, loaded)| {
            let p = loaded.ok()?.model;
            (p.target == branch).then_some(p.merged?.commit)
        })
        .collect();
    let mut walk = repo.revwalk()?;
    walk.push(tip)?;
    walk.simplify_first_parent()?;
    if let Some(since) = rule.since {
        walk.hide(since)?;
    }
    let mut v = Verified::default();
    for id in walk {
        let id = id?;
        v.checked += 1;
        if !recorded.contains(&id) {
            v.unrecorded.push(id);
        }
    }
    Ok(v)
}
