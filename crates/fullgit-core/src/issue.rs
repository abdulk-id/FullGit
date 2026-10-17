//! Issues, at `refs/fullgit/issues/<id>`.
//!
//! Ops: `issue.create {title, body, labels?}`, `issue.edit {title?, body?}`,
//! `issue.comment {body}`, `issue.comment_edit {comment, body}`,
//! `issue.label {add?, remove?}`, `issue.assign {add?, remove?}` (identity
//! ids), `issue.status {status}`.
//!
//! Contributors open issues and comment. The author or a maintainer edits,
//! labels, assigns, closes and reopens. A comment is edited by its author
//! only. Operations that change nothing (closing a closed issue, adding a
//! label it has) are accepted: concurrent ones often overlap.

use std::collections::BTreeSet;

use git2::{Oid, Repository};
use serde_json::{Value, json};

use crate::model::{self, Ctx, Loaded, Model};
use crate::op::StoredOp;
use crate::payload;
use crate::sign::Signer;
use crate::trust::{Role, Trust};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Status {
    #[default]
    Open,
    Closed,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::Closed => "closed",
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
            _ => Err(format!("unknown status {s}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    /// The `issue.comment` operation.
    pub id: Oid,
    pub author: Oid,
    pub time: i64,
    pub body: String,
    pub edited: bool,
}

/// Something that happened to an issue, for its timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum What {
    Opened,
    Edited,
    /// Index into [`Issue::comments`].
    Commented(usize),
    Labeled {
        add: Vec<String>,
        remove: Vec<String>,
    },
    Assigned {
        add: Vec<Oid>,
        remove: Vec<Oid>,
    },
    Status(Status),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub op: Oid,
    pub actor: Oid,
    pub time: i64,
    pub what: What,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Issue {
    pub title: String,
    pub body: String,
    /// The identity that opened it; set by the root operation.
    pub author: Option<Oid>,
    pub status: Status,
    pub labels: BTreeSet<String>,
    pub assignees: BTreeSet<Oid>,
    pub comments: Vec<Comment>,
    pub timeline: Vec<Event>,
}

impl Issue {
    pub fn created(&self) -> i64 {
        self.timeline.first().map_or(0, |e| e.time)
    }

    pub fn updated(&self) -> i64 {
        self.timeline.last().map_or(0, |e| e.time)
    }
}

impl Model for Issue {
    const NAMESPACE: &'static str = "issues";

    fn apply(&mut self, op: &StoredOp, ctx: &Ctx) -> Result<(), String> {
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
        let p = &op.op.payload;
        let what = match (op.parents.is_empty(), op.op.kind.as_str()) {
            (true, "issue.create") => {
                let title = title(payload::str(p, "title")?)?;
                let body = payload::opt_str(p, "body")?.unwrap_or_default();
                let labels = labels(p, "labels")?;
                self.title = title;
                self.body = body.to_owned();
                self.labels = labels.into_iter().collect();
                self.author = Some(who);
                What::Opened
            }
            (true, kind) => return Err(format!("{kind} cannot open an issue")),
            (false, "issue.edit") => {
                moderate("edit")?;
                let title = payload::opt_str(p, "title")?.map(title).transpose()?;
                let body = payload::opt_str(p, "body")?;
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
            (false, "issue.comment") => {
                let body = text(payload::str(p, "body")?)?;
                self.comments.push(Comment {
                    id: op.id,
                    author: who,
                    time: time(ctx.repo, op.id),
                    body,
                    edited: false,
                });
                What::Commented(self.comments.len() - 1)
            }
            (false, "issue.comment_edit") => {
                let id = payload::oid(p, "comment")?;
                let body = text(payload::str(p, "body")?)?;
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
            (false, "issue.label") => {
                moderate("label")?;
                let (add, remove) = (labels(p, "add")?, labels(p, "remove")?);
                for l in &remove {
                    self.labels.remove(l);
                }
                self.labels.extend(add.iter().cloned());
                What::Labeled { add, remove }
            }
            (false, "issue.assign") => {
                moderate("assign")?;
                let (add, remove) = (ids(p, "add")?, ids(p, "remove")?);
                for id in &remove {
                    self.assignees.remove(id);
                }
                self.assignees.extend(add.iter().copied());
                What::Assigned { add, remove }
            }
            (false, "issue.status") => {
                let status: Status = payload::str(p, "status")?.parse()?;
                moderate(if status == Status::Closed {
                    "close"
                } else {
                    "reopen"
                })?;
                self.status = status;
                What::Status(status)
            }
            (false, kind) => return Err(format!("unknown operation {kind}")),
        };
        self.timeline.push(Event {
            op: op.id,
            actor: who,
            time: time(ctx.repo, op.id),
            what,
        });
        Ok(())
    }
}

/// An operation's commit time, from its author's clock.
pub(crate) fn time(repo: &Repository, op: Oid) -> i64 {
    repo.find_commit(op).map_or(0, |c| c.time().seconds())
}

pub(crate) fn title(s: &str) -> Result<String, String> {
    let t = s.trim();
    if t.is_empty() || t.contains('\n') {
        return Err("a title is one non-empty line".into());
    }
    Ok(t.to_owned())
}

pub(crate) fn text(s: &str) -> Result<String, String> {
    if s.trim().is_empty() {
        return Err("empty text".into());
    }
    Ok(s.to_owned())
}

pub fn valid_label(l: &str) -> Result<(), String> {
    if l.is_empty() || l.len() > 50 || l.chars().any(|c| c.is_whitespace() || c == ',') {
        return Err(format!(
            "{l:?}: labels are 1-50 characters, without spaces or commas"
        ));
    }
    Ok(())
}

/// A list of labels; absent means none.
fn labels(p: &Value, key: &str) -> Result<Vec<String>, String> {
    strings(p, key)?
        .into_iter()
        .map(|l| valid_label(&l).map(|()| l))
        .collect()
}

/// A list of identity ids; absent means none.
fn ids(p: &Value, key: &str) -> Result<Vec<Oid>, String> {
    strings(p, key)?
        .iter()
        .map(|s| payload::parse_oid(s))
        .collect()
}

fn strings(p: &Value, key: &str) -> Result<Vec<String>, String> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{key} must hold strings"))
            })
            .collect(),
        Some(_) => Err(format!("{key} is not a list")),
    }
}

fn to_strings(ids: &[Oid]) -> Vec<String> {
    ids.iter().map(Oid::to_string).collect()
}

pub fn create(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    title: &str,
    body: &str,
    labels: &[String],
) -> Result<Oid> {
    model::create::<Issue>(
        repo,
        trust,
        signer,
        "issue.create",
        json!({ "title": title, "body": body, "labels": labels }),
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
    model::update::<Issue>(repo, trust, id, signer, "issue.edit", p)
}

pub fn comment(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    id: Oid,
    body: &str,
) -> Result<Oid> {
    model::update::<Issue>(
        repo,
        trust,
        id,
        signer,
        "issue.comment",
        json!({ "body": body }),
    )
}

pub fn edit_comment(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    id: Oid,
    comment: Oid,
    body: &str,
) -> Result<Oid> {
    model::update::<Issue>(
        repo,
        trust,
        id,
        signer,
        "issue.comment_edit",
        json!({ "comment": comment.to_string(), "body": body }),
    )
}

pub fn label(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    id: Oid,
    add: &[String],
    remove: &[String],
) -> Result<Oid> {
    model::update::<Issue>(
        repo,
        trust,
        id,
        signer,
        "issue.label",
        json!({ "add": add, "remove": remove }),
    )
}

pub fn assign(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    id: Oid,
    add: &[Oid],
    remove: &[Oid],
) -> Result<Oid> {
    model::update::<Issue>(
        repo,
        trust,
        id,
        signer,
        "issue.assign",
        json!({ "add": to_strings(add), "remove": to_strings(remove) }),
    )
}

pub fn set_status(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    id: Oid,
    status: Status,
) -> Result<Oid> {
    model::update::<Issue>(
        repo,
        trust,
        id,
        signer,
        "issue.status",
        json!({ "status": status.as_str() }),
    )
}

pub fn load(repo: &Repository, trust: &Trust, id: Oid) -> Result<Loaded<Issue>> {
    model::load::<Issue>(repo, trust, id)
}

/// Every local issue, or why it failed to load (e.g. its opening operation
/// was rejected).
pub fn all(repo: &Repository, trust: &Trust) -> Result<Vec<(Oid, Result<Loaded<Issue>>)>> {
    Ok(model::list::<Issue>(repo)?
        .into_iter()
        .map(|id| (id, load(repo, trust, id)))
        .collect())
}

/// Resolves a full id or a unique prefix.
pub fn resolve(repo: &Repository, prefix: &str) -> Result<Oid> {
    model::resolve::<Issue>(repo, prefix).map_err(|e| match e {
        Error::NotFound(p) => Error::NotFound(format!("issue {p}")),
        e => e,
    })
}
