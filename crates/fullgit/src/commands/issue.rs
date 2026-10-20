//! `fullgit issue`: issues.

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use fullgit_core::Trust;
use fullgit_core::issue::{self, Issue, Status, What};
use fullgit_core::model::{self, Abbrev};
use git2::{Oid, Repository};

use crate::{current_user_with_signer, date, resolve_identity, short_oid};

/// Issues are named by a prefix of their id, as `fullgit issue list` shows.
#[derive(Subcommand)]
pub enum IssueCmd {
    /// Open an issue. Without --title, opens your editor.
    New {
        #[arg(long, short)]
        title: Option<String>,
        /// The description.
        #[arg(long, short = 'm')]
        body: Option<String>,
        /// A label the policy lists (`fullgit policy show`).
        #[arg(long = "label", short)]
        labels: Vec<String>,
    },
    /// List issues, open ones by default, most recently updated first.
    List {
        #[arg(long)]
        closed: bool,
        #[arg(long, conflicts_with = "closed")]
        all: bool,
        /// Only issues with all these labels.
        #[arg(long = "label", short)]
        labels: Vec<String>,
        /// Only issues assigned to someone: `me`, an email or an id prefix.
        #[arg(long)]
        assignee: Option<String>,
        #[arg(long)]
        author: Option<String>,
    },
    /// Show an issue with its comments and history.
    Show { id: String },
    /// Comment on an issue. Without -m, opens your editor.
    Comment {
        id: String,
        #[arg(long, short = 'm')]
        body: Option<String>,
    },
    /// Change an issue's title or description. Without either, opens your
    /// editor on both.
    Edit {
        id: String,
        #[arg(long, short)]
        title: Option<String>,
        #[arg(long, short = 'm')]
        body: Option<String>,
    },
    /// Edit one of your comments. Without -m, opens your editor.
    EditComment {
        id: String,
        /// The comment's id, as `fullgit issue show` prints it.
        comment: String,
        #[arg(long, short = 'm')]
        body: Option<String>,
    },
    /// Close an issue, optionally with a comment.
    Close {
        id: String,
        #[arg(long, short = 'm')]
        comment: Option<String>,
    },
    /// Reopen an issue, optionally with a comment.
    Reopen {
        id: String,
        #[arg(long, short = 'm')]
        comment: Option<String>,
    },
    /// Add labels the policy lists (`fullgit policy show`), or remove them
    /// with --remove.
    Label {
        id: String,
        labels: Vec<String>,
        #[arg(long)]
        remove: Vec<String>,
    },
    /// Assign people (`me`, an email or an id prefix), or unassign them
    /// with --remove.
    Assign {
        id: String,
        who: Vec<String>,
        #[arg(long)]
        remove: Vec<String>,
    },
}

/// Runs a `fullgit issue` subcommand.
pub fn run(repo: &Repository, cmd: IssueCmd) -> Result<()> {
    let trust = Trust::load(repo)?;
    match cmd {
        IssueCmd::New {
            title,
            body,
            labels,
        } => {
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let (title, body) = match title {
                Some(t) => (t, body.unwrap_or_default()),
                None => {
                    let text = editor(
                        repo,
                        &body.unwrap_or_default(),
                        "The first line is the title, the rest the description.",
                    )?;
                    split_title(&text)?
                }
            };
            let id = issue::create(repo, &trust, &signer, &title, &body, &labels)?;
            println!("opened issue {}; `fullgit sync` shares it", name(repo, id)?);
        }
        IssueCmd::List {
            closed,
            all,
            labels,
            assignee,
            author,
        } => {
            let assignee: Option<Oid> = assignee
                .map(|w| resolve_identity(repo, &trust, &w))
                .transpose()?;
            let author: Option<Oid> = author
                .map(|w| resolve_identity(repo, &trust, &w))
                .transpose()?;
            let names = model::abbrev::<Issue>(repo)?;
            let mut shown = Vec::new();
            for (id, loaded) in issue::all(repo, &trust)? {
                let i = match loaded {
                    Ok(l) => l.model,
                    Err(e) => {
                        eprintln!("warning: issue {} is invalid: {e}", names.of(id));
                        continue;
                    }
                };
                let status_ok = all || (i.status == Status::Closed) == closed;
                let labels_ok = labels.iter().all(|l| i.labels.contains(l));
                let assignee_ok = assignee.is_none_or(|a| i.assignees.contains(&a));
                let author_ok = author.is_none_or(|a| i.author == Some(a));
                if status_ok && labels_ok && assignee_ok && author_ok {
                    shown.push((id, i));
                }
            }
            shown.sort_by_key(|(id, i)| (std::cmp::Reverse(i.updated()), *id));
            for (id, i) in &shown {
                let labels = if i.labels.is_empty() {
                    String::new()
                } else {
                    let l: Vec<_> = i.labels.iter().map(String::as_str).collect();
                    format!("  [{}]", l.join(", "))
                };
                println!(
                    "{}  {:<6}  {}{labels}  ({})",
                    names.of(*id),
                    i.status,
                    i.title,
                    who(&trust, i.author)
                );
            }
            if shown.is_empty() {
                println!("no issues");
            }
        }
        IssueCmd::Show { id } => {
            let id = issue::resolve(repo, &id)?;
            let loaded = issue::load(repo, &trust, id)?;
            show(&trust, &name(repo, id)?, &loaded.model);
            if !loaded.rejected.is_empty() {
                eprintln!();
                eprintln!("ignored {} operation(s):", loaded.rejected.len());
                for r in &loaded.rejected {
                    eprintln!("  {}: {}", short_oid(r.op), r.reason);
                }
            }
        }
        IssueCmd::Comment { id, body } => {
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let id = issue::resolve(repo, &id)?;
            let body = match body {
                Some(b) => b,
                None => editor(repo, "", "Your comment.")?,
            };
            issue::comment(repo, &trust, &signer, id, &body)?;
        }
        IssueCmd::Edit { id, title, body } => {
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let id = issue::resolve(repo, &id)?;
            let (title, body) = match (title, body) {
                (None, None) => {
                    let current = issue::load(repo, &trust, id)?.model;
                    let text = editor(
                        repo,
                        &format!("{}\n\n{}", current.title, current.body),
                        "The first line is the title, the rest the description.",
                    )?;
                    let (t, b) = split_title(&text)?;
                    (
                        (t != current.title).then_some(t),
                        (b != current.body).then_some(b),
                    )
                }
                other => other,
            };
            if title.is_none() && body.is_none() {
                println!("nothing changed");
                return Ok(());
            }
            issue::edit(repo, &trust, &signer, id, title.as_deref(), body.as_deref())?;
        }
        IssueCmd::EditComment { id, comment, body } => {
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let id = issue::resolve(repo, &id)?;
            let current = issue::load(repo, &trust, id)?.model;
            let found: Vec<_> = current
                .comments
                .iter()
                .filter(|c| c.id.to_string().starts_with(&comment))
                .collect();
            let c = match found.as_slice() {
                [c] => *c,
                [] => bail!("no comment {comment} on this issue"),
                _ => bail!("{comment} matches several comments"),
            };
            let body = match body {
                Some(b) => b,
                None => editor(repo, &c.body, "Your comment.")?,
            };
            issue::edit_comment(repo, &trust, &signer, id, c.id, &body)?;
        }
        IssueCmd::Close { id, comment } => {
            set_status(repo, &trust, &id, Status::Closed, comment)?;
        }
        IssueCmd::Reopen { id, comment } => {
            set_status(repo, &trust, &id, Status::Open, comment)?;
        }
        IssueCmd::Label { id, labels, remove } => {
            if labels.is_empty() && remove.is_empty() {
                bail!("name labels to add, or --remove them");
            }
            for l in labels.iter().chain(&remove) {
                issue::valid_label(l).map_err(anyhow::Error::msg)?;
            }
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let id = issue::resolve(repo, &id)?;
            issue::label(repo, &trust, &signer, id, &labels, &remove)?;
        }
        IssueCmd::Assign { id, who, remove } => {
            if who.is_empty() && remove.is_empty() {
                bail!("name people to assign, or --remove them");
            }
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let id = issue::resolve(repo, &id)?;
            let add = who
                .iter()
                .map(|w| resolve_identity(repo, &trust, w))
                .collect::<Result<Vec<_>>>()?;
            let remove = remove
                .iter()
                .map(|w| resolve_identity(repo, &trust, w))
                .collect::<Result<Vec<_>>>()?;
            issue::assign(repo, &trust, &signer, id, &add, &remove)?;
        }
    }
    Ok(())
}

fn set_status(
    repo: &Repository,
    trust: &Trust,
    id: &str,
    status: Status,
    comment: Option<String>,
) -> Result<()> {
    let (signer, _) = current_user_with_signer(repo, trust)?;
    let id = issue::resolve(repo, id)?;
    if issue::load(repo, trust, id)?.model.status == status {
        bail!("issue {} is already {status}", name(repo, id)?);
    }
    if let Some(body) = comment {
        issue::comment(repo, trust, &signer, id, &body)?;
    }
    issue::set_status(repo, trust, &signer, id, status)?;
    println!("issue {} is {status}", name(repo, id)?);
    Ok(())
}

fn show(trust: &Trust, name: &str, i: &Issue) {
    let comments = Abbrev::new(i.comments.iter().map(|c| c.id));
    println!("{}", i.title);
    println!(
        "{} · {} · opened by {} on {}",
        i.status,
        name,
        who(trust, i.author),
        date(i.created())
    );
    if !i.labels.is_empty() {
        let l: Vec<_> = i.labels.iter().map(String::as_str).collect();
        println!("labels:    {}", l.join(", "));
    }
    if !i.assignees.is_empty() {
        let a: Vec<_> = i.assignees.iter().map(|a| who(trust, Some(*a))).collect();
        println!("assignees: {}", a.join(", "));
    }
    if !i.body.trim().is_empty() {
        println!();
        print_indented(&i.body);
    }
    for e in &i.timeline {
        let actor = who(trust, Some(e.actor));
        let when = date(e.time);
        match &e.what {
            What::Opened => {}
            What::Edited => println!("\n· {actor} edited the description, {when}"),
            What::Commented(n) => {
                let c = &i.comments[*n];
                let edited = if c.edited { ", edited" } else { "" };
                println!(
                    "\n── {actor} commented, {when} ({}{edited})",
                    comments.of(c.id)
                );
                print_indented(&c.body);
            }
            What::Labeled { add, remove } => {
                let changes: Vec<_> = add
                    .iter()
                    .map(|l| format!("+{l}"))
                    .chain(remove.iter().map(|l| format!("-{l}")))
                    .collect();
                println!("\n· {actor} changed labels: {}, {when}", changes.join(" "));
            }
            What::Assigned { add, remove } => {
                let names = |ids: &[Oid]| {
                    ids.iter()
                        .map(|a| who(trust, Some(*a)))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                if !add.is_empty() {
                    println!("\n· {actor} assigned {}, {when}", names(add));
                }
                if !remove.is_empty() {
                    println!("\n· {actor} unassigned {}, {when}", names(remove));
                }
            }
            What::Status(Status::Closed) => println!("\n· {actor} closed this, {when}"),
            What::Status(Status::Open) => println!("\n· {actor} reopened this, {when}"),
        }
    }
}

pub(crate) fn print_indented(text: &str) {
    for line in text.trim_end().lines() {
        println!("    {line}");
    }
}

/// A person's name, or a short id if their identity isn't known here.
pub(crate) fn who(trust: &Trust, id: Option<Oid>) -> String {
    match id {
        Some(id) => trust
            .identities
            .get(&id)
            .map_or_else(|| short_oid(id), |i| i.name.clone()),
        None => "unknown".into(),
    }
}

/// How an issue is named: the shortest unique start of its id.
pub(crate) fn name(repo: &Repository, id: Oid) -> Result<String> {
    Ok(model::abbrev::<Issue>(repo)?.of(id))
}

pub(crate) fn short_id(id: Oid) -> String {
    id.to_string()[..8].to_owned()
}

/// Splits editor text into a title (the first line) and a description.
pub(crate) fn split_title(text: &str) -> Result<(String, String)> {
    let text = text.trim();
    let (title, body) = text.split_once('\n').unwrap_or((text, ""));
    if title.trim().is_empty() {
        bail!("no title; aborted");
    }
    Ok((title.trim().to_owned(), body.trim().to_owned()))
}

/// Lets the user write text in git's editor. Lines starting with `#` are
/// dropped; empty text aborts.
pub(crate) fn editor(repo: &Repository, initial: &str, help: &str) -> Result<String> {
    let out = std::process::Command::new("git")
        .arg("--git-dir")
        .arg(repo.path())
        .args(["var", "GIT_EDITOR"])
        .output()?;
    if !out.status.success() {
        bail!("no editor configured; pass the text on the command line");
    }
    let editor = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let dir = repo.path().join("fullgit");
    std::fs::create_dir_all(&dir)?;
    let file = dir.join("EDITMSG");
    std::fs::write(
        &file,
        format!("{initial}\n\n# {help}\n# Lines starting with # are ignored; empty text aborts.\n"),
    )?;
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$@\""))
        .arg(&editor)
        .arg(&file)
        .status()
        .context("running the editor")?;
    if !status.success() {
        bail!("the editor failed; aborted");
    }
    let text = std::fs::read_to_string(&file)?;
    let text: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
    let text = text.join("\n").trim().to_owned();
    if text.is_empty() {
        bail!("empty text; aborted");
    }
    Ok(text)
}
