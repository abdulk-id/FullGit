//! `fullgit pr`: pull requests.

use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Subcommand};
use fullgit_core::model::{self, Abbrev};
use fullgit_core::pr::{self, Location, Merging, Place, Pr, Readiness, Revision, Side, Status};
use fullgit_core::pr::{Verdict, What};
use fullgit_core::{Role, Signer, Trust, sync};
use git2::{Oid, Repository};

use crate::commands::issue::{editor, print_indented, short_id, split_title, who};
use crate::{
    current_user_with_signer, date, identity_of, resolve_identity, short_oid,
    signer_from_git_config,
};

/// Pull requests are named by a prefix of their id, as `fullgit pr list`
/// shows, and revisions by number: 1 is the first.
#[derive(Subcommand)]
pub enum PrCmd {
    /// Open a pull request from a branch. Without --title, opens your
    /// editor.
    New {
        #[arg(long, short)]
        title: Option<String>,
        /// The description.
        #[arg(long, short = 'm')]
        body: Option<String>,
        /// The branch to merge; the current one by default.
        #[arg(long)]
        source: Option<String>,
        /// The branch to merge into; the remote's default branch by default.
        #[arg(long)]
        target: Option<String>,
        /// Whose copy of the target to compare against.
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    /// List pull requests, open ones by default, most recently updated
    /// first.
    List {
        #[arg(long)]
        closed: bool,
        #[arg(long)]
        merged: bool,
        #[arg(long, conflicts_with_all = ["closed", "merged"])]
        all: bool,
        /// `me`, an email or an id prefix.
        #[arg(long)]
        author: Option<String>,
    },
    /// Show a pull request: revisions, comments, reviews, and whether it
    /// may be merged.
    Show { id: String },
    /// Show a revision's changes, or what changed between revisions.
    Diff {
        id: String,
        /// The latest by default.
        #[arg(long, short)]
        revision: Option<usize>,
        /// What changed since this revision, e.g. the one you last reviewed.
        #[arg(long)]
        since: Option<usize>,
    },
    /// Switch to a branch at the pull request's latest revision.
    Checkout {
        id: String,
        /// The source branch's name by default.
        #[arg(long)]
        branch: Option<String>,
    },
    /// Record the source branch's new commits as the next revision.
    /// Without an id, revises your open pull request from the current
    /// branch.
    Revise {
        id: Option<String>,
        /// What changed, for reviewers.
        #[arg(long, short = 'm')]
        note: Option<String>,
        /// A commit other than the source branch's tip.
        #[arg(long)]
        head: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    /// Comment on a pull request, or on a line with --file and --line.
    /// Without -m, opens your editor.
    Comment {
        id: String,
        #[arg(long, short = 'm')]
        body: Option<String>,
        /// A path as `fullgit pr diff` shows it.
        #[arg(long, requires = "line", conflicts_with = "reply")]
        file: Option<String>,
        #[arg(long, requires = "file")]
        line: Option<u32>,
        /// The line number is in the old version of the file.
        #[arg(long, requires = "file")]
        old: bool,
        /// The latest by default.
        #[arg(long, short, requires = "file")]
        revision: Option<usize>,
        /// Reply in a comment's thread.
        #[arg(long)]
        reply: Option<String>,
    },
    /// Edit one of your comments. Without -m, opens your editor.
    EditComment {
        id: String,
        comment: String,
        #[arg(long, short = 'm')]
        body: Option<String>,
    },
    /// Change the title or description. Without either, opens your editor.
    Edit {
        id: String,
        #[arg(long, short)]
        title: Option<String>,
        #[arg(long, short = 'm')]
        body: Option<String>,
    },
    /// Approve the latest revision, or request changes.
    #[command(group(ArgGroup::new("verdict").required(true).args(["approve", "request_changes"])))]
    Review {
        id: String,
        #[arg(long)]
        approve: bool,
        #[arg(long)]
        request_changes: bool,
        /// Without it, requesting changes opens your editor.
        #[arg(long, short = 'm')]
        body: Option<String>,
    },
    /// Close without merging, optionally with a comment.
    Close {
        id: String,
        #[arg(long, short = 'm')]
        comment: Option<String>,
    },
    /// Reopen, optionally with a comment.
    Reopen {
        id: String,
        #[arg(long, short = 'm')]
        comment: Option<String>,
    },
    /// Merge the latest revision into the target branch on the remote,
    /// if the branch's rule allows it. Syncs first and after.
    Merge {
        id: String,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
}

/// Runs a `fullgit pr` subcommand.
pub fn run(repo: &Repository, cmd: PrCmd) -> Result<()> {
    if let PrCmd::Merge { id, remote } = cmd {
        return merge(repo, &id, &remote);
    }
    let trust = Trust::load(repo)?;
    match cmd {
        PrCmd::New {
            title,
            body,
            source,
            target,
            remote,
        } => {
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let source = match source {
                Some(s) => s,
                None => current_branch(repo).context("not on a branch; pass --source")?,
            };
            let target = match target {
                Some(t) => t,
                None => default_branch(repo, &remote)?,
            };
            let (head, base, commits) = range(repo, &remote, &source, &target)?;
            let (title, body) = match title {
                Some(t) => (t, body.unwrap_or_default()),
                None => {
                    let initial = match body {
                        Some(b) => b,
                        None if commits == 1 => {
                            let c = repo.find_commit(head)?;
                            c.message().unwrap_or_default().trim().to_owned()
                        }
                        None => String::new(),
                    };
                    let help = "The first line is the title, the rest the description.";
                    split_title(&editor(repo, &initial, help)?)?
                }
            };
            let id = pr::create(
                repo, &trust, &signer, &title, &body, &source, &target, head, base,
            )?;
            println!(
                "opened pull request {} ({source} → {target}, {commits} commit(s)); \
                 `fullgit sync` shares it",
                name(repo, id)?
            );
        }
        PrCmd::List {
            closed,
            merged,
            all,
            author,
        } => {
            let author = author
                .map(|w| resolve_identity(repo, &trust, &w))
                .transpose()?;
            let names = model::abbrev::<Pr>(repo)?;
            let mut shown = Vec::new();
            for (id, loaded) in pr::all(repo, &trust)? {
                let p = match loaded {
                    Ok(l) => l.model,
                    Err(e) => {
                        eprintln!("warning: pull request {} is invalid: {e}", names.of(id));
                        continue;
                    }
                };
                let status_ok = all
                    || match p.status {
                        Status::Open => !closed && !merged,
                        Status::Closed => closed,
                        Status::Merged => merged,
                    };
                if status_ok && author.is_none_or(|a| p.author == Some(a)) {
                    shown.push((id, p));
                }
            }
            shown.sort_by_key(|(id, p)| (std::cmp::Reverse(p.updated()), *id));
            for (id, p) in &shown {
                let state = match p.status {
                    Status::Open => {
                        let r = p.readiness(&trust);
                        if !r.changes.is_empty() {
                            ", changes requested".to_owned()
                        } else if r.missing() > 0 {
                            format!(", needs {} approval(s)", r.missing())
                        } else {
                            ", ready".to_owned()
                        }
                    }
                    _ => String::new(),
                };
                println!(
                    "{}  {:<6}  {}  [{} → {}, r{}{state}]  ({})",
                    names.of(*id),
                    p.status,
                    p.title,
                    p.source,
                    p.target,
                    p.revisions.len(),
                    who(&trust, p.author)
                );
            }
            if shown.is_empty() {
                println!("no pull requests");
            }
        }
        PrCmd::Show { id } => {
            let id = pr::resolve(repo, &id)?;
            let loaded = pr::load(repo, &trust, id)?;
            show(repo, &trust, &name(repo, id)?, &loaded.model);
            if !loaded.rejected.is_empty() {
                eprintln!();
                eprintln!("ignored {} operation(s):", loaded.rejected.len());
                for r in &loaded.rejected {
                    eprintln!("  {}: {}", short_oid(r.op), r.reason);
                }
            }
        }
        PrCmd::Diff {
            id,
            revision,
            since,
        } => {
            let p = pr::load(repo, &trust, pr::resolve(repo, &id)?)?.model;
            let r = &p.revisions[number(&p, revision)?];
            have(repo, r)?;
            let (base, head) = (r.base.to_string(), r.head.to_string());
            match since {
                None => git(repo, &["diff", &base, &head])?,
                Some(n) => {
                    let old = &p.revisions[number(&p, Some(n))?];
                    have(repo, old)?;
                    if old.base == r.base {
                        git(repo, &["diff", &old.head.to_string(), &head])?;
                    } else {
                        // Rebased: compare the commits, not the trees.
                        let before = format!("{}..{}", old.base, old.head);
                        git(repo, &["range-diff", &before, &format!("{base}..{head}")])?;
                    }
                }
            }
        }
        PrCmd::Checkout { id, branch } => {
            let p = pr::load(repo, &trust, pr::resolve(repo, &id)?)?.model;
            let head = p.latest().head;
            have(repo, p.latest())?;
            let name = branch.unwrap_or(p.source);
            let hex = head.to_string();
            match repo.refname_to_id(&format!("refs/heads/{name}")) {
                Err(_) => git(repo, &["switch", "-c", &name, &hex])?,
                Ok(at) if at == head => git(repo, &["switch", &name])?,
                Ok(at) if repo.graph_descendant_of(head, at)? => {
                    git(repo, &["switch", &name])?;
                    git(repo, &["merge", "--ff-only", "--quiet", &hex])?;
                }
                Ok(_) => bail!(
                    "branch {name} has commits that revision {} doesn't; pass --branch <name>",
                    p.revisions.len()
                ),
            }
        }
        PrCmd::Revise {
            id,
            note,
            head,
            remote,
        } => {
            let (signer, my_id) = current_user_with_signer(repo, &trust)?;
            let id = match id {
                Some(id) => pr::resolve(repo, &id)?,
                None => mine_here(repo, &trust, my_id)?,
            };
            let p = pr::load(repo, &trust, id)?.model;
            let head = match head {
                Some(rev) => repo.revparse_single(&rev)?.peel_to_commit()?.id(),
                None => repo
                    .refname_to_id(&format!("refs/heads/{}", p.source))
                    .with_context(|| format!("no branch {}; pass --head", p.source))?,
            };
            let base = repo.merge_base(head, tip(repo, &remote, &p.target)?)?;
            let latest = p.latest();
            if (head, base) == (latest.head, latest.base) {
                bail!("no change since revision {}", p.revisions.len());
            }
            pr::revise(
                repo,
                &trust,
                &signer,
                id,
                head,
                base,
                &note.unwrap_or_default(),
            )?;
            println!(
                "pull request {} is at revision {}; `fullgit sync` shares it",
                name(repo, id)?,
                p.revisions.len() + 1
            );
        }
        PrCmd::Comment {
            id,
            body,
            file,
            line,
            old,
            revision,
            reply,
        } => {
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let id = pr::resolve(repo, &id)?;
            let p = pr::load(repo, &trust, id)?.model;
            let side = if old { Side::Old } else { Side::New };
            let place = match (&reply, &file, line) {
                (Some(c), _, _) => Place::Reply(find_comment(&p, c)?.id),
                (None, Some(path), Some(line)) => {
                    let n = number(&p, revision)?;
                    let r = &p.revisions[n];
                    let lines = file_lines(repo, r, path, side).with_context(|| {
                        format!(
                            "{path} isn't in revision {} ({} side)",
                            n + 1,
                            side.as_str()
                        )
                    })?;
                    if line == 0 || line as usize > lines.len() {
                        bail!("{path} has {} lines", lines.len());
                    }
                    Place::Line {
                        revision: r.id,
                        path,
                        line,
                        side,
                    }
                }
                _ => Place::General,
            };
            let body = match body {
                Some(b) => b,
                None => editor(repo, "", "Your comment.")?,
            };
            pr::comment(repo, &trust, &signer, id, &body, place)?;
        }
        PrCmd::EditComment { id, comment, body } => {
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let id = pr::resolve(repo, &id)?;
            let p = pr::load(repo, &trust, id)?.model;
            let c = find_comment(&p, &comment)?;
            let body = match body {
                Some(b) => b,
                None => editor(repo, &c.body, "Your comment.")?,
            };
            pr::edit_comment(repo, &trust, &signer, id, c.id, &body)?;
        }
        PrCmd::Edit { id, title, body } => {
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let id = pr::resolve(repo, &id)?;
            let (title, body) = match (title, body) {
                (None, None) => {
                    let current = pr::load(repo, &trust, id)?.model;
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
            pr::edit(repo, &trust, &signer, id, title.as_deref(), body.as_deref())?;
        }
        PrCmd::Review {
            id, approve, body, ..
        } => {
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let id = pr::resolve(repo, &id)?;
            let p = pr::load(repo, &trust, id)?.model;
            let verdict = if approve {
                Verdict::Approve
            } else {
                Verdict::Changes
            };
            let body = match (body, verdict) {
                (Some(b), _) => b,
                (None, Verdict::Approve) => String::new(),
                (None, Verdict::Changes) => editor(repo, "", "What should change?")?,
            };
            pr::review(repo, &trust, &signer, id, p.latest().id, verdict, &body)?;
            let n = p.revisions.len();
            match verdict {
                Verdict::Approve => println!("approved revision {n}"),
                Verdict::Changes => println!("requested changes on revision {n}"),
            }
        }
        PrCmd::Close { id, comment } => {
            set_status(repo, &trust, &id, Status::Closed, comment)?;
        }
        PrCmd::Reopen { id, comment } => {
            set_status(repo, &trust, &id, Status::Open, comment)?;
        }
        PrCmd::Merge { .. } => unreachable!("handled above"),
    }
    Ok(())
}

/// What a new pull request from `source` into `target` would hold: its
/// head, base, and how many commits lie between.
pub(crate) fn range(
    repo: &Repository,
    remote: &str,
    source: &str,
    target: &str,
) -> Result<(Oid, Oid, usize)> {
    if source == target {
        bail!("{source} is the target; pick another branch");
    }
    let head = repo
        .refname_to_id(&format!("refs/heads/{source}"))
        .with_context(|| format!("no branch {source}"))?;
    let base = repo
        .merge_base(head, tip(repo, remote, target)?)
        .with_context(|| format!("{source} and {target} share no history"))?;
    let commits = count(repo, head, base)?;
    if commits == 0 {
        bail!("{source} has no commits that {target} doesn't");
    }
    Ok((head, base, commits))
}

fn merge(repo: &Repository, id: &str, remote: &str) -> Result<()> {
    let id = pr::resolve(repo, id)?;
    println!(
        "{}",
        merge_now(repo, &signer_from_git_config(repo)?, id, remote)?
    );
    Ok(())
}

/// Merges pull request `id` into its target on `remote` and records it.
/// Returns what happened, for people.
pub(crate) fn merge_now(
    repo: &Repository,
    signer: &dyn Signer,
    id: Oid,
    remote: &str,
) -> Result<String> {
    // Decide on everyone's latest reviews, revisions and rules.
    sync::sync(repo, remote, Some(signer))?;
    let trust = Trust::load(repo)?;
    let me = identity_of(&trust, signer)?;
    let p = pr::load(repo, &trust, id)?.model;
    match p.status {
        Status::Open => {}
        Status::Closed => bail!(
            "pull request {} is closed; reopen it first",
            name(repo, id)?
        ),
        Status::Merged => bail!("pull request {} is already merged", name(repo, id)?),
    }
    if trust.role(me) < Some(Role::Maintainer) {
        bail!("merging takes a maintainer");
    }
    let readiness = p.readiness(&trust);
    if !readiness.ready() {
        bail!("{}", describe(&trust, &readiness));
    }
    let (n, latest) = (p.revisions.len(), p.latest());
    have(repo, latest)?;
    let tip = pr::fetch_branch(repo, remote, &p.target)?;
    let mut done = String::new();
    let commit = if tip == latest.head || repo.graph_descendant_of(tip, latest.head)? {
        done = format!("{} already contains revision {n}; ", p.target);
        tip
    } else {
        match pr::merge_commit(
            repo,
            tip,
            latest.head,
            &message(&trust, id, &name(repo, id)?, &p, &readiness),
        )? {
            Merging::Conflicts(paths) => bail!(
                "revision {n} conflicts with {} in:\n  {}\nmerge {} into {} (or rebase), \
                 then `fullgit pr revise`",
                p.target,
                paths.join("\n  "),
                p.target,
                p.source
            ),
            Merging::Clean(c) => {
                let spec = format!("{c}:refs/heads/{}", p.target);
                if !sync::push_specs(repo, remote, &[spec])? {
                    bail!(
                        "{} moved on {remote} meanwhile; run `fullgit pr merge` again",
                        p.target
                    );
                }
                c
            }
        }
    };
    pr::record_merge(repo, &trust, signer, id, latest.id, commit)?;
    sync::sync(repo, remote, Some(signer))?;
    Ok(format!(
        "{done}merged pull request {} into {} as {}; `git pull` brings it here",
        name(repo, id)?,
        p.target,
        short_oid(commit)
    ))
}

/// `fullgit verify`.
pub fn verify(repo: &Repository, branch: Option<String>, remote: &str) -> Result<()> {
    let trust = Trust::load(repo)?;
    let branch = match branch {
        Some(b) => b,
        None => default_branch(repo, remote)?,
    };
    let tip = tip(repo, remote, &branch)?;
    let v = pr::verify(repo, &trust, &branch, tip)?;
    let at: String = format!("{branch} at {}", short_oid(tip));
    if v.unrecorded.is_empty() {
        println!(
            "{at}: all {} commit(s) since it was protected were merged through pull requests",
            v.checked
        );
        return Ok(());
    }
    eprintln!(
        "{at}: {} of {} commit(s) since it was protected weren't merged through a pull request:",
        v.unrecorded.len(),
        v.checked
    );
    for id in &v.unrecorded {
        let c = repo.find_commit(*id)?;
        eprintln!(
            "  {} {} ({})",
            short_oid(*id),
            c.summary().ok().flatten().unwrap_or_default(),
            c.author().name().unwrap_or_default()
        );
    }
    std::process::exit(1);
}

fn message(trust: &Trust, id: Oid, name: &str, p: &Pr, r: &Readiness) -> String {
    let mut m = format!(
        "Merge pull request {}: {}\n\nMerges {} into {}, revision {}.\n\n",
        name,
        p.title,
        p.source,
        p.target,
        p.revisions.len()
    );
    for a in &r.approvals {
        if let Some(i) = trust.identities.get(a) {
            m.push_str(&format!("Approved-by: {} <{}>\n", i.name, i.email));
        }
    }
    m.push_str(&format!("Fullgit-PR: {id}\n"));
    m
}

fn set_status(
    repo: &Repository,
    trust: &Trust,
    id: &str,
    status: Status,
    comment: Option<String>,
) -> Result<()> {
    let (signer, _) = current_user_with_signer(repo, trust)?;
    let id = pr::resolve(repo, id)?;
    let current = pr::load(repo, trust, id)?.model.status;
    if current == status || current == Status::Merged {
        bail!("pull request {} is already {current}", name(repo, id)?);
    }
    if let Some(body) = comment {
        pr::comment(repo, trust, &signer, id, &body, Place::General)?;
    }
    pr::set_status(repo, trust, &signer, id, status)?;
    println!("pull request {} is {status}", name(repo, id)?);
    Ok(())
}

fn show(repo: &Repository, trust: &Trust, name: &str, p: &Pr) {
    let comments = Abbrev::new(p.comments.iter().map(|c| c.id));
    println!("{}", p.title);
    println!(
        "{} · {} · {} → {} · opened by {} on {}",
        p.status,
        name,
        p.source,
        p.target,
        who(trust, p.author),
        date(p.created())
    );
    if !p.body.trim().is_empty() {
        println!();
        print_indented(&p.body);
    }
    println!("\nrevisions:");
    for (n, r) in p.revisions.iter().enumerate() {
        let commits = count(repo, r.head, r.base).map_or("?".into(), |c| c.to_string());
        let note = if r.note.is_empty() {
            String::new()
        } else {
            format!(": {}", r.note)
        };
        println!(
            "  r{}  {}  {commits} commit(s), by {} on {}{note}",
            n + 1,
            short_id(r.head),
            who(trust, Some(r.author)),
            date(r.time)
        );
    }
    for e in &p.timeline {
        let actor = who(trust, Some(e.actor));
        let when = date(e.time);
        match &e.what {
            What::Opened => {}
            What::Edited => println!("\n· {actor} edited the description, {when}"),
            What::Revised(n) => println!("\n· {actor} pushed r{}, {when}", n + 1),
            What::Commented(n) => {
                let c = &p.comments[*n];
                let tag = format!(
                    "({}{})",
                    comments.of(c.id),
                    if c.edited { ", edited" } else { "" }
                );
                match (&c.location, c.reply_to) {
                    (_, Some(to)) => {
                        println!("\n── {actor} replied to {}, {when} {tag}", comments.of(to));
                    }
                    (Some(l), None) => {
                        let old = if l.side == Side::Old { ", old" } else { "" };
                        println!(
                            "\n── {actor} on {}:{} (r{}{old}), {when} {tag}",
                            l.path,
                            l.line,
                            l.revision + 1
                        );
                        context(repo, p, l);
                    }
                    (None, None) => println!("\n── {actor} commented, {when} {tag}"),
                }
                print_indented(&c.body);
            }
            What::Reviewed(n) => {
                let r = &p.reviews[*n];
                let verb = match r.verdict {
                    Verdict::Approve => "approved",
                    Verdict::Changes => "requested changes on",
                };
                println!("\n· {actor} {verb} r{}, {when}", r.revision + 1);
                if !r.body.trim().is_empty() {
                    print_indented(&r.body);
                }
            }
            What::Status(Status::Open) => println!("\n· {actor} reopened this, {when}"),
            What::Status(_) => println!("\n· {actor} closed this, {when}"),
            What::Merged => {
                let Some(m) = &p.merged else { continue };
                let approved = if m.approvals.is_empty() {
                    String::new()
                } else {
                    format!(", approved by {}", names(trust, m.approvals.iter()))
                };
                println!(
                    "\n· {actor} merged r{} as {}{approved}, {when}",
                    m.revision + 1,
                    short_oid(m.commit)
                );
            }
        }
    }
    if p.status == Status::Open {
        println!("\n{}", describe(trust, &p.readiness(trust)));
    }
}

/// E.g. `not ready to merge: 0 of 1 approvals from reviewers; changes
/// requested by carol`.
pub(crate) fn describe(trust: &Trust, r: &Readiness) -> String {
    let mut parts = Vec::new();
    match &r.rule {
        Some(rule) => {
            let from = rule
                .group
                .as_ref()
                .map_or(String::new(), |g| format!(" from {g}"));
            parts.push(format!(
                "{} of {} approval(s){from}",
                r.approvals.len(),
                rule.approvals
            ));
        }
        None if r.approvals.is_empty() => parts.push("no approvals required".into()),
        None => parts.push(format!("approved by {}", names(trust, r.approvals.iter()))),
    }
    if !r.changes.is_empty() {
        parts.push(format!(
            "changes requested by {}",
            names(trust, r.changes.iter())
        ));
    }
    let state = if r.ready() { "ready" } else { "not ready" };
    format!("{state} to merge: {}", parts.join("; "))
}

pub(crate) fn names<'a>(trust: &Trust, ids: impl Iterator<Item = &'a Oid>) -> String {
    ids.map(|id| who(trust, Some(*id)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Prints the commented line and the two before it.
fn context(repo: &Repository, p: &Pr, l: &Location) {
    let Ok(lines) = file_lines(repo, &p.revisions[l.revision], &l.path, l.side) else {
        return;
    };
    let line = l.line as usize;
    for n in line.saturating_sub(2).max(1)..=line.min(lines.len()) {
        let mark = if n == line { '>' } else { ' ' };
        println!("  {mark}{n:>5} │ {}", lines[n - 1]);
    }
}

pub(crate) fn file_lines(
    repo: &Repository,
    r: &Revision,
    path: &str,
    side: Side,
) -> Result<Vec<String>> {
    let commit = match side {
        Side::Old => r.base,
        Side::New => r.head,
    };
    let tree = repo.find_commit(commit)?.tree()?;
    let blob = repo.find_blob(tree.get_path(std::path::Path::new(path))?.id())?;
    Ok(String::from_utf8_lossy(blob.content())
        .lines()
        .map(str::to_owned)
        .collect())
}

/// Index of revision `n` (1-based); the latest if `None`.
fn number(p: &Pr, n: Option<usize>) -> Result<usize> {
    match n {
        None => Ok(p.revisions.len() - 1),
        Some(n) if (1..=p.revisions.len()).contains(&n) => Ok(n - 1),
        Some(n) => bail!("no revision {n}; there are {}", p.revisions.len()),
    }
}

fn find_comment<'a>(p: &'a Pr, prefix: &str) -> Result<&'a pr::Comment> {
    let found: Vec<_> = p
        .comments
        .iter()
        .filter(|c| c.id.to_string().starts_with(prefix))
        .collect();
    match found.as_slice() {
        [c] => Ok(c),
        [] => bail!("no comment {prefix} on this pull request"),
        _ => bail!("{prefix} matches several comments"),
    }
}

/// How a pull request is named: the shortest unique start of its id.
pub(crate) fn name(repo: &Repository, id: Oid) -> Result<String> {
    Ok(model::abbrev::<Pr>(repo)?.of(id))
}

/// Commits in `base..head`.
pub(crate) fn count(repo: &Repository, head: Oid, base: Oid) -> Result<usize> {
    let mut walk = repo.revwalk()?;
    walk.push(head)?;
    walk.hide(base)?;
    Ok(walk.count())
}

fn have(repo: &Repository, r: &Revision) -> Result<()> {
    if repo.find_commit(r.head).is_err() || repo.find_commit(r.base).is_err() {
        bail!("this revision's commits aren't here; run `fullgit sync`");
    }
    Ok(())
}

pub(crate) fn current_branch(repo: &Repository) -> Option<String> {
    let head = repo.head().ok()?;
    if !head.is_branch() {
        return None;
    }
    head.shorthand().ok().map(str::to_owned)
}

/// The branch `refs/remotes/<remote>/HEAD` names.
pub(crate) fn default_branch(repo: &Repository, remote: &str) -> Result<String> {
    let prefix = format!("refs/remotes/{remote}/");
    repo.find_reference(&format!("{prefix}HEAD"))
        .ok()
        .and_then(|r| r.symbolic_target().ok().flatten().map(str::to_owned))
        .and_then(|t| t.strip_prefix(&prefix).map(str::to_owned))
        .with_context(|| {
            format!(
                "don't know {remote}'s default branch; pass --target, or run \
                 `git remote set-head {remote} --auto`"
            )
        })
}

/// The branch as `remote` has it, else the local branch.
pub(crate) fn tip(repo: &Repository, remote: &str, branch: &str) -> Result<Oid> {
    repo.refname_to_id(&format!("refs/remotes/{remote}/{branch}"))
        .or_else(|_| repo.refname_to_id(&format!("refs/heads/{branch}")))
        .with_context(|| format!("no branch {branch}, here or on {remote}"))
}

/// Your one open pull request from the current branch.
fn mine_here(repo: &Repository, trust: &Trust, me: Oid) -> Result<Oid> {
    let branch = current_branch(repo).context("not on a branch; name the pull request")?;
    let found: Vec<Oid> = pr::all(repo, trust)?
        .into_iter()
        .filter_map(|(id, l)| {
            let p = l.ok()?.model;
            (p.status == Status::Open && p.source == branch && p.author == Some(me)).then_some(id)
        })
        .collect();
    match found.as_slice() {
        [id] => Ok(*id),
        [] => bail!("you have no open pull request from {branch}; name one"),
        _ => bail!("you have several open pull requests from {branch}; name one"),
    }
}

/// Runs git in the working tree (or the git dir, if bare), showing its
/// output.
fn git(repo: &Repository, args: &[&str]) -> Result<()> {
    let mut cmd = Command::new("git");
    match repo.workdir() {
        Some(dir) => cmd.current_dir(dir),
        None => cmd.arg("--git-dir").arg(repo.path()),
    };
    let status = cmd.args(args).status().context("running git")?;
    if !status.success() {
        bail!("git {} failed", args[0]);
    }
    Ok(())
}
