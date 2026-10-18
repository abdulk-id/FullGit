//! Pull request pages: the conversation, the changes with their line
//! comments, and the forms to review and merge.

use std::collections::BTreeSet;
use std::fmt::Write;

use anyhow::{Context, Result, bail};
use fullgit_core::Role;
use fullgit_core::pr::{self, Comment, Place, Pr, Side, Status, Verdict, What};
use fullgit_core::secret::DRIVER;
use git2::{Oid, Patch};

use super::html::{back, esc, markdown, short, state_badge, url_encode};
use super::issues::{comment_box, event};
use super::{Ctx, Req, Resp, with_param};
use crate::commands::pr::{
    count, current_branch, default_branch, describe, file_lines, merge_now, range,
};
use crate::date;

/// Lines of diff shown before giving up on a page.
const MAX_LINES: usize = 8000;

pub fn summary(ctx: &Ctx) -> Result<String> {
    let mut open = loaded(ctx)?;
    open.retain(|(_, p)| p.status == Status::Open);
    let mut s = format!(
        r#"<div class="list" style="margin-bottom:20px"><div class="head"><b>Open pull requests</b><span class="spacer"></span><a href="/prs">All {}</a></div>"#,
        open.len()
    );
    for (id, p) in open.iter().take(8) {
        s.push_str(&row(ctx, *id, p));
    }
    if open.is_empty() {
        s.push_str(r#"<div class="empty">No open pull requests.</div>"#);
    }
    s.push_str("</div>");
    Ok(s)
}

fn loaded(ctx: &Ctx) -> Result<Vec<(Oid, Pr)>> {
    let mut all: Vec<_> = pr::all(ctx.repo, &ctx.trust)?
        .into_iter()
        .filter_map(|(id, l)| Some((id, l.ok()?.model)))
        .collect();
    all.sort_by_key(|(id, p)| (std::cmp::Reverse(p.updated()), *id));
    Ok(all)
}

fn row(ctx: &Ctx, id: Oid, p: &Pr) -> String {
    let chip = match p.status {
        Status::Open => {
            let r = p.readiness(&ctx.trust);
            if !r.changes.is_empty() {
                r#"<span class="chip bad">changes requested</span>"#.to_owned()
            } else if r.missing() > 0 {
                format!(
                    r#"<span class="chip">needs {} approval(s)</span>"#,
                    r.missing()
                )
            } else {
                r#"<span class="chip ok">ready</span>"#.to_owned()
            }
        }
        _ => String::new(),
    };
    format!(
        r#"<div class="row"><span class="dot {st}"></span><div><a class="t" href="/prs/{s}">{t}</a>{chip}<div class="sub">#{s} by {who} · <code class="ref">{src}</code> → <code class="ref">{tgt}</code> · r{n} · updated {when}</div></div></div>"#,
        st = p.status.as_str(),
        s = ctx.prs.of(id),
        t = esc(&p.title),
        who = esc(&ctx.who(p.author)),
        src = esc(&p.source),
        tgt = esc(&p.target),
        n = p.revisions.len(),
        when = date(p.updated()),
    )
}

pub fn list(ctx: &Ctx, req: &Req) -> Result<Resp> {
    let state = req.q("state").unwrap_or("open");
    let all = loaded(ctx)?;
    let count = |s: Status| all.iter().filter(|(_, p)| p.status == s).count();
    let tab = |key: &str, text: String| {
        let on = if key == state { " class=\"on\"" } else { "" };
        format!(r#"<a{on} href="/prs?state={key}">{text}</a>"#)
    };
    let mut body = String::from(r#"<div class="actions" style="margin-bottom:12px">"#);
    if ctx.can(Role::Contributor) {
        body.push_str(r#"<a class="btn primary" href="/prs/new">New pull request</a>"#);
    }
    let _ = write!(
        body,
        r#"</div><div class="list"><div class="head">{}{}{}{}</div>"#,
        tab("open", format!("{} Open", count(Status::Open))),
        tab("merged", format!("{} Merged", count(Status::Merged))),
        tab("closed", format!("{} Closed", count(Status::Closed))),
        tab("all", "All".into()),
    );
    let mut shown = 0;
    for (id, p) in &all {
        if state == "all" || p.status.as_str() == state {
            body.push_str(&row(ctx, *id, p));
            shown += 1;
        }
    }
    if shown == 0 {
        body.push_str(r#"<div class="empty">No pull requests here.</div>"#);
    }
    body.push_str("</div>");
    Ok(ctx.page(req, "Pull requests", body))
}

pub fn new_form(ctx: &Ctx, req: &Req) -> Result<Resp> {
    ctx.signer()?;
    let target = default_branch(ctx.repo, ctx.remote).unwrap_or_default();
    let current = current_branch(ctx.repo);
    let mut options = String::new();
    for b in ctx.repo.branches(Some(git2::BranchType::Local))? {
        let (b, _) = b?;
        let Ok(Some(name)) = b.name() else { continue };
        if name == target {
            continue;
        }
        let selected = if current.as_deref() == Some(name) {
            " selected"
        } else {
            ""
        };
        let _ = write!(options, r#"<option{selected}>{}</option>"#, esc(name));
    }
    let body = format!(
        r#"<h1>New pull request</h1><form class="stack" method="post" action="/prs/new">{}
<div class="grid"><label>Merge branch<select name="source" required>{options}</select></label>
<label>into<input type="text" name="target" value="{}" required></label></div>
<input type="text" name="title" placeholder="Title" required>
<textarea name="body" placeholder="Description (markdown)" rows="10"></textarea>
<p class="meta">The branch's commits travel with the pull request when you sync; it doesn't need pushing.</p>
<div class="actions"><button class="btn primary">Open pull request</button></div></form>"#,
        back("/prs/new"),
        esc(&target)
    );
    Ok(ctx.page(req, "New pull request", body))
}

pub fn create(ctx: &Ctx, req: &Req) -> Result<Resp> {
    let (source, target) = (req.need("source")?, req.need("target")?);
    let (head, base, _) = range(ctx.repo, ctx.remote, source, target)?;
    let id = pr::create(
        ctx.repo,
        &ctx.trust,
        ctx.signer()?,
        req.need("title")?,
        req.field("body").unwrap_or_default().trim(),
        source,
        target,
        head,
        base,
    )?;
    Ok(Resp::Redirect(with_param(
        &format!("/prs/{}", ctx.prs.of(id)),
        "msg",
        "Opened. Sync shares it, with its commits.",
    )))
}

fn header(ctx: &Ctx, id: Oid, p: &Pr, tab: &str) -> String {
    let latest = p.latest();
    let commits = count(ctx.repo, latest.head, latest.base).map_or("?".into(), |n| n.to_string());
    let on = |t: &str| if t == tab { r#" class="on""# } else { "" };
    format!(
        r#"<h1>{} <span class="id">#{s}</span></h1><div class="meta">{} {} wants to merge {commits} commit(s) into <code class="ref">{}</code> from <code class="ref">{}</code></div>
<div class="tabs"><a{} href="/prs/{s}">Conversation</a><a{} href="/prs/{s}/diff">Files changed</a></div>"#,
        esc(&p.title),
        state_badge(p.status.as_str()),
        ctx.person(p.author),
        esc(&p.target),
        esc(&p.source),
        on("conversation"),
        on("diff"),
        s = ctx.prs.of(id),
    )
}

pub fn show(ctx: &Ctx, req: &Req, id: Oid) -> Result<Resp> {
    let loaded = pr::load(ctx.repo, &ctx.trust, id)?;
    let p = &loaded.model;
    let here = format!("/prs/{}", ctx.prs.of(id));
    let mut b = header(ctx, id, p, "conversation");
    b.push_str(r#"<div class="layout"><div>"#);
    b.push_str(&comment_box(
        ctx,
        "",
        p.author,
        p.created(),
        "opened this",
        &p.body,
        None,
    ));
    for e in &p.timeline {
        let actor = ctx.person(Some(e.actor));
        let when = date(e.time);
        match &e.what {
            What::Opened => {}
            What::Edited => event(&mut b, "", &actor, "edited the description", &when),
            What::Revised(n) => {
                let r = &p.revisions[*n];
                let note = if r.note.is_empty() {
                    String::new()
                } else {
                    format!(": {}", esc(&r.note))
                };
                let what = format!(
                    r#"pushed <a href="{here}/diff?r={v}">r{v}</a>{note} (<a href="{here}/diff?r={v}&since={n}">changes since r{n}</a>)"#,
                    v = n + 1,
                );
                event(&mut b, "", &actor, &what, &when);
            }
            What::Commented(n) => {
                let c = &p.comments[*n];
                if c.reply_to.is_some() {
                    continue; // shown in its thread
                }
                b.push_str(&thread(ctx, id, p, c, &here, true));
            }
            What::Reviewed(n) => {
                let r = &p.reviews[*n];
                let (icon, verb) = match r.verdict {
                    Verdict::Approve => (r#"<span class="ic ok">✓</span>"#, "approved"),
                    Verdict::Changes => {
                        (r#"<span class="ic bad">✗</span>"#, "requested changes on")
                    }
                };
                let what = format!("{verb} r{}", r.revision + 1);
                if r.body.trim().is_empty() {
                    event(&mut b, icon, &actor, &what, &when);
                } else {
                    let verb = format!("{icon} {what}");
                    b.push_str(&comment_box(
                        ctx,
                        "",
                        Some(r.reviewer),
                        r.time,
                        &verb,
                        &r.body,
                        None,
                    ));
                }
            }
            What::Status(Status::Open) => event(
                &mut b,
                r#"<span class="ic ok">●</span>"#,
                &actor,
                "reopened this",
                &when,
            ),
            What::Status(_) => event(
                &mut b,
                r#"<span class="ic bad">●</span>"#,
                &actor,
                "closed this",
                &when,
            ),
            What::Merged => {
                let Some(m) = &p.merged else { continue };
                let what = format!(
                    "merged r{} into <code class=\"ref\">{}</code> as <code>{}</code>",
                    m.revision + 1,
                    esc(&p.target),
                    &m.commit.to_string()[..12]
                );
                event(
                    &mut b,
                    r#"<span class="ic m">●</span>"#,
                    &actor,
                    &what,
                    &when,
                );
            }
        }
    }
    if p.status == Status::Open {
        b.push_str(&merge_box(ctx, p, &here));
    }
    if ctx.can(Role::Contributor) {
        let moderates = ctx.moderates(p.author);
        let status_button = match p.status {
            Status::Open if moderates => {
                r#"<button class="btn danger" name="then" value="close">Close pull request</button>"#
            }
            Status::Closed if moderates => {
                r#"<button class="btn" name="then" value="reopen">Reopen pull request</button>"#
            }
            _ => "",
        };
        let _ = write!(
            b,
            r#"<div class="box"><div class="hd"><b>Add a comment</b></div><div class="bd pad"><form class="stack" method="post" action="{here}/comment">{}<textarea name="body" placeholder="Markdown"></textarea><div class="actions">{status_button}<button class="btn primary">Comment</button></div></form></div></div>"#,
            back(&here)
        );
        if p.status == Status::Open && ctx.me_id() != p.author {
            let _ = write!(
                b,
                r#"<div class="box" id="review"><div class="hd"><b>Review revision {n}</b></div><div class="bd pad"><form class="stack" method="post" action="{here}/review">{}<textarea name="body" placeholder="Summary (optional when approving)"></textarea><div class="actions"><button class="btn danger" name="verdict" value="changes">Request changes</button><button class="btn primary" name="verdict" value="approve">Approve</button></div></form></div></div>"#,
                back(&here),
                n = p.revisions.len()
            );
        }
    }
    b.push_str("</div><aside>");
    sidebar(ctx, &mut b, p, &here);
    b.push_str("</aside></div>");
    if !loaded.rejected.is_empty() {
        let _ = write!(
            b,
            r#"<p class="meta">Ignored {} operation(s) that weren't allowed; <code>fullgit pr show {}</code> lists them.</p>"#,
            loaded.rejected.len(),
            ctx.prs.of(id)
        );
    }
    Ok(ctx.page(req, &p.title, b))
}

fn merge_box(ctx: &Ctx, p: &Pr, here: &str) -> String {
    let r = p.readiness(&ctx.trust);
    let class = if r.ready() { "ready" } else { "notready" };
    let mut s = format!(
        r#"<div class="box {class}"><div class="bd pad"><b>{}</b>"#,
        esc(&describe(&ctx.trust, &r))
    );
    if ctx.can(Role::Maintainer) {
        let disabled = if r.ready() { "" } else { " disabled" };
        let _ = write!(
            s,
            r#"<form method="post" action="{here}/merge" class="actions">{}<span class="meta">Syncs, merges r{} into <code class="ref">{}</code> on {}, and pushes.</span><button class="btn primary"{disabled}>Merge pull request</button></form>"#,
            back(here),
            p.revisions.len(),
            esc(&p.target),
            esc(ctx.remote)
        );
    }
    s.push_str("</div></div>");
    s
}

fn sidebar(ctx: &Ctx, b: &mut String, p: &Pr, here: &str) {
    b.push_str(r#"<section class="revs"><h3>Revisions</h3>"#);
    for (n, r) in p.revisions.iter().enumerate().rev() {
        let commits = count(ctx.repo, r.head, r.base).map_or("?".into(), |c| c.to_string());
        let _ = write!(
            b,
            r#"<a href="{here}/diff?r={v}">r{v} · {commits} commit(s) · {}</a>"#,
            date(r.time),
            v = n + 1
        );
    }
    b.push_str("</section><section><h3>Reviews</h3>");
    let verdicts = p.verdicts();
    if verdicts.is_empty() {
        b.push_str("None yet");
    }
    for (who, r) in verdicts {
        let what = match r.verdict {
            Verdict::Approve => format!(
                r#"<span class="ic ok">✓</span> approved r{}"#,
                r.revision + 1
            ),
            Verdict::Changes => format!(
                r#"<span class="ic bad">✗</span> requested changes on r{}"#,
                r.revision + 1
            ),
        };
        let _ = write!(b, "<div>{} {what}</div>", ctx.person(Some(who)));
    }
    b.push_str("</section>");
    if ctx.moderates(p.author) {
        let _ = write!(
            b,
            r#"<section><details><summary>Edit title and description</summary><form class="stack" method="post" action="{here}/edit">{}<input type="text" name="title" value="{}"><textarea name="body" rows="8">{}</textarea><button class="btn">Save</button></form></details></section>"#,
            back(here),
            esc(&p.title),
            esc(&p.body)
        );
    }
}

/// A comment and its replies. Line comments show the code they're on;
/// `link` adds a link to that line in the diff.
fn thread(ctx: &Ctx, id: Oid, p: &Pr, root: &Comment, back_to: &str, link: bool) -> String {
    let here = format!("/prs/{}", ctx.prs.of(id));
    let mut s = format!(r#"<div class="box thread" id="c-{}">"#, short(root.id));
    match &root.location {
        Some(l) => {
            let path = esc(&l.path);
            let place = if link {
                format!(
                    r#"<a href="{here}/diff?r={}#{}">{path}:{}</a>"#,
                    l.revision + 1,
                    anchor(&l.path, l.side, l.line),
                    l.line
                )
            } else {
                format!("{path}:{}", l.line)
            };
            let old = if l.side == Side::Old {
                ", old side"
            } else {
                ""
            };
            let _ = write!(
                s,
                r#"<div class="hd">{} commented on {place} (r{}{old}) on {}</div>"#,
                ctx.person(Some(root.author)),
                l.revision + 1,
                date(root.time)
            );
            if link {
                s.push_str(&snippet(ctx, p, l));
            }
        }
        None => {
            let _ = write!(
                s,
                r#"<div class="hd">{} commented on {}</div>"#,
                ctx.person(Some(root.author)),
                date(root.time)
            );
        }
    }
    let _ = write!(
        s,
        r#"<div class="bd md">{}{}</div>"#,
        markdown(&root.body),
        edit_form(ctx, &here, root, back_to)
    );
    for r in p.comments.iter().filter(|c| c.reply_to == Some(root.id)) {
        let _ = write!(
            s,
            r#"<div class="reply" id="c-{}"><div class="who">{} replied on {}{}</div><div class="md">{}{}</div></div>"#,
            short(r.id),
            ctx.person(Some(r.author)),
            date(r.time),
            if r.edited { " (edited)" } else { "" },
            markdown(&r.body),
            edit_form(ctx, &here, r, back_to)
        );
    }
    if root.location.is_some() && ctx.can(Role::Contributor) {
        let _ = write!(
            s,
            r#"<div class="reply"><details><summary>Reply</summary><form class="stack" method="post" action="{here}/comment">{}<input type="hidden" name="reply" value="{}"><textarea name="body"></textarea><div class="actions"><button class="btn primary">Reply</button></div></form></details></div>"#,
            back(back_to),
            root.id
        );
    }
    s.push_str("</div>");
    s
}

fn edit_form(ctx: &Ctx, here: &str, c: &Comment, back_to: &str) -> String {
    if ctx.me_id() != Some(c.author) {
        return String::new();
    }
    format!(
        r#"<details><summary>Edit</summary><form class="stack" method="post" action="{here}/edit-comment">{}<input type="hidden" name="comment" value="{}"><textarea name="body">{}</textarea><div class="actions"><button class="btn">Save</button></div></form></details>"#,
        back(back_to),
        c.id,
        esc(&c.body)
    )
}

/// The commented line and the two before it.
fn snippet(ctx: &Ctx, p: &Pr, l: &pr::Location) -> String {
    let Ok(lines) = file_lines(ctx.repo, &p.revisions[l.revision], &l.path, l.side) else {
        return String::new();
    };
    let line = l.line as usize;
    let mut s = String::from(r#"<pre class="code">"#);
    for n in line.saturating_sub(2).max(1)..=line.min(lines.len()) {
        let text = format!("{n:>5}  {}", lines[n - 1]);
        if n == line {
            let _ = write!(s, r#"<span class="hl">{}</span>"#, esc(&text));
        } else {
            let _ = writeln!(s, "{}", esc(&text));
        }
    }
    s.push_str("</pre>");
    s
}

/// The id of a line's row in the diff.
fn anchor(path: &str, side: Side, line: u32) -> String {
    let hash = path
        .bytes()
        .fold(5381u32, |h, b| h.wrapping_mul(33) ^ u32::from(b));
    let side = if side == Side::Old { 'o' } else { 'n' };
    format!("L{hash:08x}{side}{line}")
}

pub fn diff(ctx: &Ctx, req: &Req, id: Oid) -> Result<Resp> {
    let p = pr::load(ctx.repo, &ctx.trust, id)?.model;
    let n = match req.q("r") {
        None => p.revisions.len(),
        Some(v) => v
            .parse()
            .ok()
            .filter(|n| (1..=p.revisions.len()).contains(n))
            .context("no such revision")?,
    };
    let since = req
        .q("since")
        .map(|v| {
            v.parse::<usize>()
                .ok()
                .filter(|m| (1..n).contains(m))
                .context("no such earlier revision")
        })
        .transpose()?;
    let r = &p.revisions[n - 1];
    let here = format!("/prs/{}", ctx.prs.of(id));
    let mut b = header(ctx, id, &p, "diff");
    b.push_str(r#"<div class="meta">Revision: "#);
    for v in 1..=p.revisions.len() {
        if v == n && since.is_none() {
            let _ = write!(b, "<b>r{v}</b> ");
        } else {
            let _ = write!(b, r#"<a href="{here}/diff?r={v}">r{v}</a> "#);
        }
    }
    if n > 1 {
        let m = since.unwrap_or(n - 1);
        if since.is_some() {
            let _ = write!(b, " · <b>changes from r{m} to r{n}</b>");
        } else {
            let _ = write!(
                b,
                r#" · <a href="{here}/diff?r={n}&since={m}">changes since r{m}</a>"#
            );
        }
    }
    b.push_str("</div>");
    if ctx.repo.find_commit(r.head).is_err() || ctx.repo.find_commit(r.base).is_err() {
        b.push_str(
            r#"<div class="flash err">This revision's commits aren't here yet; sync.</div>"#,
        );
        return Ok(ctx.page(req, &p.title, b));
    }
    match since {
        Some(m) => {
            let old = &p.revisions[m - 1];
            if old.base == r.base {
                b.push_str(&render(ctx, old.head, r.head, None)?);
            } else {
                b.push_str(r#"<p class="meta">The branch was rebased, so this compares the commits (<code>git range-diff</code>).</p>"#);
                b.push_str(&range_diff(ctx, old.base, old.head, r.base, r.head)?);
            }
        }
        None => {
            let comments = Commenting {
                id,
                p: &p,
                revision: n - 1,
                here: &here,
                page: format!("{here}/diff?r={n}"),
                at: req.q("at").zip(req.q("file")),
            };
            b.push_str(&render(ctx, r.base, r.head, Some(&comments))?);
        }
    }
    Ok(ctx.page(req, &format!("Files changed · {}", p.title), b))
}

/// Line comments on the revision a diff shows.
struct Commenting<'a> {
    id: Oid,
    p: &'a Pr,
    revision: usize,
    here: &'a str,
    /// This diff page's URL.
    page: String,
    /// The line to show a comment form under: `n12` or `o3`, and its file.
    at: Option<(&'a str, &'a str)>,
}

fn render(ctx: &Ctx, from: Oid, to: Oid, comments: Option<&Commenting>) -> Result<String> {
    let repo = ctx.repo;
    let (a, b) = (
        repo.find_commit(from)?.tree()?,
        repo.find_commit(to)?.tree()?,
    );
    let mut opts = git2::DiffOptions::new();
    opts.context_lines(3);
    let mut diff = repo.diff_tree_to_tree(Some(&a), Some(&b), Some(&mut opts))?;
    diff.find_similar(None)?;
    let mut s = String::new();
    let mut shown = 0;
    let threads: Vec<&Comment> = comments
        .map(|c| {
            c.p.comments
                .iter()
                .filter(|x| {
                    x.reply_to.is_none()
                        && x.location
                            .as_ref()
                            .is_some_and(|l| l.revision == c.revision)
                })
                .collect()
        })
        .unwrap_or_default();
    let can_comment = comments.is_some() && ctx.can(Role::Contributor);
    if diff.deltas().len() == 0 {
        s.push_str(r#"<div class="empty">No changes.</div>"#);
    }
    for idx in 0..diff.deltas().len() {
        let Some(patch) = Patch::from_diff(&diff, idx)? else {
            continue;
        };
        let delta = patch.delta();
        let path = delta
            .new_file()
            .path()
            .or_else(|| delta.old_file().path())
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let old_path = delta
            .old_file()
            .path()
            .map(|p| p.to_string_lossy().into_owned());
        let title = match &old_path {
            Some(o) if *o != path => format!("{} → {}", esc(o), esc(&path)),
            _ => esc(&path),
        };
        let (adds, dels) = patch.line_stats().map_or((0, 0), |(_, a, d)| (a, d));
        let _ = write!(
            s,
            r#"<div class="diff"><div class="file">{title} <span class="chip ok">+{adds}</span><span class="chip bad">−{dels}</span></div>"#
        );
        let secret = repo
            .get_attr(
                std::path::Path::new(&path),
                "filter",
                git2::AttrCheckFlags::FILE_THEN_INDEX,
            )
            .ok()
            .flatten()
            == Some(DRIVER);
        if secret {
            s.push_str(
                r#"<div class="msg">Encrypted secret; its contents aren't shown.</div></div>"#,
            );
            continue;
        }
        if patch.delta().flags().is_binary() {
            s.push_str(r#"<div class="msg">Binary file.</div></div>"#);
            continue;
        }
        if shown > MAX_LINES {
            s.push_str(r#"<div class="msg">Not shown: the diff is too long. <code>fullgit pr diff</code> shows it all.</div></div>"#);
            continue;
        }
        s.push_str("<table>");
        let mut placed = BTreeSet::new();
        for h in 0..patch.num_hunks() {
            let (hunk, lines) = patch.hunk(h)?;
            let _ = write!(
                s,
                r#"<tr class="hunk"><td class="n"></td><td class="n"></td><td class="c">{}</td></tr>"#,
                esc(String::from_utf8_lossy(hunk.header()).trim_end())
            );
            for l in 0..lines {
                let line = patch.line_in_hunk(h, l)?;
                let (class, side, number) = match line.origin() {
                    '+' => ("add", Side::New, line.new_lineno()),
                    '-' => ("del", Side::Old, line.old_lineno()),
                    ' ' => ("ctx", Side::New, line.new_lineno()),
                    _ => continue, // "no newline at end of file" markers
                };
                let Some(number) = number else { continue };
                shown += 1;
                let id = anchor(&path, side, number);
                let num = |n: Option<u32>| n.map_or(String::new(), |n| n.to_string());
                let (old, new) = (num(line.old_lineno()), num(line.new_lineno()));
                let key = format!("{}{number}", if side == Side::Old { 'o' } else { 'n' });
                let (old, new) = match comments {
                    Some(c) if can_comment => {
                        let link = |text: String| {
                            if text.is_empty() {
                                return text;
                            }
                            format!(
                                r##"<a href="{}&at={key}&file={}#{id}" title="Comment on this line">{text}</a>"##,
                                c.page,
                                url_encode(&path)
                            )
                        };
                        (link(old), link(new))
                    }
                    _ => (old, new),
                };
                let text = String::from_utf8_lossy(line.content());
                let _ = write!(
                    s,
                    r#"<tr class="{class}" id="{id}"><td class="n">{old}</td><td class="n">{new}</td><td class="c">{}</td></tr>"#,
                    esc(text.trim_end_matches(['\n', '\r']))
                );
                let Some(c) = comments else { continue };
                for t in threads.iter().filter(|t| {
                    t.location
                        .as_ref()
                        .is_some_and(|l| l.path == path && l.side == side && l.line == number)
                }) {
                    placed.insert(t.id);
                    let _ = write!(
                        s,
                        r#"<tr class="note"><td colspan="3">{}</td></tr>"#,
                        thread(ctx, c.id, c.p, t, &format!("{}#{id}", c.page), false)
                    );
                }
                if can_comment && c.at == Some((key.as_str(), path.as_str())) {
                    let _ = write!(
                        s,
                        r#"<tr class="note"><td colspan="3"><form class="stack" method="post" action="{}/comment">{}<input type="hidden" name="path" value="{}"><input type="hidden" name="line" value="{number}"><input type="hidden" name="side" value="{}"><input type="hidden" name="revision" value="{}"><textarea name="body" placeholder="Comment on line {number}" autofocus></textarea><div class="actions"><a class="btn" href="{}#{id}">Cancel</a><button class="btn primary">Comment</button></div></form></td></tr>"#,
                        c.here,
                        back(&format!("{}#{id}", c.page)),
                        esc(&path),
                        side.as_str(),
                        c.p.revisions[c.revision].id,
                        c.page,
                    );
                }
            }
        }
        s.push_str("</table>");
        // Comments on lines the diff doesn't show, e.g. made from the CLI.
        if let Some(c) = comments {
            for t in threads.iter().filter(|t| {
                !placed.contains(&t.id) && t.location.as_ref().is_some_and(|l| l.path == path)
            }) {
                let _ = write!(
                    s,
                    r#"<div class="msg">On a line outside the diff:</div><div style="padding:0 8px">{}</div>"#,
                    thread(ctx, c.id, c.p, t, &c.page, true)
                );
            }
        }
        s.push_str("</div>");
    }
    Ok(s)
}

fn range_diff(ctx: &Ctx, base1: Oid, head1: Oid, base2: Oid, head2: Oid) -> Result<String> {
    let out = std::process::Command::new("git")
        .arg("--git-dir")
        .arg(ctx.repo.path())
        .args([
            "range-diff",
            "--no-color",
            &format!("{base1}..{head1}"),
            &format!("{base2}..{head2}"),
        ])
        .output()?;
    if !out.status.success() {
        bail!(
            "git range-diff failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(format!(
        r#"<pre class="code">{}</pre>"#,
        esc(&String::from_utf8_lossy(&out.stdout))
    ))
}

pub fn act(ctx: &Ctx, req: &Req, id: Oid, action: &str) -> Result<Resp> {
    let here = format!("/prs/{}", ctx.prs.of(id));
    let back_to = super::back_of(req).to_owned();
    if action == "merge" {
        let _pass = super::ssh_passphrase(ctx)?;
        let msg = merge_now(ctx.repo, ctx.signer()?, id, ctx.remote)?;
        return Ok(Resp::Redirect(with_param(&here, "msg", &msg)));
    }
    let signer = ctx.signer()?;
    let (repo, trust) = (ctx.repo, &ctx.trust);
    let current = pr::load(repo, trust, id)?.model;
    let msg = match action {
        "comment" => {
            let body = req.field("body").unwrap_or_default().trim();
            let then = req.field("then");
            if body.is_empty() && then.is_none() {
                bail!("write a comment first");
            }
            if !body.is_empty() {
                let place = match (req.field("reply"), req.field("path")) {
                    (Some(to), _) => Place::Reply(Oid::from_str(to)?),
                    (None, Some(path)) => Place::Line {
                        revision: Oid::from_str(req.need("revision")?)?,
                        path,
                        line: req.need("line")?.parse()?,
                        side: req.need("side")?.parse().map_err(anyhow::Error::msg)?,
                    },
                    (None, None) => Place::General,
                };
                pr::comment(repo, trust, signer, id, body, place)?;
            }
            match then {
                Some("close") => {
                    pr::set_status(repo, trust, signer, id, Status::Closed)?;
                    "Closed."
                }
                Some("reopen") => {
                    pr::set_status(repo, trust, signer, id, Status::Open)?;
                    "Reopened."
                }
                _ => "Commented.",
            }
        }
        "review" => {
            let verdict: Verdict = req.need("verdict")?.parse().map_err(anyhow::Error::msg)?;
            let body = req.field("body").unwrap_or_default().trim();
            if verdict == Verdict::Changes && body.is_empty() {
                bail!("say what should change");
            }
            pr::review(repo, trust, signer, id, current.latest().id, verdict, body)?;
            match verdict {
                Verdict::Approve => "Approved.",
                Verdict::Changes => "Requested changes.",
            }
        }
        "edit" => {
            let title = req.need("title")?;
            // A field left out means unchanged.
            let body = req.field("body").map(str::trim);
            let title = (title != current.title).then_some(title);
            let body = body.filter(|b| *b != current.body);
            if title.is_none() && body.is_none() {
                bail!("nothing changed");
            }
            pr::edit(repo, trust, signer, id, title, body)?;
            "Saved."
        }
        "edit-comment" => {
            let comment = Oid::from_str(req.need("comment")?)?;
            pr::edit_comment(repo, trust, signer, id, comment, req.need("body")?)?;
            "Comment saved."
        }
        other => bail!("unknown action {other}"),
    };
    let to = if back_to.starts_with(&here) {
        back_to
    } else {
        here
    };
    Ok(Resp::Redirect(with_param(&to, "msg", msg)))
}
