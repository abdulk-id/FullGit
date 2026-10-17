//! Issue pages.

use std::collections::BTreeSet;
use std::fmt::Write;

use anyhow::{Result, bail};
use fullgit_core::Role;
use fullgit_core::issue::{self, Issue, Status, What};
use git2::Oid;

use super::html::{back, esc, markdown, short, state_badge};
use super::{Ctx, Req, Resp, with_param};
use crate::date;

pub fn summary(ctx: &Ctx) -> Result<String> {
    let mut open = loaded(ctx)?;
    open.retain(|(_, i)| i.status == Status::Open);
    let mut s = format!(
        r#"<div class="list" style="margin-bottom:20px"><div class="head"><b>Open issues</b><span class="spacer"></span><a href="/issues">All {}</a></div>"#,
        open.len()
    );
    for (id, i) in open.iter().take(8) {
        s.push_str(&row(ctx, *id, i));
    }
    if open.is_empty() {
        s.push_str(r#"<div class="empty">No open issues.</div>"#);
    }
    s.push_str("</div>");
    Ok(s)
}

/// Every issue that loads, most recently updated first.
fn loaded(ctx: &Ctx) -> Result<Vec<(Oid, Issue)>> {
    let mut all: Vec<_> = issue::all(ctx.repo, &ctx.trust)?
        .into_iter()
        .filter_map(|(id, l)| Some((id, l.ok()?.model)))
        .collect();
    all.sort_by_key(|(id, i)| (std::cmp::Reverse(i.updated()), *id));
    Ok(all)
}

fn row(ctx: &Ctx, id: Oid, i: &Issue) -> String {
    let labels: String = i.labels.iter().map(|l| label(l)).collect();
    let comments = match i.comments.len() {
        0 => String::new(),
        n => format!(" · {n} comment(s)"),
    };
    format!(
        r#"<div class="row"><span class="dot {st}"></span><div><a class="t" href="/issues/{s}">{t}</a>{labels}<div class="sub">#{s} opened by {who} on {when}{comments}</div></div></div>"#,
        st = i.status.as_str(),
        s = ctx.issues.of(id),
        t = esc(&i.title),
        who = esc(&ctx.who(i.author)),
        when = date(i.created()),
    )
}

pub fn label(l: &str) -> String {
    format!(
        r#"<a class="label" href="/issues?state=all&label={}">{}</a>"#,
        super::html::url_encode(l),
        esc(l)
    )
}

pub fn list(ctx: &Ctx, req: &Req) -> Result<Resp> {
    let state = req.q("state").unwrap_or("open");
    let label_filter = req.q("label");
    let all = loaded(ctx)?;
    let count = |s: Status| all.iter().filter(|(_, i)| i.status == s).count();
    let tab = |key: &str, text: String| {
        let on = if key == state { " class=\"on\"" } else { "" };
        format!(r#"<a{on} href="/issues?state={key}">{text}</a>"#)
    };
    let mut body = String::from(r#"<div class="actions" style="margin-bottom:12px">"#);
    if ctx.can(Role::Contributor) {
        body.push_str(r#"<a class="btn primary" href="/issues/new">New issue</a>"#);
    }
    body.push_str("</div>");
    let _ = write!(
        body,
        r#"<div class="list"><div class="head">{}{}{}"#,
        tab("open", format!("{} Open", count(Status::Open))),
        tab("closed", format!("{} Closed", count(Status::Closed))),
        tab("all", "All".into()),
    );
    if let Some(l) = label_filter {
        let _ = write!(body, r#"<span>label: {}</span>"#, esc(l));
    }
    body.push_str("</div>");
    let mut shown = 0;
    for (id, i) in &all {
        let state_ok = state == "all" || i.status.as_str() == state;
        if state_ok && label_filter.is_none_or(|l| i.labels.contains(l)) {
            body.push_str(&row(ctx, *id, i));
            shown += 1;
        }
    }
    if shown == 0 {
        body.push_str(r#"<div class="empty">No issues here.</div>"#);
    }
    body.push_str("</div>");
    Ok(ctx.page(req, "Issues", body))
}

pub fn new_form(ctx: &Ctx, req: &Req) -> Result<Resp> {
    ctx.signer()?;
    let body = format!(
        r#"<h1>New issue</h1><form class="stack" method="post" action="/issues/new">{}
<input type="text" name="title" placeholder="Title" required autofocus>
<textarea name="body" placeholder="Description (markdown)" rows="10"></textarea>
{}
<div class="actions"><button class="btn primary">Open issue</button></div></form>"#,
        back("/issues/new"),
        label_picker(ctx, &BTreeSet::new()),
    );
    Ok(ctx.page(req, "New issue", body))
}

pub fn create(ctx: &Ctx, req: &Req) -> Result<Resp> {
    let labels = chosen_labels(ctx, req)?;
    let id = issue::create(
        ctx.repo,
        &ctx.trust,
        ctx.signer()?,
        req.need("title")?,
        req.field("body").unwrap_or_default().trim(),
        &labels,
    )?;
    Ok(Resp::Redirect(with_param(
        &format!("/issues/{}", ctx.issues.of(id)),
        "msg",
        "Opened. Sync shares it.",
    )))
}

/// Checkboxes for the labels the policy lists, `current` ticked. Without a
/// policy any label goes, so it's a text field.
fn label_picker(ctx: &Ctx, current: &BTreeSet<String>) -> String {
    let Some(listed) = issue::available(&ctx.trust) else {
        let current: Vec<&str> = current.iter().map(String::as_str).collect();
        return format!(
            r#"<input type="text" name="labels" value="{}" placeholder="Labels, separated by spaces or commas">"#,
            esc(&current.join(" "))
        );
    };
    if listed.is_empty() {
        return r#"<p class="meta">No labels yet; maintainers add them in <a href="/settings">Settings</a>.</p>"#.into();
    }
    let mut s = String::from(r#"<div class="pick">"#);
    for l in listed {
        let checked = if current.contains(l) { " checked" } else { "" };
        let _ = write!(
            s,
            r#"<label><input type="checkbox" name="label" value="{0}"{checked}> <span class="label">{0}</span></label>"#,
            esc(l)
        );
    }
    s.push_str("</div>");
    s
}

/// The labels a form picked, from [`label_picker`].
fn chosen_labels(ctx: &Ctx, req: &Req) -> Result<Vec<String>> {
    if issue::available(&ctx.trust).is_some() {
        return Ok(req.fields("label").into_iter().map(str::to_owned).collect());
    }
    let labels: Vec<String> = req
        .field("labels")
        .unwrap_or_default()
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    for l in &labels {
        issue::valid_label(l).map_err(anyhow::Error::msg)?;
    }
    Ok(labels)
}

pub fn show(ctx: &Ctx, req: &Req, id: Oid) -> Result<Resp> {
    let loaded = issue::load(ctx.repo, &ctx.trust, id)?;
    let i = &loaded.model;
    let here = format!("/issues/{}", ctx.issues.of(id));
    let moderates = ctx.moderates(i.author);
    let mut b = String::new();
    let _ = write!(
        b,
        r#"<h1>{} <span class="id">#{}</span></h1><div class="meta">{} {} opened this on {} · {} comment(s)</div>"#,
        esc(&i.title),
        ctx.issues.of(id),
        state_badge(i.status.as_str()),
        ctx.person(i.author),
        date(i.created()),
        i.comments.len()
    );
    b.push_str(r#"<div class="layout"><div>"#);
    b.push_str(&comment_box(
        ctx,
        "",
        i.author,
        i.created(),
        "opened this",
        &i.body,
        None,
    ));
    for e in &i.timeline {
        let actor = ctx.person(Some(e.actor));
        let when = date(e.time);
        match &e.what {
            What::Opened => {}
            What::Edited => event(&mut b, "", &actor, "edited the description", &when),
            What::Commented(n) => {
                let c = &i.comments[*n];
                let edit = (ctx.me_id() == Some(c.author)).then(|| {
                    format!(
                        r#"<details><summary>Edit</summary><form class="stack" method="post" action="{here}/edit-comment">{}<input type="hidden" name="comment" value="{}"><textarea name="body">{}</textarea><div class="actions"><button class="btn">Save</button></div></form></details>"#,
                        back(&here),
                        c.id,
                        esc(&c.body)
                    )
                });
                let verb = if c.edited {
                    "commented (edited)"
                } else {
                    "commented"
                };
                b.push_str(&comment_box(
                    ctx,
                    &format!("c-{}", short(c.id)),
                    Some(c.author),
                    c.time,
                    verb,
                    &c.body,
                    edit,
                ));
            }
            What::Labeled { add, remove } => {
                let mut what = String::new();
                if !add.is_empty() {
                    what.push_str("added ");
                    what.extend(add.iter().map(|l| label(l)));
                }
                if !remove.is_empty() {
                    what.push_str(if add.is_empty() {
                        "removed "
                    } else {
                        " and removed "
                    });
                    what.extend(remove.iter().map(|l| label(l)));
                }
                event(&mut b, "", &actor, &what, &when);
            }
            What::Assigned { add, remove } => {
                let names = |ids: &[Oid]| {
                    ids.iter()
                        .map(|a| format!("<b>{}</b>", esc(&ctx.who(Some(*a)))))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                if !add.is_empty() {
                    event(
                        &mut b,
                        "",
                        &actor,
                        &format!("assigned {}", names(add)),
                        &when,
                    );
                }
                if !remove.is_empty() {
                    event(
                        &mut b,
                        "",
                        &actor,
                        &format!("unassigned {}", names(remove)),
                        &when,
                    );
                }
            }
            What::Status(Status::Closed) => event(
                &mut b,
                r#"<span class="ic bad">●</span>"#,
                &actor,
                "closed this",
                &when,
            ),
            What::Status(Status::Open) => event(
                &mut b,
                r#"<span class="ic ok">●</span>"#,
                &actor,
                "reopened this",
                &when,
            ),
        }
    }
    if ctx.can(Role::Contributor) {
        let status_button = if !moderates {
            String::new()
        } else if i.status == Status::Open {
            r#"<button class="btn danger" name="then" value="close">Close issue</button>"#.into()
        } else {
            r#"<button class="btn" name="then" value="reopen">Reopen issue</button>"#.into()
        };
        let _ = write!(
            b,
            r#"<div class="box"><div class="hd"><b>Add a comment</b></div><div class="bd pad"><form class="stack" method="post" action="{here}/comment">{}<textarea name="body" placeholder="Markdown"></textarea><div class="actions">{status_button}<button class="btn primary">Comment</button></div></form></div></div>"#,
            back(&here)
        );
    }
    b.push_str("</div><aside>");
    sidebar(ctx, &mut b, i, &here, moderates);
    b.push_str("</aside></div>");
    if !loaded.rejected.is_empty() {
        let _ = write!(
            b,
            r#"<p class="meta">Ignored {} operation(s) that weren't allowed; <code>fullgit issue show {}</code> lists them.</p>"#,
            loaded.rejected.len(),
            ctx.issues.of(id)
        );
    }
    Ok(ctx.page(req, &i.title, b))
}

fn sidebar(ctx: &Ctx, b: &mut String, i: &Issue, here: &str, moderates: bool) {
    b.push_str("<section><h3>Labels</h3>");
    if i.labels.is_empty() {
        b.push_str("None yet");
    }
    for l in &i.labels {
        b.push_str(&label(l));
    }
    let none_listed = issue::available(&ctx.trust).is_some_and(|l| l.is_empty());
    if moderates && none_listed {
        b.push_str(&label_picker(ctx, &i.labels));
    } else if moderates {
        let _ = write!(
            b,
            r#"<details><summary>Edit</summary><form class="stack" method="post" action="{here}/labels">{}{}<button class="btn">Save labels</button></form></details>"#,
            back(here),
            label_picker(ctx, &i.labels)
        );
    }
    b.push_str("</section><section><h3>Assignees</h3>");
    if i.assignees.is_empty() {
        b.push_str("No one");
    }
    for a in &i.assignees {
        let _ = write!(b, "<div>{}</div>", ctx.person(Some(*a)));
    }
    if moderates {
        let _ = write!(
            b,
            r#"<details><summary>Edit</summary><form class="stack" method="post" action="{here}/assign">{}"#,
            back(here)
        );
        for (id, person) in &ctx.trust.identities {
            let checked = if i.assignees.contains(id) {
                " checked"
            } else {
                ""
            };
            let _ = write!(
                b,
                r#"<label style="display:block"><input type="checkbox" name="assignee" value="{id}"{checked}> {}</label>"#,
                esc(&person.name)
            );
        }
        b.push_str(r#"<button class="btn">Save assignees</button></form></details>"#);
    }
    b.push_str("</section>");
    if moderates {
        let _ = write!(
            b,
            r#"<section><details><summary>Edit title and description</summary><form class="stack" method="post" action="{here}/edit">{}<input type="text" name="title" value="{}"><textarea name="body" rows="8">{}</textarea><button class="btn">Save</button></form></details></section>"#,
            back(here),
            esc(&i.title),
            esc(&i.body)
        );
    }
}

/// A bordered comment: header, rendered markdown, and maybe an edit form.
pub fn comment_box(
    ctx: &Ctx,
    anchor: &str,
    author: Option<Oid>,
    time: i64,
    verb: &str,
    body: &str,
    footer: Option<String>,
) -> String {
    let id = if anchor.is_empty() {
        String::new()
    } else {
        format!(r#" id="{anchor}""#)
    };
    let text = if body.trim().is_empty() {
        r#"<p class="meta"><i>No description.</i></p>"#.to_owned()
    } else {
        markdown(body)
    };
    format!(
        r#"<div class="box"{id}><div class="hd">{} {verb} on {}</div><div class="bd md">{text}{}</div></div>"#,
        ctx.person(author),
        date(time),
        footer.unwrap_or_default()
    )
}

/// A one-line timeline entry. `what` is HTML.
pub fn event(b: &mut String, icon: &str, actor: &str, what: &str, when: &str) {
    let _ = write!(
        b,
        r#"<div class="event">{icon}{actor} {what} · {when}</div>"#
    );
}

pub fn act(ctx: &Ctx, req: &Req, id: Oid, action: &str) -> Result<Resp> {
    let signer = ctx.signer()?;
    let (repo, trust) = (ctx.repo, &ctx.trust);
    let current = issue::load(repo, trust, id)?.model;
    let here = format!("/issues/{}", ctx.issues.of(id));
    let msg = match action {
        "comment" => {
            let body = req.field("body").unwrap_or_default().trim();
            let then = req.field("then");
            if body.is_empty() && then.is_none() {
                bail!("write a comment first");
            }
            if !body.is_empty() {
                issue::comment(repo, trust, signer, id, body)?;
            }
            match then {
                Some("close") => {
                    issue::set_status(repo, trust, signer, id, Status::Closed)?;
                    "Closed."
                }
                Some("reopen") => {
                    issue::set_status(repo, trust, signer, id, Status::Open)?;
                    "Reopened."
                }
                _ => "Commented.",
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
            issue::edit(repo, trust, signer, id, title, body)?;
            "Saved."
        }
        "labels" => {
            let want: BTreeSet<String> = chosen_labels(ctx, req)?.into_iter().collect();
            let add: Vec<_> = want.difference(&current.labels).cloned().collect();
            let remove: Vec<_> = current.labels.difference(&want).cloned().collect();
            if add.is_empty() && remove.is_empty() {
                bail!("nothing changed");
            }
            issue::label(repo, trust, signer, id, &add, &remove)?;
            "Labels saved."
        }
        "assign" => {
            let want = req
                .fields("assignee")
                .into_iter()
                .map(Oid::from_str)
                .collect::<Result<BTreeSet<_>, _>>()?;
            let add: Vec<_> = want.difference(&current.assignees).copied().collect();
            let remove: Vec<_> = current.assignees.difference(&want).copied().collect();
            if add.is_empty() && remove.is_empty() {
                bail!("nothing changed");
            }
            issue::assign(repo, trust, signer, id, &add, &remove)?;
            "Assignees saved."
        }
        "edit-comment" => {
            let comment = Oid::from_str(req.need("comment")?)?;
            issue::edit_comment(repo, trust, signer, id, comment, req.need("body")?)?;
            "Comment saved."
        }
        other => bail!("unknown action {other}"),
    };
    Ok(Resp::Redirect(with_param(&here, "msg", msg)))
}
