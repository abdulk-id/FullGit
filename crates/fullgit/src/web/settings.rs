//! The settings page: the labels issues may carry.

use std::collections::BTreeMap;
use std::fmt::Write;

use anyhow::{Result, bail};
use fullgit_core::{Role, issue, policy};

use super::html::{back, esc};
use super::issues::label;
use super::{Ctx, Req, Resp, with_param};

pub fn show(ctx: &Ctx, req: &Req) -> Result<Resp> {
    let mut b = String::from(
        r#"<h1>Settings</h1><div class="box"><div class="hd"><b>Labels</b></div><div class="bd pad">"#,
    );
    let Some(listed) = issue::available(&ctx.trust) else {
        b.push_str("<p>Without a policy, issues take any label. <code>fullgit policy init</code> creates one; its labels are then kept here.</p></div></div>");
        return Ok(ctx.page(req, "Settings", b));
    };
    let edit = ctx.can(Role::Maintainer);
    b.push_str(r#"<p class="meta">Issues may carry only these labels. Maintainers and owners change the list; sync shares it. A label taken off the list stops showing on its issues, and shows again if it comes back.</p>"#);

    // How many issues carry each label, listed or not.
    let mut used: BTreeMap<String, usize> = BTreeMap::new();
    let mut unlisted: BTreeMap<String, usize> = BTreeMap::new();
    for (_, loaded) in issue::all(ctx.repo, &ctx.trust)? {
        let Ok(l) = loaded else { continue };
        for x in &l.model.labels {
            *used.entry(x.clone()).or_default() += 1;
        }
        for x in &l.model.unlisted {
            *unlisted.entry(x.clone()).or_default() += 1;
        }
    }

    if listed.is_empty() {
        b.push_str("<p>No labels yet.</p>");
    } else {
        b.push_str(r#"<table class="labels">"#);
        for l in listed {
            let n = used.get(l).copied().unwrap_or(0);
            let remove = match edit {
                true => button("remove", l, "Remove", " danger"),
                false => String::new(),
            };
            let _ = write!(
                b,
                r#"<tr><td>{}</td><td class="meta">{n} issue(s)</td><td>{remove}</td></tr>"#,
                label(l)
            );
        }
        b.push_str("</table>");
    }
    if edit {
        let _ = write!(
            b,
            r#"<form class="add" method="post" action="/settings/labels">{}<input type="text" name="add" placeholder="New label" required><button class="btn">Add label</button></form>"#,
            back("/settings")
        );
    }
    if !unlisted.is_empty() {
        b.push_str(
            r#"<h2 style="margin-top:16px">On issues, but not listed</h2><table class="labels">"#,
        );
        for (l, n) in &unlisted {
            let add = match edit {
                true => button("add", l, "Add", ""),
                false => String::new(),
            };
            let _ = write!(
                b,
                r#"<tr><td><span class="label">{}</span></td><td class="meta">{n} issue(s)</td><td>{add}</td></tr>"#,
                esc(l)
            );
        }
        b.push_str("</table>");
    }
    b.push_str("</div></div>");
    Ok(ctx.page(req, "Settings", b))
}

/// A one-button form that adds or removes `label`.
fn button(field: &str, label: &str, text: &str, class: &str) -> String {
    format!(
        r#"<form class="inline" method="post" action="/settings/labels">{}<input type="hidden" name="{field}" value="{}"><button class="btn{class}">{text}</button></form>"#,
        back("/settings"),
        esc(label)
    )
}

pub fn labels(ctx: &Ctx, req: &Req) -> Result<Resp> {
    let signer = ctx.signer()?;
    let (repo, trust) = (ctx.repo, &ctx.trust);
    let msg = match (req.field("add").map(str::trim), req.field("remove")) {
        (Some(l), None) if !l.is_empty() => {
            policy::label_add(repo, trust, signer, l)?;
            format!("Added {l}. Sync shares it.")
        }
        (None, Some(l)) => {
            policy::label_remove(repo, trust, signer, l)?;
            format!("Removed {l}. Sync shares it.")
        }
        _ => bail!("name a label to add or remove"),
    };
    Ok(Resp::Redirect(with_param("/settings", "msg", &msg)))
}
