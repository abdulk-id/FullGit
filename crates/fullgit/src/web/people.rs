//! The people page: who is registered, and the role an owner can give them.
//!
//! Emails are covered until clicked. The cover is other text, blurred, so
//! the address itself is not what shows through. The cover doesn't use a
//! script: it is a checkbox, and the menu is `<details>`.

use std::fmt::Write;

use anyhow::{Result, bail};
use fullgit_core::identity::Identity;
use fullgit_core::{Role, policy};
use git2::Oid;

use super::html::{avatar, back, escape_for_html, url_encode};
use super::{HandlerResult, PageContext, ParsedRequest, with_param};

pub fn show(ctx: &PageContext, req: &ParsedRequest) -> Result<HandlerResult> {
    let q = req.query_param("q").map(str::trim).filter(|q| !q.is_empty());
    let back_to = here(q);
    let mut b = String::from("<h1>People</h1>");
    if ctx.me.is_none() {
        b.push_str(
            r#"<div class="flash err">Your signing key belongs to no identity, so this page is read-only. Run <code>fullgit id create</code>.</div>"#,
        );
    }
    if let Some(id) = ctx.me
        && let Some(person) = ctx.trust.identities.get(&id)
    {
        b.push_str(
            r#"<div class="box you" id="you"><div class="hd"><b>You</b></div><div class="bd">"#,
        );
        b.push_str(&entry(ctx, id, person, true, &back_to));
        b.push_str("</div></div>");
    }
    let _ = write!(
        b,
        r#"<form class="search" method="get" action="/people"><input type="text" name="q" value="{}" placeholder="Search by name" aria-label="Search by name"><button class="btn">Search</button></form>"#,
        escape_for_html(q.unwrap_or(""))
    );
    b.push_str(r#"<div class="list"><div class="head"><b>All people</b></div>"#);
    let people = others(ctx, q);
    if people.is_empty() {
        let msg = match (q.is_some(), ctx.me.is_some()) {
            (true, true) => "No one else matches.",
            (true, false) => "No matches.",
            (false, true) => "No one else is registered.",
            (false, false) => "No one is registered.",
        };
        let _ = write!(b, r#"<div class="empty">{msg}</div>"#);
    } else {
        for (id, person) in people {
            b.push_str(&entry(ctx, id, person, false, &back_to));
        }
    }
    b.push_str("</div>");
    b.push_str(&policy_notes(ctx));
    Ok(ctx.page(req, "People", b))
}

/// Where a role change returns, keeping the current search.
fn here(q: Option<&str>) -> String {
    match q {
        Some(q) => format!("/people?q={}", url_encode(q)),
        None => "/people".to_owned(),
    }
}

/// Everyone except you, owners first, filtered by name when `q` is set.
fn others<'a>(ctx: &'a PageContext, q: Option<&str>) -> Vec<(Oid, &'a Identity)> {
    let q = q.map(str::to_lowercase);
    let mut people: Vec<_> = ctx
        .trust
        .identities
        .iter()
        .filter(|(id, _)| ctx.me != Some(**id))
        .filter(|(_, person)| {
            q.as_ref()
                .is_none_or(|q| person.name.to_lowercase().contains(q))
        })
        .map(|(id, person)| (*id, person))
        .collect();
    people.sort_by(|a, b| {
        ctx.trust
            .role(b.0)
            .cmp(&ctx.trust.role(a.0))
            .then_with(|| a.1.name.to_lowercase().cmp(&b.1.name.to_lowercase()))
            .then_with(|| a.0.cmp(&b.0))
    });
    people
}

/// One person. `you` pins them as "You" and always shows how many keys they have.
/// Everyone else's key count is shown only to an owner.
fn entry(ctx: &PageContext, id: Oid, person: &Identity, you: bool, back_to: &str) -> String {
    let who = match you {
        true => format!(
            r#"{}<b>You</b> <span class="sub">{}</span>"#,
            avatar(&person.name, Some(id)),
            escape_for_html(&person.name)
        ),
        false => format!(
            "{}<b>{}</b>",
            avatar(&person.name, Some(id)),
            escape_for_html(&person.name)
        ),
    };
    let keys = match you || ctx.can(Role::Owner) {
        true => format!(
            r#"<div class="keys">{}</div>"#,
            keys_label(person.keys.len())
        ),
        false => String::new(),
    };
    format!(
        r#"<div class="person"><div class="who">{who}</div><div class="mail">{}</div><div class="role">{}</div>{keys}{}</div>"#,
        veil(&person.email, id),
        escape_for_html(&role_label(ctx, id)),
        menu(ctx, id, back_to),
    )
}

fn role_label(ctx: &PageContext, id: Oid) -> String {
    match ctx.trust.role(id) {
        Some(role) => role.as_str().to_owned(),
        None => "no role".to_owned(),
    }
}

fn keys_label(n: usize) -> String {
    match n {
        1 => "1 key".to_owned(),
        n => format!("{n} keys"),
    }
}

/// The address, hidden behind blurred stand-in text until the box is ticked.
/// The stand-in is not the address, so the blur has nothing to give away.
fn veil(email: &str, id: Oid) -> String {
    format!(
        r#"<label class="veil"><input type="checkbox" aria-label="Show email"><span class="masked"><span class="blur">{}</span><span class="tip">Click to reveal email</span></span><span class="clear">{}<span class="tip">Click to hide email</span></span></label>"#,
        escape_for_html(&mask(email.chars().count(), id)),
        escape_for_html(email),
    )
}

/// `len` letters chosen from `id`, stable across reloads.
fn mask(len: usize, id: Oid) -> String {
    const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    let bytes = id.as_bytes();
    (0..len.max(1))
        .map(|i| {
            let b = usize::from(bytes[i % bytes.len()]);
            char::from(ALPHA[(b + i * 13) % ALPHA.len()])
        })
        .collect()
}

/// The role menu. Only an owner may change the policy, so only an owner sees it.
fn menu(ctx: &PageContext, id: Oid, back_to: &str) -> String {
    if !ctx.can(Role::Owner) {
        return String::new();
    }
    let current = ctx.trust.role(id);
    let mut options = String::new();
    for role in Role::ALL {
        let sel = if current == Some(role) {
            " selected"
        } else {
            ""
        };
        let _ = write!(
            options,
            r#"<option value="{role}"{sel}>{role}</option>"#,
            role = role.as_str()
        );
    }
    let sel = if current.is_none() { " selected" } else { "" };
    let _ = write!(options, r#"<option value=""{sel}>no role</option>"#);
    format!(
        r#"<details class="menu"><summary aria-label="Change role">⋯</summary><div class="pop"><p>Change role</p><form method="post" action="/people/role">{back}<input type="hidden" name="identity" value="{id}"><select name="role" aria-label="Role">{options}</select><button class="btn">Save</button></form></div></details>"#,
        back = back(back_to),
    )
}

pub fn set_role(ctx: &PageContext, req: &ParsedRequest) -> Result<HandlerResult> {
    if !ctx.can(Role::Owner) {
        bail!("only an owner can change someone's role");
    }
    let id = crate::resolve(ctx.repo, &ctx.trust, req.require_form_field("identity")?)?;
    let Some(raw) = req.form_field("role") else {
        bail!("name a role, or an empty one to remove it");
    };
    let desired = match raw.trim() {
        "" => None,
        name => Some(name.parse::<Role>().map_err(anyhow::Error::msg)?),
    };
    if ctx.trust.role(id) == desired {
        bail!("nothing changed");
    }
    let signer = ctx.signer()?;
    let who = ctx.who(Some(id));
    let msg = match desired {
        Some(role) => {
            policy::grant(ctx.repo, &ctx.trust, signer, id, role)?;
            format!("{who} is now {role}. Sync shares it.")
        }
        None => {
            policy::revoke(ctx.repo, &ctx.trust, signer, id)?;
            format!("Removed {who}'s role. Sync shares it.")
        }
    };
    Ok(HandlerResult::Redirect(with_param(super::back_of(req), "msg", &msg)))
}

/// Groups and branch rules, which used to sit in the overview's people panel.
fn policy_notes(ctx: &PageContext) -> String {
    let Some((_, p)) = &ctx.trust.policy else {
        return String::new();
    };
    if p.groups.is_empty() && p.rules.is_empty() {
        return String::new();
    }
    let mut s =
        String::from(r#"<div class="box"><div class="hd"><b>Policy</b></div><div class="bd pad">"#);
    for (group, members) in &p.groups {
        let names: Vec<_> = members
            .iter()
            .map(|m| escape_for_html(&ctx.who(Some(*m))))
            .collect();
        let _ = write!(
            s,
            "<p>Group <b>{}</b>: {}</p>",
            escape_for_html(group),
            names.join(", ")
        );
    }
    for (branch, rule) in &p.rules {
        let from = rule
            .group
            .as_ref()
            .map_or(String::new(), |g| format!(" from {}", escape_for_html(g)));
        let _ = write!(
            s,
            r#"<p>Merging into <code class="ref">{}</code> takes {} approval(s){from}.</p>"#,
            escape_for_html(branch),
            rule.approvals
        );
    }
    s.push_str("</div></div>");
    s
}
