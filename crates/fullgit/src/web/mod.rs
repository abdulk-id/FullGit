//! `fullgit web`: a local web UI for issues, pull requests and people.
//!
//! It listens on 127.0.0.1 only, and answers only browsers holding the
//! random token printed at start: `?token=` once sets a cookie, which is
//! `SameSite=Strict`, so other sites can't make the browser act here. The
//! `Host` header must be the address served (against DNS rebinding), and
//! a POST's `Origin`, when sent, must be this server. Pages run no
//! scripts; the content security policy forbids them.
//!
//! Requests are served one at a time. GETs never change anything; each
//! POST does one thing and redirects back, with a message.

mod html;
mod issues;
mod prs;

use std::collections::BTreeMap;
use std::io::Read;

use anyhow::{Context, Result, bail};
use fullgit_core::sync::{self, Outcome};
use fullgit_core::{Role, Signer, SshKeygenSigner, Trust, issue, pr};
use git2::{Oid, Repository};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::me;
use html::{Page, esc, url_encode};

pub struct Options {
    pub port: u16,
    pub open: bool,
    pub remote: String,
}

pub fn serve(repo_path: &std::path::Path, opts: Options) -> Result<()> {
    let server = Server::http(("127.0.0.1", opts.port))
        .map_err(|e| anyhow::anyhow!("can't listen on port {}: {e}", opts.port))?;
    let port = server
        .server_addr()
        .to_ip()
        .context("not a TCP address")?
        .port();
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let url = format!("http://127.0.0.1:{port}/?token={token}");
    println!("serving {} at {url}", repo_path.display());
    println!("only this URL gets in; Ctrl-C stops the server");
    use std::io::Write;
    std::io::stdout().flush()?;
    if opts.open {
        open_browser(&url);
    }
    let app = App {
        repo_path: repo_path.to_owned(),
        token,
        port,
        remote: opts.remote,
    };
    for request in server.incoming_requests() {
        app.handle(request);
    }
    Ok(())
}

fn open_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

struct App {
    repo_path: std::path::PathBuf,
    token: String,
    port: u16,
    remote: String,
}

/// One parsed request.
pub struct Req {
    pub method: Method,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub form: Vec<(String, String)>,
}

impl Req {
    pub fn q(&self, key: &str) -> Option<&str> {
        self.query.get(key).map(String::as_str)
    }

    pub fn field(&self, key: &str) -> Option<&str> {
        self.form
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// A field that must be there, trimmed; empty counts as missing.
    pub fn need(&self, key: &str) -> Result<&str> {
        match self.field(key).map(str::trim) {
            Some(v) if !v.is_empty() => Ok(v),
            _ => bail!("{key} is empty"),
        }
    }

    pub fn fields(&self, key: &str) -> Vec<&str> {
        self.form
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

pub enum Resp {
    Html(u16, String),
    /// 303 See Other.
    Redirect(String),
}

/// What every page needs.
pub struct Ctx<'a> {
    pub repo: &'a Repository,
    pub trust: Trust,
    /// Your signer and identity, if your key has one.
    pub me: Option<(SshKeygenSigner, Oid)>,
    pub remote: &'a str,
    pub name: String,
}

impl Ctx<'_> {
    pub fn me_id(&self) -> Option<Oid> {
        self.me.as_ref().map(|(_, id)| *id)
    }

    pub fn signer(&self) -> Result<&SshKeygenSigner> {
        match &self.me {
            Some((s, _)) => Ok(s),
            None => bail!("your signing key belongs to no identity; run `fullgit id create`"),
        }
    }

    /// Whether you hold at least `role`.
    pub fn can(&self, role: Role) -> bool {
        self.me_id()
            .is_some_and(|id| self.trust.role(id) >= Some(role))
    }

    /// Whether you may manage something `author` opened.
    pub fn moderates(&self, author: Option<Oid>) -> bool {
        self.me_id().is_some_and(|me| Some(me) == author) && self.can(Role::Contributor)
            || self.can(Role::Maintainer)
    }

    /// A person's name, or a short id if their identity isn't known here.
    pub fn who(&self, id: Option<Oid>) -> String {
        crate::commands::issue::who(&self.trust, id)
    }

    /// Avatar and name.
    pub fn person(&self, id: Option<Oid>) -> String {
        let name = self.who(id);
        format!("{}<b>{}</b>", html::avatar(&name, id), esc(&name))
    }

    pub fn page(&self, req: &Req, title: &str, body: String) -> Resp {
        let me = match self.me_id() {
            Some(id) => {
                let role = crate::role_name(&self.trust, id);
                format!("{} {}", self.person(Some(id)), esc(role))
            }
            None => "read-only: your key has no identity".into(),
        };
        let path = match req
            .query
            .iter()
            .filter(|(k, _)| !matches!(k.as_str(), "msg" | "err"))
            .count()
        {
            0 => req.path.clone(),
            _ => format!("{}?{}", req.path, query_string(&req.query)),
        };
        Resp::Html(
            200,
            Page {
                title,
                repo: &self.name,
                me: &me,
                path: &path,
                msg: req.q("msg"),
                err: req.q("err"),
                body,
            }
            .render(),
        )
    }
}

fn query_string(q: &BTreeMap<String, String>) -> String {
    q.iter()
        .filter(|(k, _)| !matches!(k.as_str(), "msg" | "err"))
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

impl App {
    fn handle(&self, mut request: Request) {
        let response = match self.check(&request) {
            Err(why) => text(403, why),
            Ok(Some(redirect)) => redirect,
            Ok(None) => match self.parse(&mut request) {
                Err(e) => text(400, &format!("{e:#}")),
                Ok(req) => match self.route(&req) {
                    Ok(Resp::Html(status, body)) => html_response(status, body),
                    Ok(Resp::Redirect(to)) => redirect(&to),
                    Err(e) if req.method == Method::Post => {
                        redirect(&with_param(back_of(&req), "err", &format!("{e:#}")))
                    }
                    Err(e) => html_response(404, error_page(&format!("{e:#}"))),
                },
            },
        };
        let _ = request.respond(response);
    }

    /// Authenticates a request. `Ok(Some(_))` answers it right away: a
    /// valid `?token=` sets the cookie and redirects without it.
    fn check(
        &self,
        request: &Request,
    ) -> Result<Option<Response<std::io::Cursor<Vec<u8>>>>, &'static str> {
        let header = |name: &'static str| {
            request
                .headers()
                .iter()
                .find(|h| h.field.equiv(name))
                .map(|h| h.value.as_str().to_owned())
        };
        let host = header("Host").unwrap_or_default();
        let port = self.port;
        if host != format!("127.0.0.1:{port}") && host != format!("localhost:{port}") {
            return Err("unexpected Host header");
        }
        if *request.method() == Method::Post
            && let Some(origin) = header("Origin")
            && origin != format!("http://{host}")
        {
            return Err("cross-origin request refused");
        }
        let (path, query) = split_url(request.url());
        if let Some(t) = query.get("token") {
            if !same(t, &self.token) {
                return Err("wrong token; use the URL `fullgit web` printed");
            }
            let cookie = format!(
                "{}={}; HttpOnly; SameSite=Strict; Path=/",
                self.cookie(),
                self.token
            );
            // Keep the rest of the URL, so links with the token deep-link.
            let rest: BTreeMap<String, String> = query
                .iter()
                .filter(|(k, _)| *k != "token")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let to = match rest.is_empty() {
                true => path,
                false => format!("{path}?{}", query_string(&rest)),
            };
            return Ok(Some(redirect(&to).with_header(
                Header::from_bytes("Set-Cookie", cookie).expect("valid header"),
            )));
        }
        let cookies = header("Cookie").unwrap_or_default();
        let ok = cookies.split(';').any(|c| {
            c.trim()
                .split_once('=')
                .is_some_and(|(k, v)| k == self.cookie() && same(v, &self.token))
        });
        if !ok {
            return Err("open the URL `fullgit web` printed; it holds the access token");
        }
        Ok(None)
    }

    /// Cookies are shared across ports, so each server names its own.
    fn cookie(&self) -> String {
        format!("fullgit_{}", self.port)
    }

    fn parse(&self, request: &mut Request) -> Result<Req> {
        let (path, query) = split_url(request.url());
        let mut form = Vec::new();
        if *request.method() == Method::Post {
            let mut body = String::new();
            request
                .as_reader()
                .take(4 << 20)
                .read_to_string(&mut body)
                .context("reading the form")?;
            form = parse_pairs(&body);
        }
        Ok(Req {
            method: request.method().clone(),
            path,
            query,
            form,
        })
    }

    fn route(&self, req: &Req) -> Result<Resp> {
        let repo = Repository::open(&self.repo_path)?;
        let trust = Trust::load(&repo)?;
        let me = me(&repo, &trust).ok();
        let name = self
            .repo_path
            .file_name()
            .map_or_else(|| "repository".into(), |n| n.to_string_lossy().into_owned());
        let ctx = Ctx {
            repo: &repo,
            trust,
            me,
            remote: &self.remote,
            name,
        };
        let parts: Vec<&str> = req
            .path
            .trim_matches('/')
            .split('/')
            .filter(|p| !p.is_empty())
            .collect();
        let post = req.method == Method::Post;
        match (post, parts.as_slice()) {
            (false, []) => home(&ctx, req),
            (true, ["sync"]) => sync_now(&ctx, req),
            (false, ["issues"]) => issues::list(&ctx, req),
            (false, ["issues", "new"]) => issues::new_form(&ctx, req),
            (true, ["issues", "new"]) => issues::create(&ctx, req),
            (false, ["issues", id]) => issues::show(&ctx, req, issue::resolve(&repo, id)?),
            (true, ["issues", id, action]) => {
                issues::act(&ctx, req, issue::resolve(&repo, id)?, action)
            }
            (false, ["prs"]) => prs::list(&ctx, req),
            (false, ["prs", "new"]) => prs::new_form(&ctx, req),
            (true, ["prs", "new"]) => prs::create(&ctx, req),
            (false, ["prs", id]) => prs::show(&ctx, req, pr::resolve(&repo, id)?),
            (false, ["prs", id, "diff"]) => prs::diff(&ctx, req, pr::resolve(&repo, id)?),
            (true, ["prs", id, action]) => prs::act(&ctx, req, pr::resolve(&repo, id)?, action),
            _ => bail!("no page {}", req.path),
        }
    }
}

/// The overview: what's open, and who may do what.
fn home(ctx: &Ctx, req: &Req) -> Result<Resp> {
    let mut body = String::new();
    body.push_str(r#"<div class="grid"><div>"#);
    body.push_str(&prs::summary(ctx)?);
    body.push_str(&issues::summary(ctx)?);
    body.push_str("</div><div>");
    body.push_str(&people(ctx));
    body.push_str("</div></div>");
    Ok(ctx.page(req, "Overview", body))
}

fn people(ctx: &Ctx) -> String {
    let mut s =
        String::from(r#"<div class="box"><div class="hd"><b>People</b></div><div class="bd pad">"#);
    if ctx.me.is_none() {
        s.push_str(
            r#"<div class="flash err">Your signing key belongs to no identity, so this page is read-only. Run <code>fullgit id create</code>.</div>"#,
        );
    }
    let policy = ctx.trust.policy.as_ref().map(|(_, p)| p);
    if policy.is_none() {
        s.push_str("<p>No policy: everyone may do everything. <code>fullgit policy init</code> creates one.</p>");
    }
    s.push_str(
        r#"<table class="people"><tr><th>Name</th><th>Email</th><th>Role</th><th>Keys</th></tr>"#,
    );
    let mut people: Vec<_> = ctx.trust.identities.iter().collect();
    people.sort_by_key(|(id, i)| (std::cmp::Reverse(ctx.trust.role(**id)), i.name.clone()));
    for (id, i) in people {
        s.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            ctx.person(Some(*id)),
            esc(&i.email),
            esc(crate::role_name(&ctx.trust, *id)),
            i.keys.len()
        ));
    }
    s.push_str("</table>");
    if let Some(p) = policy {
        for (group, members) in &p.groups {
            let names: Vec<_> = members.iter().map(|m| esc(&ctx.who(Some(*m)))).collect();
            s.push_str(&format!(
                "<p>Group <b>{}</b>: {}</p>",
                esc(group),
                names.join(", ")
            ));
        }
        for (branch, rule) in &p.rules {
            let from = rule
                .group
                .as_ref()
                .map_or(String::new(), |g| format!(" from {}", esc(g)));
            s.push_str(&format!(
                r#"<p>Merging into <code class="ref">{}</code> takes {} approval(s){from}.</p>"#,
                esc(branch),
                rule.approvals
            ));
        }
    }
    s.push_str("</div></div>");
    s
}

fn sync_now(ctx: &Ctx, req: &Req) -> Result<Resp> {
    // Without a key we can still fetch, fast-forward and push.
    let signer = ctx.me.as_ref().map(|(s, _)| s as &dyn Signer);
    let report = sync::sync(ctx.repo, ctx.remote, signer)?;
    let count = |f: fn(&Outcome) -> bool| report.refs.values().filter(|o| f(o)).count();
    let new = count(|o| matches!(o, Outcome::New | Outcome::FastForwarded | Outcome::Merged));
    let skipped = count(|o| matches!(o, Outcome::Rejected(_)));
    let mut msg = format!("Synced with {}: {new} updated", ctx.remote);
    if skipped > 0 {
        msg.push_str(&format!(
            ", {skipped} skipped (run `fullgit sync` to see why)"
        ));
    }
    Ok(Resp::Redirect(with_param(back_of(req), "msg", &msg)))
}

/// Where a POST returns to: its `back` field, if it's a local path.
pub fn back_of(req: &Req) -> &str {
    match req.field("back") {
        Some(b) if b.starts_with('/') && !b.starts_with("//") && !b.contains('\\') => b,
        _ => "/",
    }
}

/// Adds `key=value` to a local URL, keeping its fragment last.
pub fn with_param(url: &str, key: &str, value: &str) -> String {
    let (base, frag) = url.split_once('#').map_or((url, ""), |(b, f)| (b, f));
    let sep = if base.contains('?') { '&' } else { '?' };
    let frag = if frag.is_empty() {
        String::new()
    } else {
        format!("#{frag}")
    };
    format!("{base}{sep}{key}={}{frag}", url_encode(value))
}

fn split_url(url: &str) -> (String, BTreeMap<String, String>) {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    (decode(path), parse_pairs(query).into_iter().collect())
}

fn parse_pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

/// Decodes `application/x-www-form-urlencoded` text.
fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => match (
                bytes.get(i + 1).and_then(hex),
                bytes.get(i + 2).and_then(hex),
            ) {
                (Some(hi), Some(lo)) => {
                    out.push(hi << 4 | lo);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: &u8) -> Option<u8> {
    (*b as char).to_digit(16).map(|d| d as u8)
}

/// Compares secrets in time independent of where they differ.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn security_headers<R: Read>(r: Response<R>) -> Response<R> {
    let csp = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' https: data:; \
               form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
    r.with_header(Header::from_bytes("Content-Security-Policy", csp).expect("valid header"))
        .with_header(Header::from_bytes("X-Frame-Options", "DENY").expect("valid header"))
        .with_header(Header::from_bytes("Referrer-Policy", "no-referrer").expect("valid header"))
        .with_header(Header::from_bytes("Cache-Control", "no-store").expect("valid header"))
}

fn html_response(status: u16, body: String) -> Response<std::io::Cursor<Vec<u8>>> {
    security_headers(
        Response::from_string(body)
            .with_status_code(status)
            .with_header(
                Header::from_bytes("Content-Type", "text/html; charset=utf-8")
                    .expect("valid header"),
            ),
    )
}

fn text(status: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    security_headers(
        Response::from_string(format!("{body}\n"))
            .with_status_code(status)
            .with_header(
                Header::from_bytes("Content-Type", "text/plain; charset=utf-8")
                    .expect("valid header"),
            ),
    )
}

fn redirect(to: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let location = Header::from_bytes("Location", to)
        .unwrap_or_else(|()| Header::from_bytes("Location", "/").expect("valid header"));
    security_headers(
        Response::from_string("")
            .with_status_code(303)
            .with_header(location),
    )
}

fn error_page(message: &str) -> String {
    format!(
        r#"<!doctype html><meta charset="utf-8"><title>fullgit</title><p>{}</p><p><a href="/">Back to the overview</a></p>"#,
        esc(message)
    )
}
