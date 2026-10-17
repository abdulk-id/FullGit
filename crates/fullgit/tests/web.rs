//! Phase 7: the local web UI, driven over HTTP.

mod cli;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use cli::common::{Fixture, git};
use cli::{fg_ok, user};

struct Server {
    child: Child,
    port: u16,
    token: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map_or("", |(_, v)| v.as_str())
    }
}

fn start(dir: &Path) -> Server {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fullgit"))
        .current_dir(dir)
        .args(["web", "--no-open"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let url = line.split_whitespace().last().unwrap();
    let rest = url.strip_prefix("http://127.0.0.1:").unwrap();
    let (port, token) = rest.split_once("/?token=").unwrap();
    Server {
        child,
        port: port.parse().unwrap(),
        token: token.to_owned(),
    }
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

impl Server {
    fn raw(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Reply {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\n");
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        stream.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).unwrap();
        let (head, body) = out.split_once("\r\n\r\n").unwrap();
        let mut lines = head.lines();
        let status = lines.next().unwrap().split_whitespace().nth(1).unwrap();
        let headers = lines
            .filter_map(|l| l.split_once(": "))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        Reply {
            status: status.parse().unwrap(),
            headers,
            body: body.to_owned(),
        }
    }

    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    fn cookie(&self) -> String {
        format!("fullgit_{}={}", self.port, self.token)
    }

    fn get(&self, path: &str) -> Reply {
        let r = self.raw(
            "GET",
            path,
            &[("Host", &self.host()), ("Cookie", &self.cookie())],
            "",
        );
        assert_eq!(r.status, 200, "GET {path}: {}", r.body);
        r
    }

    /// Posts a form and returns where it redirects to.
    fn post(&self, path: &str, form: &[(&str, &str)]) -> String {
        let body: Vec<String> = form
            .iter()
            .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
            .collect();
        let origin = format!("http://{}", self.host());
        let r = self.raw(
            "POST",
            path,
            &[
                ("Host", &self.host()),
                ("Cookie", &self.cookie()),
                ("Origin", &origin),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            &body.join("&"),
        );
        assert_eq!(r.status, 303, "POST {path}: {}", r.body);
        r.header("Location").to_owned()
    }
}

/// The value of the first `name="<name>" value="..."` in a page.
fn field(page: &str, name: &str) -> String {
    let marker = format!(r#"name="{name}" value=""#);
    let start = page.find(&marker).unwrap() + marker.len();
    page[start..].split('"').next().unwrap().to_owned()
}

#[test]
fn only_the_token_holder_gets_in() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    let alice = user(&fx, &remote, "alice");
    let s = start(&alice);
    let host = s.host();

    assert_eq!(s.raw("GET", "/", &[("Host", &host)], "").status, 403);
    let wrong = s.raw("GET", "/?token=nope", &[("Host", &host)], "");
    assert_eq!(wrong.status, 403);
    let login = s.raw(
        "GET",
        &format!("/issues?token={}", s.token),
        &[("Host", &host)],
        "",
    );
    assert_eq!((login.status, login.header("Location")), (303, "/issues"));
    let cookie = login.header("Set-Cookie");
    assert!(
        cookie.starts_with(&s.cookie())
            && cookie.contains("HttpOnly")
            && cookie.contains("SameSite=Strict"),
        "{cookie}"
    );

    // DNS rebinding: right cookie, wrong Host.
    let rebound = s.raw(
        "GET",
        "/",
        &[
            ("Host", &format!("evil.example:{}", s.port)),
            ("Cookie", &s.cookie()),
        ],
        "",
    );
    assert_eq!(rebound.status, 403);
    // Another site posting a form.
    let forged = s.raw(
        "POST",
        "/issues/new",
        &[
            ("Host", &host),
            ("Cookie", &s.cookie()),
            ("Origin", "http://evil.example"),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        "title=pwned",
    );
    assert_eq!(forged.status, 403);
    assert_eq!(fg_ok(&alice, &["issue", "list", "--all"]), "no issues\n");

    let home = s.get("/");
    assert!(home.body.contains("alice@example.com"), "{}", home.body);
    let csp = home.header("Content-Security-Policy");
    assert!(
        csp.contains("default-src 'none'") && !csp.contains("script"),
        "{csp}"
    );
    // Browsers send this page's origin with its forms only if the referrer
    // policy lets them; under `no-referrer` they send `Origin: null`.
    assert_eq!(home.header("Referrer-Policy"), "same-origin");
    let null = s.raw(
        "POST",
        "/issues/new",
        &[
            ("Host", &host),
            ("Cookie", &s.cookie()),
            ("Origin", "null"),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        "title=pwned",
    );
    assert_eq!(null.status, 403);
}

#[test]
fn issues_and_pull_requests_in_the_browser() {
    let fx = Fixture::new();
    let remote = fx.bare("remote.git");
    git(&remote, &["symbolic-ref", "HEAD", "refs/heads/master"]);
    let alice = user(&fx, &remote, "alice");
    let bob = user(&fx, &remote, "bob");
    std::fs::write(alice.join("lib.rs"), "fn a() {}\n").unwrap();
    git(&alice, &["add", "lib.rs"]);
    git(&alice, &["commit", "-q", "-m", "Start"]);
    fg_ok(&alice, &["policy", "init"]);
    git(&alice, &["add", ".fullgit/root"]);
    git(&alice, &["commit", "-q", "-m", "Policy"]);
    git(&alice, &["push", "-q", "origin", "HEAD:master"]);
    fg_ok(&alice, &["sync"]);
    fg_ok(
        &alice,
        &["policy", "grant", "bob@example.com", "contributor"],
    );
    fg_ok(&alice, &["policy", "protect", "master"]);
    fg_ok(&alice, &["sync"]);
    git(&bob, &["pull", "-q", "origin", "master"]);
    fg_ok(&bob, &["init"]);
    fg_ok(&bob, &["sync"]);
    git(&bob, &["checkout", "-q", "-b", "retry"]);
    std::fs::write(bob.join("lib.rs"), "fn a() {}\nfn retry() {}\n").unwrap();
    git(&bob, &["commit", "-q", "-am", "Retry"]);
    let out = fg_ok(
        &bob,
        &["pr", "new", "-t", "Retry sync", "--target", "master"],
    );
    let id = out.split_whitespace().nth(3).unwrap().to_owned();
    fg_ok(&bob, &["sync"]);

    let s = start(&alice);
    let back = s.post("/sync", &[("back", "/prs")]);
    assert!(back.starts_with("/prs?msg=Synced"), "{back}");
    let list = s.get("/prs").body;
    assert!(
        list.contains("Retry sync") && list.contains("needs 1 approval(s)"),
        "{list}"
    );

    // A line comment, written in markdown, with things that mustn't run.
    let page = format!("/prs/{id}/diff");
    let diff = s.get(&page).body;
    assert!(
        diff.contains("fn retry() {}") && diff.contains("at=n2&file=lib.rs"),
        "{diff}"
    );
    let form = s.get(&format!("{page}?r=1&at=n2&file=lib.rs")).body;
    let revision = field(&form, "revision");
    let nasty = "**Backoff?** <script>alert(1)</script> [x](javascript:alert(1)) <img src=x onerror=alert(1)>";
    let to = s.post(
        &format!("/prs/{id}/comment"),
        &[
            ("back", &format!("{page}?r=1")),
            ("body", nasty),
            ("path", "lib.rs"),
            ("line", "2"),
            ("side", "new"),
            ("revision", &revision),
        ],
    );
    assert!(to.starts_with(&format!("{page}?r=1&msg=Commented")), "{to}");
    let diff = s.get(&format!("{page}?r=1")).body;
    assert!(diff.contains("<strong>Backoff?</strong>"), "{diff}");
    for bad in ["<script>alert", r#"href="javascript:"#, "<img src=x"] {
        assert!(!diff.contains(bad), "{bad} in\n{diff}");
    }
    assert!(
        diff.contains("&lt;script&gt;") && diff.contains(r##"<a href="#">x</a>"##),
        "{diff}"
    );

    // Review and merge.
    s.post(
        &format!("/prs/{id}/review"),
        &[("back", "/"), ("verdict", "approve")],
    );
    let show = s.get(&format!("/prs/{id}")).body;
    assert!(
        show.contains("ready to merge: 1 of 1 approval(s)"),
        "{show}"
    );
    assert!(show.contains("commented on <a href="), "{show}");
    let to = s.post(&format!("/prs/{id}/merge"), &[("back", "/")]);
    assert!(to.contains("msg=merged%20pull%20request"), "{to}");
    let parents = git(&remote, &["log", "-1", "--format=%P", "master"]);
    assert_eq!(parents.split_whitespace().count(), 2, "{parents}");
    assert!(
        s.get(&format!("/prs/{id}"))
            .body
            .contains(r#"<span class="state merged">"#)
    );

    // An issue: opened, commented on and closed.
    let to = s.post(
        "/issues/new",
        &[
            ("back", "/issues/new"),
            ("title", "<b>Docs</b> are stale"),
            ("body", "See *README*"),
            ("labels", "docs"),
        ],
    );
    let issue = to
        .strip_prefix("/issues/")
        .unwrap()
        .split('?')
        .next()
        .unwrap()
        .to_owned();
    let page = s.get(&format!("/issues/{issue}")).body;
    assert!(
        page.contains("&lt;b&gt;Docs&lt;/b&gt; are stale") && page.contains("<em>README</em>"),
        "{page}"
    );
    assert!(!page.contains("<b>Docs</b>"), "{page}");
    let to = s.post(
        &format!("/issues/{issue}/edit"),
        &[("back", "/"), ("title", "<b>Docs</b> are stale")],
    );
    assert!(to.contains("err=nothing%20changed"), "{to}");
    s.post(
        &format!("/issues/{issue}/comment"),
        &[("back", "/"), ("body", "Fixed"), ("then", "close")],
    );
    assert!(fg_ok(&alice, &["issue", "list", "--closed"]).contains("Docs"));

    // Bob sees Alice's work from the command line.
    fg_ok(&alice, &["sync"]);
    fg_ok(&bob, &["sync"]);
    let show = fg_ok(&bob, &["pr", "show", &id]);
    assert!(
        show.contains("**Backoff?**") && show.contains("alice merged r1"),
        "{show}"
    );
}
