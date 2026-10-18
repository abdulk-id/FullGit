//! Building pages: escaping, markdown, and the shared layout. Everything
//! users wrote goes through [`esc`] or [`markdown`].

use std::fmt::Write;

use git2::Oid;
use pulldown_cmark::{CowStr, Event, Options, Parser, Tag};

/// Escapes text for HTML element content and quoted attribute values.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Renders markdown. Raw HTML is shown as text, and links only keep
/// http(s), mailto and relative targets.
pub fn markdown(text: &str) -> String {
    let options =
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
    let events = Parser::new_ext(text, options).map(|e| match e {
        Event::Html(h) | Event::InlineHtml(h) => Event::Text(h),
        Event::Start(Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        }) => Event::Start(Tag::Link {
            link_type,
            dest_url: safe_url(dest_url),
            title,
            id,
        }),
        Event::Start(Tag::Image {
            link_type,
            dest_url,
            title,
            id,
        }) => Event::Start(Tag::Image {
            link_type,
            dest_url: safe_url(dest_url),
            title,
            id,
        }),
        e => e,
    });
    let mut out = String::new();
    pulldown_cmark::html::push_html(&mut out, events);
    out
}

fn safe_url(url: CowStr) -> CowStr {
    let lower = url.trim().to_ascii_lowercase();
    let scheme = lower.split_once(':').map(|(s, _)| s);
    let relative = scheme.is_none_or(|s| s.contains('/') || s.contains('?') || s.contains('#'));
    if relative || matches!(scheme, Some("http" | "https" | "mailto")) {
        url
    } else {
        CowStr::Borrowed("#")
    }
}

/// Percent-encodes a query parameter value.
pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

pub fn short(id: Oid) -> String {
    id.to_string()[..8].to_owned()
}

/// A round badge with the person's initial, coloured by their id.
pub fn avatar(name: &str, id: Option<Oid>) -> String {
    let hue = id.map_or(0, |id| u32::from(id.as_bytes()[0]) * 360 / 256);
    let initial = name.chars().next().unwrap_or('?').to_uppercase();
    format!(
        r#"<span class="avatar" style="--hue:{hue}">{}</span>"#,
        esc(&initial.to_string())
    )
}

pub fn state_badge(state: &str) -> String {
    let label = match state {
        "open" => "Open",
        "closed" => "Closed",
        "merged" => "Merged",
        s => s,
    };
    format!(r#"<span class="state {state}">{label}</span>"#)
}

/// A hidden field telling the POST handler where to go back to.
pub fn back(path: &str) -> String {
    format!(r#"<input type="hidden" name="back" value="{}">"#, esc(path))
}

pub struct Page<'a> {
    pub title: &'a str,
    pub repo: &'a str,
    /// Who is signed in, for the header.
    pub me: &'a str,
    /// Where the sync button returns to.
    pub path: &'a str,
    pub msg: Option<&'a str>,
    pub err: Option<&'a str>,
    pub body: String,
}

impl Page<'_> {
    pub fn render(&self) -> String {
        let mut flash = String::new();
        if let Some(m) = self.msg {
            let _ = write!(flash, r#"<div class="flash ok">{}</div>"#, esc(m));
        }
        if let Some(e) = self.err {
            let _ = write!(flash, r#"<div class="flash err">{}</div>"#, esc(e));
        }
        format!(
            r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · {repo}</title><style>{CSS}</style></head>
<body><header><div class="bar">
<a class="brand" href="/">fullgit</a><span class="repo">{repo}</span>
<nav><a href="/issues">Issues</a><a href="/prs">Pull requests</a><a href="/people">People</a><a href="/settings">Settings</a></nav>
<span class="spacer"></span><span class="me">{me}</span>
<form method="post" action="/sync">{back}<button class="btn">Sync</button></form>
</div></header>
<main>{flash}{body}</main></body></html>"#,
            title = esc(self.title),
            repo = esc(self.repo),
            me = self.me,
            back = back(self.path),
            body = self.body,
        )
    }
}

const CSS: &str = r#"
:root{--bg:#fff;--fg:#1f2328;--muted:#59636e;--line:#d1d9e0;--soft:#f6f8fa;--accent:#0969da;
--open:#1a7f37;--closed:#cf222e;--merged:#8250df;--add:#dafbe1;--del:#ffebe9;--addn:#ccffd8;--deln:#ffd7d5;
--hunk:#ddf4ff;--warn:#fff8c5}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#3d444d;
--soft:#151b23;--accent:#4493f8;--open:#3fb950;--closed:#f85149;--merged:#ab7df8;--add:#12261e;
--del:#25171c;--addn:#1d4428;--deln:#542426;--hunk:#121d2f;--warn:#2b2611}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{border-bottom:1px solid var(--line);background:var(--soft)}
.bar{max-width:1200px;margin:auto;display:flex;align-items:center;gap:16px;padding:10px 20px}
.brand{font-weight:700;color:var(--fg);font-size:16px}.repo{color:var(--muted)}
nav{display:flex;gap:14px}nav a{color:var(--fg)}.spacer{flex:1}.me{color:var(--muted)}
main{max-width:1200px;margin:auto;padding:20px}
h1{font-size:26px;font-weight:400;margin:0 0 6px}h1 .id{color:var(--muted)}
h2{font-size:16px;margin:0 0 10px}
.btn{font:inherit;padding:4px 12px;border:1px solid var(--line);border-radius:6px;background:var(--soft);color:var(--fg);cursor:pointer}
.btn:hover{border-color:var(--muted)}.btn.primary{background:var(--open);border-color:var(--open);color:#fff}
.btn.danger{color:var(--closed)}.btn:disabled{opacity:.5;cursor:not-allowed}
input[type=text],input[type=password],textarea,select{font:inherit;width:100%;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
textarea{min-height:90px;resize:vertical}
.flash{padding:10px 14px;border-radius:6px;margin-bottom:16px;border:1px solid var(--line)}
.flash.ok{background:var(--add)}.flash.err{background:var(--del)}
.state{display:inline-block;padding:3px 10px;border-radius:999px;color:#fff;font-size:13px;font-weight:600}
.state.open{background:var(--open)}.state.closed{background:var(--closed)}.state.merged{background:var(--merged)}
.meta{color:var(--muted);margin-bottom:16px}.meta b{color:var(--fg)}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin:16px 0}
.tabs a{padding:8px 14px;color:var(--fg);border:1px solid transparent;border-bottom:0;border-radius:6px 6px 0 0;margin-bottom:-1px}
.tabs a.on{border-color:var(--line);background:var(--bg);font-weight:600}
.list{border:1px solid var(--line);border-radius:6px}
.list .head{background:var(--soft);padding:10px 14px;border-bottom:1px solid var(--line);display:flex;gap:14px;align-items:center}
.list .head a{color:var(--muted)}.list .head a.on{color:var(--fg);font-weight:600}
.row{padding:10px 14px;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:flex-start}
.row:last-child{border-bottom:0}.row .t{font-weight:600;color:var(--fg);font-size:15px}.row .sub{color:var(--muted);font-size:12px}
.dot{width:10px;height:10px;border-radius:50%;margin-top:6px;flex:none}.dot.open{background:var(--open)}
.dot.closed{background:var(--closed)}.dot.merged{background:var(--merged)}
.empty{padding:30px;text-align:center;color:var(--muted)}
.label{display:inline-block;padding:0 8px;border-radius:999px;border:1px solid var(--line);font-size:12px;margin-left:4px;background:var(--soft)}
.pick label{display:inline-block;margin:0 10px 4px 0}
table.labels{border-collapse:collapse;width:100%;margin-bottom:12px}table.labels td{padding:6px 10px;border-bottom:1px solid var(--line)}
table.labels td:first-child{width:1%;white-space:nowrap;padding-right:24px}table.labels td:last-child{text-align:right}form.add{display:flex;gap:8px}form.add input{max-width:20em}
.chip{font-size:12px;color:var(--muted);margin-left:6px}.chip.ok{color:var(--open)}.chip.bad{color:var(--closed)}
.layout{display:grid;grid-template-columns:1fr 280px;gap:24px}@media (max-width:860px){.layout{grid-template-columns:1fr}}
aside section{border-bottom:1px solid var(--line);padding-bottom:12px;margin-bottom:12px}
aside h3{font-size:12px;color:var(--muted);margin:0 0 6px;font-weight:600}
.box{border:1px solid var(--line);border-radius:6px;margin-bottom:16px;background:var(--bg)}
.box>.hd{background:var(--soft);border-bottom:1px solid var(--line);padding:8px 14px;color:var(--muted);border-radius:6px 6px 0 0}
.box>.hd b{color:var(--fg)}.box>.bd{padding:4px 14px}.box>.bd.pad{padding:12px 14px}
.thread .reply{border-top:1px solid var(--line);padding:4px 14px}.thread .reply .who{color:var(--muted);font-size:12px;padding-top:6px}
.event{color:var(--muted);padding:6px 0 6px 16px;margin-left:16px;border-left:2px solid var(--line)}
.event b{color:var(--fg)}.event .ic{font-weight:700;margin-right:4px}.ic.ok{color:var(--open)}.ic.bad{color:var(--closed)}.ic.m{color:var(--merged)}
.avatar{display:inline-flex;width:20px;height:20px;border-radius:50%;align-items:center;justify-content:center;
background:hsl(var(--hue) 55% 45%);color:#fff;font-size:11px;font-weight:700;vertical-align:middle;margin-right:4px}
.md p{margin:8px 0}.md pre{background:var(--soft);padding:10px;border-radius:6px;overflow:auto}
.md code{background:var(--soft);padding:1px 4px;border-radius:4px;font-size:90%}.md pre code{padding:0}
.md img{max-width:100%}.md blockquote{margin:8px 0;padding:0 12px;color:var(--muted);border-left:3px solid var(--line)}
.md table{border-collapse:collapse}.md td,.md th{border:1px solid var(--line);padding:4px 8px}
form.stack>*{margin-bottom:8px}form.inline{display:inline}.actions{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap}
details summary{cursor:pointer;color:var(--muted)}details[open] summary{margin-bottom:8px}
.ready{border-left:4px solid var(--open)}.notready{border-left:4px solid var(--closed)}
.diff{border:1px solid var(--line);border-radius:6px;margin-bottom:16px;overflow:hidden}
.diff .file{background:var(--soft);padding:8px 14px;border-bottom:1px solid var(--line);font-family:ui-monospace,monospace;font-weight:600}
.diff table{width:100%;border-collapse:collapse;font:12px/20px ui-monospace,SFMono-Regular,Menlo,monospace}
.diff td{padding:0 8px;vertical-align:top}.diff td.n{width:1%;min-width:44px;text-align:right;color:var(--muted);user-select:none}
.diff td.n a{color:inherit}.diff td.c{white-space:pre-wrap;word-break:break-all}
.diff tr.add td{background:var(--add)}.diff tr.add td.n{background:var(--addn)}
.diff tr.del td{background:var(--del)}.diff tr.del td.n{background:var(--deln)}
.diff tr.hunk td{background:var(--hunk);color:var(--muted)}.diff tr.note>td{padding:8px;background:var(--soft);font:14px/1.5 system-ui,sans-serif}
.diff tr:target td{outline:2px solid var(--accent);outline-offset:-2px}
.diff .note .box{margin:4px 0;max-width:820px}.diff .msg{padding:10px 14px;color:var(--muted)}
pre.code{background:var(--soft);padding:8px 10px;margin:8px 0;border-radius:6px;font:12px/18px ui-monospace,monospace;overflow:auto}
pre.code .hl{background:var(--warn);display:inline-block;width:100%}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:start}@media (max-width:860px){.grid{grid-template-columns:1fr}}
form.search{display:flex;gap:8px;margin:0 0 16px;max-width:28em}form.search input{flex:1;width:auto;min-width:0}form.search button{flex:none}
.box.you{border-color:var(--accent)}
.person{display:flex;gap:16px;align-items:center;padding:10px 14px}
.person .who{flex:1;min-width:10em}.person .who .sub{margin-left:6px}
.person .mail{flex:1.4;min-width:8em}.person .role{width:7.5em;color:var(--muted)}
.person .keys{width:4.5em;color:var(--muted);white-space:nowrap}
.list>.person{border-bottom:1px solid var(--line)}.list>.person:last-child{border-bottom:0}
.veil{position:relative;display:inline-block;cursor:pointer}
.veil input{position:absolute;opacity:0;width:1px;height:1px}
.veil .masked,.veil .clear{position:relative}
.veil .clear{display:none}
.veil input:checked ~ .masked{display:none}
.veil input:checked ~ .clear{display:inline}
.veil .blur{filter:blur(6px);user-select:none;letter-spacing:.03em}
.veil .tip{display:none;position:absolute;left:0;top:calc(100% + 4px);z-index:3;background:var(--fg);color:var(--bg);
font-size:12px;line-height:1.3;font-weight:400;padding:3px 8px;border-radius:4px;white-space:nowrap}
.veil .masked:hover .tip,.veil .clear:hover .tip{display:block}
.veil input:focus-visible ~ .masked,.veil input:focus-visible ~ .clear{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
details.menu{position:relative;display:inline-block}
details.menu>summary{list-style:none;cursor:pointer;width:28px;height:28px;display:flex;align-items:center;justify-content:center;
border-radius:6px;border:1px solid transparent;color:var(--fg);user-select:none}
details.menu>summary::-webkit-details-marker{display:none}
details.menu>summary::marker{content:none}
details.menu>summary:hover,details.menu[open]>summary{background:var(--soft);border-color:var(--line);margin-bottom:0}
details.menu .pop{position:absolute;right:0;top:calc(100% + 4px);z-index:5;background:var(--bg);border:1px solid var(--line);
border-radius:6px;padding:12px;min-width:200px;box-shadow:0 8px 24px #0003}
details.menu .pop p{margin:0 0 8px;font-weight:600;color:var(--fg)}
details.menu .pop form{display:flex;flex-direction:column;gap:8px;margin:0}
details.menu .pop button{width:100%}
.revs a{display:block;padding:2px 0}.revs .cur{font-weight:600}
code.ref{background:var(--hunk);padding:1px 6px;border-radius:6px;font-size:12px}
"#;
