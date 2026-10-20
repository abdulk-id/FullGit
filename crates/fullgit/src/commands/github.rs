//! `fullgit github`: copy issues and pull requests from GitHub.

use std::collections::BTreeMap;
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use fullgit_core::github::{self, Line, Note, RemoteIssue, RemotePr, RemoteState, Snapshot};
use fullgit_core::pr::Side;
use fullgit_core::{Issue, Trust, model};
use git2::{Oid, Repository};
use serde_json::Value;

use crate::{current_user_with_signer, short_oid};

/// GitHub is only read. Run `import` again to pick up changes there.
#[derive(Subcommand)]
pub enum GithubCmd {
    /// Copy issues and pull requests from GitHub into this repository.
    /// Nothing is written back. Run it again to update what was imported:
    /// title, description, labels, status, and those comments. Comments
    /// written here stay. A GitHub review is copied as a comment, not as an
    /// approval. `fullgit sync` shares the result.
    Import {
        /// Remote whose URL is the GitHub repository.
        #[arg(long, default_value = "origin")]
        remote: String,
        /// `owner/name`, when it isn't the remote's URL.
        #[arg(long)]
        repo: Option<String>,
    },
}

/// Runs a `fullgit github` subcommand.
pub fn run(repo: &Repository, cmd: GithubCmd) -> Result<()> {
    match cmd {
        GithubCmd::Import { remote, repo: name } => import(repo, &remote, name.as_deref()),
    }
}

fn import(repo: &Repository, remote: &str, name: Option<&str>) -> Result<()> {
    let trust = Trust::load(repo)?;
    model::needs_policy::<Issue>(&trust)?;
    let (signer, _) = current_user_with_signer(repo, &trust)?;
    let name = match name {
        Some(name) => github::parse_repo(name)
            .with_context(|| format!("{name:?} is not a GitHub repository (owner/name)"))?,
        None => {
            let url = remote_url(repo, remote)?;
            github::repo_from_url(&url)
                .with_context(|| format!("{remote} is not a GitHub repository ({url})"))?
        }
    };
    eprintln!("reading {name} from GitHub");
    let mut snapshot = fetch(&name)?;
    materialize(repo, remote, &mut snapshot);
    let report = github::import(repo, &signer, &snapshot)?;
    print_report(&report);
    Ok(())
}

fn remote_url(repo: &Repository, remote: &str) -> Result<String> {
    let remote = repo
        .find_remote(remote)
        .with_context(|| format!("no remote {remote}"))?;
    remote.url().map(str::to_owned).context("remote has no URL")
}

fn fetch(name: &str) -> Result<Snapshot> {
    let issues = api(&format!("repos/{name}/issues?state=all&per_page=100"))?;
    let comments = api(&format!("repos/{name}/issues/comments?per_page=100"))?;
    let pulls = api(&format!("repos/{name}/pulls?state=all&per_page=100"))?;
    let review_comments = api(&format!("repos/{name}/pulls/comments?per_page=100"))?;
    let pulls = as_array(pulls, "pull requests")?;
    let mut reviews = BTreeMap::new();
    for pull in &pulls {
        let Some(number) = number_of(pull) else {
            continue;
        };
        let page = api(&format!("repos/{name}/pulls/{number}/reviews?per_page=100"))?;
        reviews.insert(number, as_array(page, "reviews")?);
    }
    Ok(assemble(
        name,
        &as_array(issues, "issues")?,
        &as_array(comments, "comments")?,
        &pulls,
        &as_array(review_comments, "review comments")?,
        &reviews,
    ))
}

fn api(path: &str) -> Result<Value> {
    let out = Command::new("gh")
        .args(["api", "--paginate", path])
        .env("GH_PROMPT_DISABLED", "1")
        .output()
        .context("the GitHub bridge needs the `gh` command, logged in (`gh auth login`)")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim();
        bail!(
            "{}",
            if err.is_empty() {
                "gh api failed".to_owned()
            } else {
                err.to_owned()
            }
        );
    }
    let text = String::from_utf8(out.stdout).context("gh api did not return UTF-8")?;
    if text.trim().is_empty() {
        return Ok(Value::Array(Vec::new()));
    }
    serde_json::from_str(&text).with_context(|| format!("{path} was not JSON"))
}

fn as_array(value: Value, what: &str) -> Result<Vec<Value>> {
    match value {
        Value::Array(items) => Ok(items),
        _ => bail!("GitHub did not return a list of {what}"),
    }
}

fn materialize(repo: &Repository, remote: &str, snapshot: &mut Snapshot) {
    for pr in &mut snapshot.prs {
        if let Ok(tip) = github::fetch_branch_tip(repo, remote, &pr.target) {
            pr.target_tip = Some(tip);
        }
        let missing = pr.head.is_none_or(|head| repo.find_commit(head).is_err());
        let fetched = missing
            .then(|| github::fetch_pull_head(repo, remote, pr.number).ok())
            .flatten();
        if let Some(head) = pr.head
            && repo.find_commit(head).is_err()
        {
            let _ = github::fetch_sha(repo, remote, head);
            if repo.find_commit(head).is_err() {
                pr.head = fetched;
            }
        } else if pr.head.is_none() {
            pr.head = fetched;
        }
        if let Some(base) = pr.base_sha
            && repo.find_commit(base).is_err()
        {
            let _ = github::fetch_sha(repo, remote, base);
        }
        if let Some(merge) = pr.merge_commit
            && repo.find_commit(merge).is_err()
        {
            let _ = github::fetch_sha(repo, remote, merge);
        }
    }
}

fn print_report(report: &github::Report) {
    for label in &report.labels_added {
        match &label.github_name {
            Some(from) => println!("added label {}  ({from} on GitHub)", label.label),
            None => println!("added label {}", label.label),
        }
    }
    for (name, why) in &report.labels_skipped {
        eprintln!("warning: label {name}: {why}");
    }
    if report.entries.is_empty() && report.labels_added.is_empty() {
        println!("no issues or pull requests");
        return;
    }
    for entry in &report.entries {
        let kind = entry.kind.as_str();
        match &entry.change {
            github::Change::Created(id) => {
                println!("{kind} #{}  created  {}", entry.number, short_oid(*id));
            }
            github::Change::Updated(id) => {
                println!("{kind} #{}  updated  {}", entry.number, short_oid(*id));
            }
            github::Change::Unchanged(id) => {
                println!("{kind} #{}  unchanged  {}", entry.number, short_oid(*id));
            }
            github::Change::Skipped(why) => {
                eprintln!("warning: {kind} #{} skipped: {why}", entry.number);
            }
        }
        for note in &entry.notes {
            println!("  {note}");
        }
    }
    if report.wrote() {
        println!("`fullgit sync` shares what changed");
    }
}

fn assemble(
    repo: &str,
    issues: &[Value],
    comments: &[Value],
    pulls: &[Value],
    review_comments: &[Value],
    reviews: &BTreeMap<u64, Vec<Value>>,
) -> Snapshot {
    let mut issue_notes: BTreeMap<u64, Vec<Timed>> = BTreeMap::new();
    let mut pr_notes: BTreeMap<u64, Vec<Timed>> = BTreeMap::new();
    for comment in comments {
        let Some(number) = comment
            .get("issue_url")
            .and_then(Value::as_str)
            .and_then(trailing_number)
        else {
            continue;
        };
        let Some(id) = comment.get("id").and_then(Value::as_u64) else {
            continue;
        };
        let Some(body) = github::attributed(&login(comment), &text(comment, "body")) else {
            continue;
        };
        issue_notes.entry(number).or_default().push(Timed {
            at: timestamp(comment),
            note: Note {
                key: format!("comment:{id}"),
                body,
                line: None,
                reply_to: None,
            },
        });
    }
    for comment in review_comments {
        let Some(number) = comment
            .get("pull_request_url")
            .and_then(Value::as_str)
            .and_then(trailing_number)
        else {
            continue;
        };
        let Some(id) = comment.get("id").and_then(Value::as_u64) else {
            continue;
        };
        let Some(body) = github::attributed(&login(comment), &text(comment, "body")) else {
            continue;
        };
        let reply_to = comment
            .get("in_reply_to_id")
            .and_then(Value::as_u64)
            .map(|id| format!("line:{id}"));
        pr_notes.entry(number).or_default().push(Timed {
            at: timestamp(comment),
            note: Note {
                key: format!("line:{id}"),
                body,
                line: line_of(comment),
                reply_to,
            },
        });
    }
    for (number, list) in reviews {
        for review in list {
            let Some(id) = review.get("id").and_then(Value::as_u64) else {
                continue;
            };
            let state = review.get("state").and_then(Value::as_str).unwrap_or("");
            let Some(body) = review_text(&login(review), state, &text(review, "body")) else {
                continue;
            };
            pr_notes.entry(*number).or_default().push(Timed {
                at: timestamp(review),
                note: Note {
                    key: format!("review:{id}"),
                    body,
                    line: None,
                    reply_to: None,
                },
            });
        }
    }

    let pull_numbers: BTreeMap<u64, &Value> = pulls
        .iter()
        .filter_map(|p| number_of(p).map(|n| (n, p)))
        .collect();

    let mut remote_issues = Vec::new();
    for issue in issues {
        if issue.get("pull_request").is_some() {
            continue;
        }
        let Some(number) = number_of(issue) else {
            continue;
        };
        remote_issues.push(RemoteIssue {
            number,
            title: text(issue, "title"),
            body: text(issue, "body"),
            open: issue.get("state").and_then(Value::as_str) != Some("closed"),
            author: login(issue),
            url: text(issue, "html_url"),
            labels: label_names(issue),
            assignees: logins(issue, "assignees"),
            comments: take_notes(&mut issue_notes, number)
                .into_iter()
                .map(|t| t.note)
                .collect(),
        });
    }

    let mut remote_prs = Vec::new();
    for (number, pull) in pull_numbers {
        // Conversation comments were filed under the issue number. Pull
        // requests share GitHub's number space with issues.
        let mut notes = take_notes(&mut issue_notes, number);
        notes.append(&mut take_notes(&mut pr_notes, number));
        notes.sort_by(|a, b| (&a.at, &a.note.key).cmp(&(&b.at, &b.note.key)));
        let merged = pull.get("merged").and_then(Value::as_bool).unwrap_or(false)
            || pull.get("merged_at").is_some_and(Value::is_string);
        let state = if merged {
            RemoteState::Merged
        } else if pull.get("state").and_then(Value::as_str) == Some("closed") {
            RemoteState::Closed
        } else {
            RemoteState::Open
        };
        remote_prs.push(RemotePr {
            number,
            title: text(pull, "title"),
            body: text(pull, "body"),
            state,
            author: login(pull),
            url: text(pull, "html_url"),
            source: pull
                .pointer("/head/ref")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            source_owner: pull
                .pointer("/head/repo/owner/login")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            target: pull
                .pointer("/base/ref")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            draft: pull.get("draft").and_then(Value::as_bool).unwrap_or(false),
            merged_by: merged
                .then(|| pull.pointer("/merged_by/login").and_then(Value::as_str))
                .flatten()
                .map(str::to_owned),
            labels: label_names(pull),
            head: pull.pointer("/head/sha").and_then(sha),
            base_sha: pull.pointer("/base/sha").and_then(sha),
            target_tip: None,
            merge_commit: merged
                .then(|| pull.get("merge_commit_sha").and_then(sha))
                .flatten(),
            notes: notes.into_iter().map(|t| t.note).collect(),
        });
    }
    remote_issues.sort_by_key(|i| i.number);
    remote_prs.sort_by_key(|p| p.number);
    Snapshot {
        repo: repo.to_owned(),
        issues: remote_issues,
        prs: remote_prs,
    }
}

struct Timed {
    at: String,
    note: Note,
}

fn take_notes(map: &mut BTreeMap<u64, Vec<Timed>>, number: u64) -> Vec<Timed> {
    let mut notes = map.remove(&number).unwrap_or_default();
    notes.sort_by(|a, b| (&a.at, &a.note.key).cmp(&(&b.at, &b.note.key)));
    notes
}

fn review_text(author: &str, state: &str, body: &str) -> Option<String> {
    let author = author.trim().trim_start_matches('@');
    let who = if author.is_empty() {
        "Someone".to_owned()
    } else {
        format!("@{author}")
    };
    let body = body.trim();
    let head = match state {
        "APPROVED" => format!("{who} approved this pull request on GitHub."),
        "CHANGES_REQUESTED" => format!("{who} requested changes on GitHub."),
        "DISMISSED" => format!("{who} had a review dismissed on GitHub."),
        "COMMENTED" => return github::attributed(author, body),
        _ => return None,
    };
    if body.is_empty() {
        Some(head)
    } else {
        Some(format!("{head}\n\n{body}"))
    }
}

fn line_of(comment: &Value) -> Option<Line> {
    let path = comment.get("path").and_then(Value::as_str)?.to_owned();
    let line = comment
        .get("line")
        .and_then(Value::as_u64)
        .or_else(|| comment.get("original_line").and_then(Value::as_u64))?;
    let line = u32::try_from(line).ok()?;
    if path.is_empty() || line == 0 {
        return None;
    }
    let side = match comment.get("side").and_then(Value::as_str) {
        Some("LEFT") => Side::Old,
        _ => Side::New,
    };
    Some(Line { path, line, side })
}

fn number_of(value: &Value) -> Option<u64> {
    value.get("number").and_then(Value::as_u64)
}

fn trailing_number(url: &str) -> Option<u64> {
    url.rsplit('/').next()?.parse().ok()
}

fn login(value: &Value) -> String {
    value
        .pointer("/user/login")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn logins(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.get("login").and_then(Value::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn label_names(value: &Value) -> Vec<String> {
    value
        .get("labels")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.get("name").and_then(Value::as_str).or_else(|| v.as_str()))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn timestamp(value: &Value) -> String {
    ["submitted_at", "created_at", "updated_at"]
        .iter()
        .find_map(|key| value.get(key).and_then(Value::as_str))
        .unwrap_or("")
        .to_owned()
}

fn sha(value: &Value) -> Option<Oid> {
    let text = value.as_str()?;
    if text.len() != 40 {
        return None;
    }
    Oid::from_str(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn separates_issues_from_pull_requests() {
        let issues = vec![
            json!({
                "number": 4,
                "title": "Sync loses ops",
                "body": "Steps",
                "state": "open",
                "html_url": "https://github.com/acme/widgets/issues/4",
                "user": { "login": "octocat" },
                "labels": [{ "name": "good first issue" }],
                "assignees": [{ "login": "hubot" }]
            }),
            json!({
                "number": 5,
                "title": "A pull request, listed with the issues",
                "pull_request": { "url": "https://api.github.com/repos/acme/widgets/pulls/5" }
            }),
        ];
        let comments = vec![json!({
            "id": 9,
            "issue_url": "https://api.github.com/repos/acme/widgets/issues/4",
            "body": "reproduced",
            "created_at": "2026-10-18T00:00:00Z",
            "user": { "login": "ada" }
        })];
        let pulls = vec![json!({
            "number": 5,
            "title": "Retry sync",
            "body": "Back off",
            "state": "closed",
            "merged": true,
            "merged_at": "2026-10-19T00:00:00Z",
            "merge_commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "html_url": "https://github.com/acme/widgets/pull/5",
            "draft": false,
            "user": { "login": "octocat" },
            "merged_by": { "login": "ada" },
            "labels": [{ "name": "bug" }],
            "head": {
                "ref": "retry",
                "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "repo": { "owner": { "login": "fork" } }
            },
            "base": {
                "ref": "master",
                "sha": "cccccccccccccccccccccccccccccccccccccccc"
            }
        })];
        let review_comments = vec![json!({
            "id": 3,
            "pull_request_url": "https://api.github.com/repos/acme/widgets/pulls/5",
            "body": "here",
            "path": "src/sync.rs",
            "line": 12,
            "side": "LEFT",
            "created_at": "2026-10-18T01:00:00Z",
            "user": { "login": "ada" }
        })];
        let mut reviews = BTreeMap::new();
        reviews.insert(
            5,
            vec![
                json!({
                    "id": 7,
                    "state": "APPROVED",
                    "body": "Ship it",
                    "submitted_at": "2026-10-18T02:00:00Z",
                    "user": { "login": "ada" }
                }),
                json!({
                    "id": 8,
                    "state": "COMMENTED",
                    "body": "",
                    "user": { "login": "ada" }
                }),
                json!({
                    "id": 1,
                    "state": "PENDING",
                    "body": "secret",
                    "user": { "login": "ada" }
                }),
            ],
        );
        let snapshot = assemble(
            "acme/widgets",
            &issues,
            &comments,
            &pulls,
            &review_comments,
            &reviews,
        );
        assert_eq!(snapshot.issues.len(), 1);
        let issue = &snapshot.issues[0];
        assert_eq!(issue.number, 4);
        assert_eq!(issue.comments.len(), 1);
        assert_eq!(issue.comments[0].body, "@ada: reproduced");
        assert_eq!(issue.labels, ["good first issue"]);
        assert!(issue.open);

        assert_eq!(snapshot.prs.len(), 1);
        let pr = &snapshot.prs[0];
        assert_eq!(pr.state, RemoteState::Merged);
        assert_eq!(pr.merged_by.as_deref(), Some("ada"));
        assert_eq!(pr.source, "retry");
        assert_eq!(pr.source_owner, "fork");
        assert_eq!(pr.target, "master");
        assert_eq!(pr.notes.len(), 2);
        assert_eq!(pr.notes[0].key, "line:3");
        assert_eq!(pr.notes[0].line.as_ref().unwrap().side, Side::Old);
        assert_eq!(pr.notes[0].line.as_ref().unwrap().line, 12);
        assert!(pr.notes[1].body.contains("approved this pull request"));
        assert!(pr.notes[1].body.contains("Ship it"));
    }
}
