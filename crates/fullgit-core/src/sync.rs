//! `fullgit sync`: fetch the remote's `refs/fullgit/*`, merge each entity
//! into the local copy, and push. Never force-pushes, and never moves a
//! local ref backwards.

use std::collections::BTreeMap;
use std::process::Command;

use git2::{Oid, Repository};

use crate::entity::{self, Merged};
use crate::refs;
use crate::sign::Signer;
use crate::{Error, Result};

/// How many fetch-merge-push rounds to try when a push races another writer.
const MAX_ROUNDS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Only on the remote; created locally.
    New,
    FastForwarded,
    Merged,
    /// Local already contains the remote's operations.
    UpToDate,
    /// Not merged, and not pushed: the remote's version failed verification,
    /// or merging it needs a signing key. Overwriting the remote is left to
    /// a human; an older client could otherwise "repair" away operations in
    /// a format it doesn't understand yet.
    Rejected(String),
}

#[derive(Debug, Default)]
pub struct Report {
    /// Per local ref name, the result of the last round that touched it.
    pub refs: BTreeMap<String, Outcome>,
    pub pushed: bool,
}

/// Runs fetch → merge → push, retrying when the push loses a race.
///
/// `signer` is only needed to merge diverged entities. Without it, diverged
/// entities are reported as rejected and left for later.
pub fn sync(repo: &Repository, remote: &str, signer: Option<&dyn Signer>) -> Result<Report> {
    let mut report = Report::default();
    for _ in 0..MAX_ROUNDS {
        fetch(repo, remote)?;
        merge_tracking(repo, remote, signer, &mut report)?;
        let skip = report
            .refs
            .iter()
            .filter(|(_, o)| matches!(o, Outcome::Rejected(_)))
            .map(|(r, _)| r.as_str())
            .collect::<Vec<_>>();
        if push(repo, remote, &skip)? {
            report.pushed = true;
            return Ok(report);
        }
    }
    Err(Error::Conflict(format!(
        "push to {remote} kept being rejected after {MAX_ROUNDS} rounds"
    )))
}

pub fn fetch(repo: &Repository, remote: &str) -> Result<()> {
    git(
        repo,
        &[
            "fetch",
            "--quiet",
            "--prune",
            remote,
            &refs::fetch_refspec(remote),
        ],
    )
}

/// Pushes every local `refs/fullgit/*` ref except those in `skip`, without
/// forcing. Returns `false` if the remote rejected any ref (e.g. someone
/// else pushed first); the caller should fetch and merge again.
pub fn push(repo: &Repository, remote: &str, skip: &[&str]) -> Result<bool> {
    let mut names = Vec::new();
    for r in repo.references_glob(&format!("{}*", refs::PREFIX))? {
        if let Ok(name) = r?.name()
            && !skip.contains(&name)
        {
            names.push(name.to_owned());
        }
    }
    push_refs(repo, remote, &names)
}

/// Pushes the named local refs to the same names, without forcing. Returns
/// `false` if the remote rejected any.
pub fn push_refs(repo: &Repository, remote: &str, names: &[String]) -> Result<bool> {
    let specs: Vec<String> = names.iter().map(|n| format!("{n}:{n}")).collect();
    push_specs(repo, remote, &specs)
}

/// Pushes `src:dst` refspecs without forcing. Returns `false` if the remote
/// rejected any.
pub fn push_specs(repo: &Repository, remote: &str, specs: &[String]) -> Result<bool> {
    if specs.is_empty() {
        return Ok(true);
    }
    let mut args = vec!["push", "--porcelain", remote];
    args.extend(specs.iter().map(String::as_str));
    let out = git_output(repo, &args)?;
    // Porcelain lines start with a flag; `!` means rejected.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let rejected = stdout.lines().any(|l| l.starts_with('!'));
    if !out.status.success() && !rejected {
        return Err(git_error("push", &out));
    }
    Ok(!rejected)
}

/// Merges every fetched entity into its local ref.
pub fn merge_tracking(
    repo: &Repository,
    remote: &str,
    signer: Option<&dyn Signer>,
    report: &mut Report,
) -> Result<()> {
    let tracking = refs::remote_tracking_prefix(remote);
    let mut fetched = Vec::new();
    for r in repo.references_glob(&format!("{tracking}*"))? {
        let r = r?;
        if let (Ok(name), Some(id)) = (r.name(), r.target()) {
            let local = format!("{}{}", refs::PREFIX, &name[tracking.len()..]);
            fetched.push((local, id));
        }
    }

    for (local, remote_head) in fetched {
        if local.starts_with(refs::CODE_PREFIX) {
            report
                .refs
                .insert(local.clone(), code(repo, &local, remote_head)?);
            continue;
        }
        let outcome = match check(repo, &local, remote_head) {
            Err(reason) => Outcome::Rejected(reason),
            Ok(()) => match entity::merge(repo, &local, signer, remote_head) {
                Ok(Merged::Created(_)) => Outcome::New,
                Ok(Merged::UpToDate(_)) => Outcome::UpToDate,
                Ok(Merged::FastForwarded(_)) => Outcome::FastForwarded,
                Ok(Merged::Merged(_)) => Outcome::Merged,
                Err(e @ Error::NeedsSigner(_)) => Outcome::Rejected(e.to_string()),
                Err(e) => return Err(e),
            },
        };
        report.refs.insert(local, outcome);
    }
    Ok(())
}

/// Takes a code ref if it names its own target. Nothing else about it needs
/// checking: it only matters once a signed pull request names its commit.
fn code(repo: &Repository, local: &str, remote_head: Oid) -> Result<Outcome> {
    let named = &local[refs::CODE_PREFIX.len()..];
    if named != remote_head.to_string() {
        return Ok(Outcome::Rejected(format!("points at {remote_head}")));
    }
    if repo.find_commit(remote_head).is_err() {
        return Ok(Outcome::Rejected("not a commit".into()));
    }
    if repo.refname_to_id(local).is_ok() {
        return Ok(Outcome::UpToDate);
    }
    repo.reference(local, remote_head, false, "fullgit: code")?;
    Ok(Outcome::New)
}

/// Verifies the remote's version of an entity before it is allowed near the
/// local ref: every operation must be validly signed with consistent clocks,
/// the DAG must have a single root, and for `<namespace>/<id>` refs that
/// root must be `<id>`.
fn check(repo: &Repository, local: &str, remote_head: Oid) -> Result<(), String> {
    let mut heads = vec![remote_head];
    heads.extend(repo.refname_to_id(local).ok());
    let ops = entity::load(repo, &heads).map_err(|e| e.to_string())?;
    let roots: Vec<_> = ops.iter().filter(|o| o.parents.is_empty()).collect();
    if roots.len() != 1 {
        return Err(format!(
            "expected one root operation, found {}",
            roots.len()
        ));
    }
    let last = local.rsplit('/').next().unwrap_or_default();
    if let Ok(id) = Oid::from_str(last)
        && last.len() == 40
        && roots[0].id != id
    {
        return Err(format!("root is {}, but the ref names {id}", roots[0].id));
    }
    Ok(())
}

pub(crate) fn git(repo: &Repository, args: &[&str]) -> Result<()> {
    let out = git_output(repo, args)?;
    if out.status.success() {
        Ok(())
    } else {
        Err(git_error(args[0], &out))
    }
}

pub(crate) fn git_output(repo: &Repository, args: &[&str]) -> Result<std::process::Output> {
    Ok(Command::new("git")
        .arg("--git-dir")
        .arg(repo.path())
        .args(args)
        .output()?)
}

pub(crate) fn git_error(what: &str, out: &std::process::Output) -> Error {
    Error::Git(git2::Error::from_str(&format!(
        "git {what} failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}
