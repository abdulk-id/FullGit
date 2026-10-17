//! `fullgit hook <name>`, called by the hooks `fullgit init` installs.

use std::io::BufRead;

use anyhow::{Result, bail};
use fullgit_core::local::{self, Saved};
use fullgit_core::{Trust, guard, refs, sync};
use git2::{Oid, Repository};

use crate::me;

pub fn run(repo: &Repository, name: &str, args: &[String]) -> Result<()> {
    match name {
        "pre-commit" => {
            let leaks = guard::in_index(repo)?;
            if !leaks.is_empty() {
                eprintln!("fullgit: refusing to commit:");
                for (path, leak) in &leaks {
                    eprintln!("  {path} ({})", leak.describe());
                }
                if leaks.iter().any(|(_, l)| *l == guard::Leak::Unsealed) {
                    eprintln!(
                        "unencrypted secrets: is the filter configured? run `fullgit init`, \
                         then `git add` them again"
                    );
                }
                if leaks.iter().any(|(_, l)| *l == guard::Leak::Local) {
                    eprintln!(
                        "per-user files are saved with `fullgit local save`, not committed; \
                         `git rm --cached` them"
                    );
                }
                std::process::exit(1);
            }
        }
        "pre-push" => {
            let remote = args.first().map(String::as_str).unwrap_or("origin");
            let tracking = format!("refs/remotes/{remote}/*");
            let mut found = Vec::new();
            let mut pushes_branches = false;
            for line in std::io::stdin().lock().lines() {
                let line = line?;
                let fields: Vec<&str> = line.split_whitespace().collect();
                let [_, local, remote_ref, remote_oid] = fields[..] else {
                    continue;
                };
                let local = Oid::from_str(local)?;
                // Pull requests' commits are code like any branch's.
                let code = remote_ref.starts_with(refs::CODE_PREFIX);
                if local.is_zero() || (remote_ref.starts_with(refs::PREFIX) && !code) {
                    continue; // a deletion, or fullgit's operations
                }
                pushes_branches |= !code;
                let hide = [Oid::from_str(remote_oid)?];
                found.extend(guard::in_commits(repo, local, &hide, &[&tracking])?);
            }
            if !found.is_empty() {
                eprintln!("fullgit: refusing to push commits with:");
                for (commit, path, leak) in &found {
                    eprintln!(
                        "  {} {path} ({})",
                        &commit.to_string()[..12],
                        leak.describe()
                    );
                }
                std::process::exit(1);
            }
            // A push of fullgit's refs alone is `fullgit sync`, or the push
            // below; saving there would recurse.
            if pushes_branches && let Err(e) = save_local(repo, remote) {
                eprintln!("fullgit: didn't save your per-user files: {e:#}");
            }
        }
        other => bail!("unknown hook {other}"),
    }
    Ok(())
}

/// Saves and pushes the per-user files if they changed. Never fails the
/// push it runs in.
fn save_local(repo: &Repository, remote: &str) -> Result<()> {
    if local::declared(repo)?.files.is_empty() {
        return Ok(());
    }
    let trust = Trust::load_identities(repo)?;
    let (signer, me) = me(repo, &trust)?;
    match local::save(repo, &trust, &signer, me, false)? {
        Saved::UpToDate => {}
        Saved::Behind => eprintln!(
            "fullgit: not saving your per-user files: they were saved from another device \
             since; run `fullgit local restore`, then `fullgit local save`"
        ),
        Saved::Saved { files, .. } => {
            if sync::push_refs(repo, remote, &[local::refname(me)])? {
                eprintln!("fullgit: saved {files} per-user file(s)");
            } else {
                eprintln!(
                    "fullgit: saved {files} per-user file(s), but couldn't push them; \
                     run `fullgit sync`"
                );
            }
        }
    }
    Ok(())
}
