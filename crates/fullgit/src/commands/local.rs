//! `fullgit local`: per-user files encrypted in your own snapshot ref.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Subcommand;
use fullgit_core::local::{self, Saved};
use fullgit_core::secret::DecryptionKey;
use fullgit_core::{Trust, sign};
use git2::Repository;

use crate::commands::secret::repo_relative;
use crate::{current_user_with_signer, date, short_oid};

#[derive(Subcommand)]
pub enum LocalCmd {
    /// Mark files as per-user: ignored by git, and kept in your own
    /// encrypted snapshot instead. Commit .gitattributes and .gitignore.
    Add {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// List per-user files, and whether they changed since you last saved.
    List,
    /// Save your per-user files as your new snapshot, encrypted to all your
    /// keys. `git push` does this too, when they changed.
    Save {
        /// Replace a snapshot saved from another device that this clone
        /// hasn't restored.
        #[arg(long)]
        force: bool,
    },
    /// Write your snapshot's files into the working tree. Files you changed
    /// here since you last saved or restored are kept, unless --force.
    Restore {
        #[arg(long)]
        force: bool,
        /// An earlier snapshot, from `fullgit local log`.
        #[arg(long)]
        from: Option<String>,
    },
    /// Your snapshots, newest first.
    Log,
}

/// Runs a `fullgit local` subcommand.
pub fn run(repo: &Repository, cmd: LocalCmd) -> Result<()> {
    match cmd {
        LocalCmd::Add { paths } => {
            let index = repo.index()?;
            for path in paths {
                let path = repo_relative(repo, &path)?;
                local::mark(repo, &path)?;
                println!("{path} is now a per-user file");
                if index.get_path(Path::new(&path), 0).is_some() {
                    eprintln!(
                        "warning: {path} is tracked by git; run `git rm --cached {path}` and \
                         commit (git history keeps what was committed)"
                    );
                }
            }
            println!("next: commit .gitattributes and .gitignore, and `fullgit local save`");
        }
        LocalCmd::List => {
            let trust = Trust::load_identities(repo)?;
            let (_, my_id) = current_user_with_signer(repo, &trust)?;
            let history = local::history(repo, &trust, my_id)?;
            let state = local::state(repo, my_id)?;
            let declared = local::declared(repo)?;
            let files = local::collect(repo, &declared.files)?;
            match history.latest() {
                Some(s) => println!(
                    "snapshot {} saved {} by key {}",
                    short_oid(s.id),
                    date(s.time),
                    sign::fingerprint(&s.signer)
                ),
                None => println!("no snapshot yet"),
            }
            if history.head.is_some() && history.head != state.base {
                println!("  saved from another device since; `fullgit local restore` gets it");
            }
            for (path, f) in &files {
                let status = match state.files.get(path) {
                    Some(h) if *h == f.hash() => "saved",
                    Some(_) => "changed",
                    None => "not saved",
                };
                println!("{path:<40} {status}");
            }
            for path in state.files.keys().filter(|p| !files.contains_key(*p)) {
                println!("{path:<40} missing; `fullgit local restore` brings it back");
            }
            for path in &declared.tracked {
                println!("{path:<40} tracked by git, so not saved; `git rm --cached` it");
            }
        }
        LocalCmd::Save { force } => {
            let trust = Trust::load_identities(repo)?;
            let (signer, my_id) = current_user_with_signer(repo, &trust)?;
            for path in local::declared(repo)?.tracked {
                eprintln!("warning: {path} is tracked by git, so not saved");
            }
            match local::save(repo, &trust, &signer, my_id, force)? {
                Saved::UpToDate => println!("up to date"),
                Saved::Saved { id, files } => println!(
                    "saved {files} file(s) as snapshot {}; `fullgit sync` pushes it",
                    short_oid(id)
                ),
                Saved::Behind => bail!(
                    "your per-user files were saved from another device since this clone last \
                     saved or restored;\nrun `fullgit local restore` first, or `fullgit local \
                     save --force` to replace that snapshot"
                ),
            }
        }
        LocalCmd::Restore { force, from } => {
            let trust = Trust::load_identities(repo)?;
            let (_, my_id) = current_user_with_signer(repo, &trust)?;
            let history = local::history(repo, &trust, my_id)?;
            let head = history
                .head
                .context("you have no snapshot yet; `fullgit local save` makes one")?;
            let snapshot = match &from {
                None => history
                    .latest()
                    .context("your snapshot ref holds no snapshot signed by you")?,
                Some(prefix) => {
                    let found: Vec<_> = history
                        .snapshots
                        .iter()
                        .filter(|s| s.id.to_string().starts_with(prefix.as_str()))
                        .collect();
                    match found.as_slice() {
                        [s] => *s,
                        [] => bail!("no snapshot {prefix}; see `fullgit local log`"),
                        _ => bail!("{prefix} matches several snapshots"),
                    }
                }
            };
            let key = DecryptionKey::from_git_config(repo)?;
            let files = snapshot.open(&key).map_err(|why| {
                anyhow!(
                    "can't open snapshot {}: {why}\nit is encrypted to {}; on a device holding \
                     one of those, `fullgit local save` re-encrypts it to all your current keys",
                    short_oid(snapshot.id),
                    snapshot.recipients.join(", ")
                )
            })?;
            let r = local::restore(repo, my_id, head, &files, force)?;
            for p in &r.written {
                println!("restored  {p}");
            }
            for (p, why) in &r.skipped {
                println!("skipped   {p}: {why}");
            }
            for p in &r.extra {
                println!("kept      {p}: not in the snapshot; saved next time");
            }
            if r.written.is_empty() && r.conflicts.is_empty() {
                println!("up to date");
            }
            if !r.conflicts.is_empty() {
                for p in &r.conflicts {
                    eprintln!("conflict  {p}: changed here and in the snapshot");
                }
                bail!(
                    "kept your versions; `fullgit local restore --force` takes the snapshot's, \
                     `fullgit local save --force` keeps yours"
                );
            }
        }
        LocalCmd::Log => {
            let trust = Trust::load_identities(repo)?;
            let (_, my_id) = current_user_with_signer(repo, &trust)?;
            let history = local::history(repo, &trust, my_id)?;
            for s in history.snapshots.iter().rev() {
                println!(
                    "{}  {}  key {}",
                    short_oid(s.id),
                    date(s.time),
                    sign::fingerprint(&s.signer)
                );
            }
            if history.ignored > 0 {
                eprintln!(
                    "warning: ignored {} operation(s) on your snapshot ref that you didn't sign",
                    history.ignored
                );
            }
        }
    }
    Ok(())
}
