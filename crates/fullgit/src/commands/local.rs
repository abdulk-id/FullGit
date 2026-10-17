//! `fullgit local`: per-user files.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Subcommand;
use fullgit_core::local::{self, Saved};
use fullgit_core::secret::DecryptionKey;
use fullgit_core::{Trust, sign};
use git2::Repository;

use crate::commands::secret::repo_relative;
use crate::{me, short};

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
            let (_, me) = me(repo, &trust)?;
            let history = local::history(repo, &trust, me)?;
            let state = local::state(repo, me)?;
            let declared = local::declared(repo)?;
            let files = local::collect(repo, &declared.files)?;
            match history.latest() {
                Some(s) => println!(
                    "snapshot {} saved {} by key {}",
                    short(s.id),
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
            let (signer, me) = me(repo, &trust)?;
            for path in local::declared(repo)?.tracked {
                eprintln!("warning: {path} is tracked by git, so not saved");
            }
            match local::save(repo, &trust, &signer, me, force)? {
                Saved::UpToDate => println!("up to date"),
                Saved::Saved { id, files } => println!(
                    "saved {files} file(s) as snapshot {}; `fullgit sync` pushes it",
                    short(id)
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
            let (_, me) = me(repo, &trust)?;
            let history = local::history(repo, &trust, me)?;
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
                    short(snapshot.id),
                    snapshot.recipients.join(", ")
                )
            })?;
            let r = local::restore(repo, me, head, &files, force)?;
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
            let (_, me) = me(repo, &trust)?;
            let history = local::history(repo, &trust, me)?;
            for s in history.snapshots.iter().rev() {
                println!(
                    "{}  {}  key {}",
                    short(s.id),
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

/// `YYYY-MM-DD HH:MM UTC` for a Unix time.
fn date(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn formats_dates() {
        assert_eq!(super::date(0), "1970-01-01 00:00 UTC");
        assert_eq!(super::date(1_792_238_400), "2026-10-17 12:00 UTC");
        assert_eq!(super::date(951_782_400), "2000-02-29 00:00 UTC");
    }
}
