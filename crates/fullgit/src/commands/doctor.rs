//! `fullgit doctor`: checks this clone's setup.

use anyhow::Result;
use fullgit_core::secret::{self, DecryptionKey, Sealed};
use fullgit_core::{Signer, Trust, local, policy, refs, remote, setup, sign};
use git2::Repository;

use crate::{me, role_name};

#[derive(Default)]
struct Report {
    failed: bool,
}

impl Report {
    fn ok(&self, msg: impl std::fmt::Display) {
        println!("ok    {msg}");
    }
    fn warn(&self, msg: impl std::fmt::Display) {
        println!("warn  {msg}");
    }
    fn fail(&mut self, msg: impl std::fmt::Display) {
        self.failed = true;
        println!("FAIL  {msg}");
    }
}

pub fn run(repo: &Repository) -> Result<()> {
    let mut r = Report::default();

    for name in repo.remotes()?.iter().flatten().flatten() {
        if remote::is_legacy(repo, name)? {
            r.warn(format!(
                "remote {name} fetches refs/fullgit/* as remote branches named fullgit/...; \
                 run `fullgit init {name}` to move them out of the branch list"
            ));
        } else if remote::has_refspec(repo, name, &refs::fetch_refspec(name))? {
            r.ok(format!("remote {name} fetches refs/fullgit/*"));
        } else {
            r.warn(format!(
                "remote {name} doesn't fetch refs/fullgit/*; run `fullgit init {name}`"
            ));
        }
    }

    match crate::signer(repo) {
        Ok(s) => r.ok(format!(
            "signing key {}",
            sign::fingerprint(s.public_key().key_data())
        )),
        Err(e) => r.fail(format!("{e:#}")),
    }

    let trust = match Trust::load(repo) {
        Ok(t) => Some(t),
        Err(e) => {
            r.fail(format!("loading identities and policy: {e}"));
            None
        }
    };
    if let Some(trust) = &trust {
        match me(repo, trust) {
            Ok((_, id)) => r.ok(format!(
                "identity {} ({})",
                &id.to_string()[..12],
                role_name(trust, id)
            )),
            Err(e) => r.warn(format!("{e:#}")),
        }
        match (&trust.policy, policy::pinned_root(repo)?) {
            (Some((root, _)), Some(_)) => r.ok(format!("policy {root} (pinned)")),
            (Some((root, _)), None) => r.warn(format!(
                "policy {root} is not pinned; run `fullgit init` to pin it"
            )),
            (None, _) => r.warn("no policy: nothing is restricted, and secrets are unavailable"),
        }
        for (id, why) in &trust.invalid {
            r.warn(format!("identity {id} is invalid: {why}"));
        }
    }

    match setup::drivers(repo)? {
        Some(cmd) => {
            let exe = cmd
                .trim_start_matches('\'')
                .split('\'')
                .next()
                .unwrap_or_default();
            if std::path::Path::new(exe).exists() {
                r.ok(format!("secret filter runs {exe}"));
            } else {
                r.fail(format!(
                    "secret filter runs {exe}, which doesn't exist; run `fullgit init`"
                ));
            }
        }
        None => r.warn("secret filter not configured; run `fullgit init`"),
    }
    for hook in setup::HOOKS {
        if setup::hook_installed(repo, hook)? {
            r.ok(format!("{hook} hook"));
        } else {
            r.warn(format!("{hook} hook not installed; run `fullgit init`"));
        }
    }

    let entries = secret::entries(repo)?;
    if !entries.is_empty() {
        match DecryptionKey::from_git_config(repo) {
            Ok(k) => r.ok(format!("decryption key {}", k.path.display())),
            Err(e) => r.warn(format!("can't decrypt secrets: {e}")),
        }
    }
    let workdir = repo.workdir();
    for e in entries {
        let blob = repo.find_blob(e.blob)?;
        let Ok(sealed) = Sealed::parse(blob.content()) else {
            r.fail(format!("{} is staged unencrypted", e.path));
            continue;
        };
        if let Some(trust) = &trust {
            if let Err(why) = sealed.verify(trust) {
                r.fail(format!("{}: {why}", e.path));
            }
            let current = secret::recipients(trust, &e.group)
                .map(|k| k.iter().map(sign::fingerprint).collect::<Vec<_>>());
            if current.is_ok_and(|c| c != sealed.recipients) {
                r.warn(format!("{} needs `fullgit secret rekey`", e.path));
            }
        }
        if let Some(dir) = workdir
            && std::fs::read(dir.join(&e.path)).is_ok_and(|c| Sealed::is_sealed(&c))
        {
            r.warn(format!("{} is still encrypted in the working tree", e.path));
        }
    }

    let declared = local::declared(repo)?;
    for p in &declared.tracked {
        r.fail(format!(
            "{p} is a per-user file tracked by git; run `git rm --cached {p}`"
        ));
    }
    for p in &declared.files {
        if !repo.is_path_ignored(p)? {
            r.warn(format!(
                "{p} is a per-user file but not ignored; add it to .gitignore"
            ));
        }
    }
    if let Some(trust) = &trust
        && let Ok((_, me)) = me(repo, trust)
    {
        let history = local::history(repo, trust, me)?;
        let state = local::state(repo, me)?;
        let files = local::collect(repo, &declared.files)?;
        if history.head.is_some() && history.head != state.base {
            r.warn("per-user files were saved from another device; run `fullgit local restore`");
        } else if local::hashes(&files) != state.files {
            r.warn(
                "per-user files changed since saved; `fullgit local save` or `git push` saves them",
            );
        } else if !files.is_empty() {
            r.ok(format!("{} per-user file(s) saved", files.len()));
        }
    }

    if r.failed {
        std::process::exit(1);
    }
    Ok(())
}
