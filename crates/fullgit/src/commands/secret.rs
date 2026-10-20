//! `fullgit secret`: encrypted files, plus git filter and textconv drivers.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use fullgit_core::filter::{self, SecretFilter};
use fullgit_core::secret::{self, DecryptionKey, Rekeyed, Sealed};
use fullgit_core::{Signer, SshKeygenSigner, Trust, sign};
use git2::Repository;

use crate::signer_from_git_config;

#[derive(Subcommand)]
pub enum SecretCmd {
    /// Mark files as secrets of a policy group, in .gitattributes. Then
    /// `git add` them as usual; they are sealed on the way in.
    Add {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Policy group whose members can read them.
        #[arg(long)]
        group: String,
    },
    /// List secrets and whether they are sealed, current and readable.
    List,
    /// Reseal secrets to their group's current keys, e.g. after someone
    /// left the group. Stages the result; commit it.
    Rekey { paths: Vec<String> },
    /// Decrypt secrets that are still sealed in the working tree, e.g.
    /// after `fullgit init` in an existing clone, or after joining a group.
    Checkout,
}

/// Runs a `fullgit secret` subcommand.
pub fn run(repo: &Repository, cmd: SecretCmd) -> Result<()> {
    match cmd {
        SecretCmd::Add { paths, group } => {
            let trust = Trust::load(repo)?;
            secret::recipients(&trust, &group)?;
            for path in paths {
                let path = repo_relative(repo, &path)?;
                secret::mark(repo, &path, &group)?;
                println!("{path} is now a secret of {group}");
                if secret::committed_unsealed(repo, &path)? {
                    eprintln!(
                        "warning: {path} is already committed unencrypted; git history keeps \
                         those values, so rotate them"
                    );
                }
            }
            println!("next: git add .gitattributes and the files, and commit");
        }
        SecretCmd::List => {
            let trust = Trust::load(repo)?;
            let mine: Option<String> = signer_from_git_config(repo)
                .map(|s| sign::fingerprint(s.public_key().key_data()))
                .ok();
            for e in secret::entries(repo)? {
                let blob = repo.find_blob(e.blob)?;
                let state = match Sealed::parse(blob.content()) {
                    Err(_) => "NOT SEALED".to_owned(),
                    Ok(s) => {
                        let mut notes = Vec::new();
                        if let Err(why) = s.verify(&trust) {
                            notes.push(format!("untrusted: {why}"));
                        }
                        let current = secret::recipients(&trust, &e.group)
                            .map(|k| k.iter().map(sign::fingerprint).collect::<Vec<_>>());
                        if current.as_ref().is_ok_and(|c| *c != s.recipients) {
                            notes.push("needs rekey".into());
                        }
                        if mine.as_ref().is_some_and(|m| s.recipients.contains(m)) {
                            notes.push("readable by you".into());
                        }
                        notes.join(", ")
                    }
                };
                println!("{:<30} {:<16} {state}", e.path, e.group);
            }
        }
        SecretCmd::Rekey { paths } => {
            let trust = Trust::load(repo)?;
            let signer: SshKeygenSigner = signer_from_git_config(repo)?;
            let key = DecryptionKey::from_git_config(repo)?;
            let names = key_owners(&trust);
            let mut failed = false;
            for (path, outcome) in secret::rekey(repo, &trust, &signer, &key, &paths)? {
                match outcome {
                    Rekeyed::UpToDate => println!("up to date  {path}"),
                    Rekeyed::Resealed { lost } => {
                        println!("resealed    {path}");
                        let lost: Vec<_> = lost
                            .iter()
                            .map(|f| names.get(f).cloned().unwrap_or_else(|| f.clone()))
                            .collect();
                        if !lost.is_empty() {
                            println!(
                                "  rotate its values: {} could read earlier versions",
                                lost.join(", ")
                            );
                        }
                    }
                    Rekeyed::Failed(why) => {
                        failed = true;
                        eprintln!("failed      {path}: {why}");
                    }
                }
            }
            if failed {
                bail!("some secrets were not resealed");
            }
        }
        SecretCmd::Checkout => {
            let still = secret::checkout(repo)?;
            if !still.is_empty() {
                bail!("still sealed: {}", still.join(", "));
            }
        }
    }
    Ok(())
}

/// `filter.fullgit.process`.
pub fn filter_process(repo: &Repository) -> Result<()> {
    let mut filter = SecretFilter::new(repo);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    filter::serve(&mut stdin.lock(), &mut stdout.lock(), &mut filter)?;
    if !filter.left_sealed.is_empty() {
        eprintln!("fullgit: left these secrets encrypted:");
        for (path, why) in &filter.left_sealed {
            eprintln!("  {path}: {why}");
        }
        eprintln!("fullgit: once that's fixed, run `fullgit secret checkout`");
    }
    Ok(())
}

/// `diff.fullgit.textconv`: shows secrets decrypted in `git diff`.
pub fn textconv(repo: &Repository, file: &Path) -> Result<()> {
    use std::io::Write;
    let content = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let out = match Sealed::parse(&content) {
        Err(_) => content,
        Ok(sealed) => match SecretFilter::new(repo).open(&sealed) {
            Ok(plaintext) => plaintext,
            Err(why) => format!(
                "[fullgit secret of group {}, not shown: {why}]\n",
                sealed.group
            )
            .into_bytes(),
        },
    };
    std::io::stdout().write_all(&out)?;
    Ok(())
}

/// Fingerprint → who held that key, for messages.
fn key_owners(trust: &Trust) -> BTreeMap<String, String> {
    let mut names = BTreeMap::new();
    for i in trust.identities.values() {
        for k in i.all_keys() {
            names.insert(sign::fingerprint(&k), format!("{} <{}>", i.name, i.email));
        }
    }
    names
}

/// `path` (relative to the current directory) relative to the repository
/// root, with `/` separators. The file needn't exist.
pub(crate) fn repo_relative(repo: &Repository, path: &Path) -> Result<String> {
    let workdir = repo.workdir().context("a bare repository has no secrets")?;
    let workdir = workdir.canonicalize()?;
    let absolute = std::env::current_dir()?.canonicalize()?.join(path);
    let mut normal = PathBuf::new();
    for c in absolute.components() {
        match c {
            Component::ParentDir => {
                normal.pop();
            }
            Component::CurDir => {}
            c => normal.push(c),
        }
    }
    let relative = normal
        .strip_prefix(&workdir)
        .with_context(|| format!("{} is outside the repository", path.display()))?;
    let parts: Vec<_> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if parts.is_empty() {
        bail!("{} is the repository itself", path.display());
    }
    Ok(parts.join("/"))
}
