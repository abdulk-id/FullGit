//! `fullgit id`: identities.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use fullgit_core::{Signer, SshKeygenSigner, Trust, identity, sign};
use git2::Repository;

use crate::{me, resolve, role_name, short, signer};

/// Identities are named by `me`, an email, or an id prefix.
#[derive(Subcommand)]
pub enum IdCmd {
    /// Create an identity for your signing key (git's user.signingkey).
    Create {
        /// Defaults to git's user.name.
        #[arg(long)]
        name: Option<String>,
        /// Defaults to git's user.email.
        #[arg(long)]
        email: Option<String>,
    },
    /// Show an identity.
    Show {
        #[arg(default_value = "me")]
        who: String,
    },
    /// List all identities and their roles.
    List,
    /// Change your name or email.
    Edit {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        email: Option<String>,
    },
    /// Add a key to your identity, e.g. for another machine.
    ///
    /// Give the key's path if its private half (or ssh-agent) is available
    /// here. Otherwise run `fullgit id prove <your id>` on the other machine
    /// and pass its output with --proof.
    AddKey {
        /// Path to the key (private or .pub).
        key: Option<PathBuf>,
        /// Output of `fullgit id prove`, or `-` for stdin.
        #[arg(long, conflicts_with = "key")]
        proof: Option<PathBuf>,
    },
    /// Prove that your signing key may be added to an identity; prints a
    /// proof for `fullgit id add-key --proof` on a machine holding it.
    Prove { identity: String },
    /// Remove a key from your identity. Operations it signed so far stay
    /// yours; anything it signs later does not.
    RemoveKey {
        /// Path to the public key, or its SHA256 fingerprint.
        key: String,
    },
}

pub fn run(repo: &Repository, cmd: IdCmd) -> Result<()> {
    match cmd {
        IdCmd::Create { name, email } => {
            let signer = signer(repo)?;
            let trust = Trust::load_identities(repo)?;
            if let [existing, ..] = trust
                .identities_with_key(signer.public_key().key_data())
                .as_slice()
            {
                bail!("your signing key already belongs to identity {existing}");
            }
            let config = repo.config()?;
            let name = match name {
                Some(n) => n,
                None => config.get_string("user.name").context("pass --name")?,
            };
            let email = match email {
                Some(e) => e,
                None => config.get_string("user.email").context("pass --email")?,
            };
            let id = identity::create(repo, &signer, &name, &email)?;
            println!("created identity {id} for {name} <{email}>");
        }
        IdCmd::Show { who } => {
            let trust = Trust::load(repo)?;
            let id = resolve(repo, &trust, &who)?;
            let i = &trust.identities[&id];
            println!("identity {id}");
            println!("name     {}", i.name);
            println!("email    {}", i.email);
            println!("role     {}", role_name(&trust, id));
            for key in &i.keys {
                println!("key      {}", sign::fingerprint(key));
            }
            for (key, _) in &i.removed {
                println!("removed  {}", sign::fingerprint(key));
            }
        }
        IdCmd::List => {
            let trust = Trust::load(repo)?;
            for (id, i) in &trust.identities {
                println!(
                    "{}  {:<11}  {} <{}>",
                    short(*id),
                    role_name(&trust, *id),
                    i.name,
                    i.email
                );
            }
            for (id, why) in &trust.invalid {
                eprintln!("warning: identity {} is invalid: {why}", short(*id));
            }
        }
        IdCmd::Edit { name, email } => {
            if name.is_none() && email.is_none() {
                bail!("nothing to change; pass --name or --email");
            }
            let (signer, me) = me(repo, &Trust::load_identities(repo)?)?;
            identity::edit(repo, me, &signer, name.as_deref(), email.as_deref())?;
        }
        IdCmd::AddKey { key, proof } => {
            let (signer, me) = me(repo, &Trust::load_identities(repo)?)?;
            let (key, proof) = match (key, proof) {
                (Some(path), None) => {
                    let new = SshKeygenSigner::new(&path)?;
                    let proof = identity::prove(&new, me)?;
                    (new.public_key().key_data().clone(), proof)
                }
                (None, Some(path)) => parse_proof(&read_input(&path)?)?,
                _ => bail!("pass a key path or --proof"),
            };
            identity::add_key(repo, me, &signer, &key, &proof)?;
            println!("added {}", sign::fingerprint(&key));
        }
        IdCmd::Prove { identity: who } => {
            let trust = Trust::load_identities(repo)?;
            let id = resolve(repo, &trust, &who)?;
            let signer = signer(repo)?;
            let proof = identity::prove(&signer, id)?;
            print!(
                "{}\n{proof}",
                sign::key_to_string(signer.public_key().key_data())
            );
        }
        IdCmd::RemoveKey { key } => {
            let trust = Trust::load_identities(repo)?;
            let (signer, me) = me(repo, &trust)?;
            let current = &trust.identities[&me].keys;
            let key = match current.iter().find(|k| sign::fingerprint(k) == key) {
                Some(k) => k.clone(),
                None => read_key(&key)?,
            };
            identity::remove_key(repo, me, &signer, &key)?;
            println!("removed {}", sign::fingerprint(&key));
        }
    }
    Ok(())
}

fn read_input(path: &PathBuf) -> Result<String> {
    if path.as_os_str() == "-" {
        return Ok(std::io::read_to_string(std::io::stdin())?);
    }
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

fn read_key(path: &str) -> Result<ssh_key::public::KeyData> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("{path} is neither a key file nor a current key's fingerprint"))?;
    Ok(sign::key_from_string(&text)?)
}

/// Splits `fullgit id prove` output into the key and the signature.
fn parse_proof(text: &str) -> Result<(ssh_key::public::KeyData, String)> {
    let (key, proof) = text
        .trim_start()
        .split_once('\n')
        .context("a proof starts with the key on its own line")?;
    Ok((sign::key_from_string(key)?, proof.to_owned()))
}
