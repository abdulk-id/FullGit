//! `fullgit id`: create and manage signing identities.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use fullgit_core::{Signer, SshKeygenSigner, Trust, identity, sign};
use git2::{Oid, Repository};
use ssh_key::public::KeyData;

use crate::{
    current_user_with_signer, resolve_identity, role_name, short_oid, signer_from_git_config,
};

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

/// Runs a `fullgit id` subcommand.
pub fn run(repo: &Repository, cmd: IdCmd) -> Result<()> {
    match cmd {
        IdCmd::Create { name, email } => {
            let signer: SshKeygenSigner = signer_from_git_config(repo)?;
            let trust: Trust = Trust::load_identities(repo)?;
            if let [existing, ..] = trust
                .identities_with_key(signer.public_key().key_data())
                .as_slice()
            {
                bail!("your signing key already belongs to identity {existing}");
            }
            let config = repo.config()?;
            let name: String = match name {
                Some(n) => n,
                None => config.get_string("user.name").context("pass --name")?,
            };
            let email: String = match email {
                Some(e) => e,
                None => config.get_string("user.email").context("pass --email")?,
            };
            let id: Oid = identity::create(repo, &signer, &name, &email)?;
            println!("created identity {id} for {name} <{email}>");
        }
        IdCmd::Show { who } => {
            let trust: Trust = Trust::load(repo)?;
            let id: Oid = resolve_identity(repo, &trust, &who)?;
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
            let trust: Trust = Trust::load(repo)?;
            for (id, i) in &trust.identities {
                println!(
                    "{}  {:<11}  {} <{}>",
                    short_oid(*id),
                    role_name(&trust, *id),
                    i.name,
                    i.email
                );
            }
            for (id, why) in &trust.invalid {
                eprintln!("warning: identity {} is invalid: {why}", short_oid(*id));
            }
        }
        IdCmd::Edit { name, email } => {
            if name.is_none() && email.is_none() {
                bail!("nothing to change; pass --name or --email");
            }
            let trust: Trust = Trust::load_identities(repo)?;
            let (signer, my_id) = current_user_with_signer(repo, &trust)?;
            identity::edit(repo, my_id, &signer, name.as_deref(), email.as_deref())?;
        }
        IdCmd::AddKey { key, proof } => {
            let trust: Trust = Trust::load_identities(repo)?;
            let (signer, my_id) = current_user_with_signer(repo, &trust)?;
            let (key, proof): (KeyData, String) = match (key, proof) {
                (Some(path), None) => {
                    let new: SshKeygenSigner = SshKeygenSigner::new(&path)?;
                    let proof: String = identity::prove(&new, my_id)?;
                    (new.public_key().key_data().clone(), proof)
                }
                (None, Some(path)) => parse_proof(&read_input(&path)?)?,
                _ => bail!("pass a key path or --proof"),
            };
            identity::add_key(repo, my_id, &signer, &key, &proof)?;
            println!("added {}", sign::fingerprint(&key));
        }
        IdCmd::Prove { identity: who } => {
            let trust: Trust = Trust::load_identities(repo)?;
            let id: Oid = resolve_identity(repo, &trust, &who)?;
            let signer: SshKeygenSigner = signer_from_git_config(repo)?;
            let proof: String = identity::prove(&signer, id)?;
            print!(
                "{}\n{proof}",
                sign::key_to_string(signer.public_key().key_data())
            );
        }
        IdCmd::RemoveKey { key } => {
            let trust: Trust = Trust::load_identities(repo)?;
            let (signer, my_id) = current_user_with_signer(repo, &trust)?;
            let current = &trust.identities[&my_id].keys;
            let key: KeyData = match current.iter().find(|k| sign::fingerprint(k) == key) {
                Some(k) => k.clone(),
                None => read_key(&key)?,
            };
            identity::remove_key(repo, my_id, &signer, &key)?;
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

fn read_key(path: &str) -> Result<KeyData> {
    let text: String = std::fs::read_to_string(path)
        .with_context(|| format!("{path} is neither a key file nor a current key's fingerprint"))?;
    Ok(sign::key_from_string(&text)?)
}

/// Splits `fullgit id prove` output into the key and the signature.
fn parse_proof(text: &str) -> Result<(KeyData, String)> {
    let (key, proof): (&str, &str) = text
        .trim_start()
        .split_once('\n')
        .context("a proof starts with the key on its own line")?;
    Ok((sign::key_from_string(key)?, proof.to_owned()))
}
