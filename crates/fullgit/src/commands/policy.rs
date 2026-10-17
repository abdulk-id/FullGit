//! `fullgit policy`: roles and groups.

use anyhow::{Result, bail};
use clap::Subcommand;
use fullgit_core::{Role, Trust, policy};
use git2::Repository;

use crate::{describe, me, resolve};

/// Identities are named by `me`, an email, or an id prefix.
#[derive(Subcommand)]
pub enum PolicyCmd {
    /// Create the policy, with you as owner. Writes .fullgit/root for you
    /// to commit.
    Init {
        /// More owners besides you.
        #[arg(long = "owner")]
        owners: Vec<String>,
    },
    /// Show roles and groups.
    Show,
    /// Give an identity a role: reader, contributor, maintainer or owner.
    Grant { who: String, role: Role },
    /// Take away an identity's role.
    Revoke { who: String },
    /// Manage named groups, e.g. who can read a secret.
    #[command(subcommand)]
    Group(GroupCmd),
}

#[derive(Subcommand)]
pub enum GroupCmd {
    Add { group: String, who: String },
    Remove { group: String, who: String },
}

pub fn run(repo: &Repository, cmd: PolicyCmd) -> Result<()> {
    match cmd {
        PolicyCmd::Init { owners } => {
            if let Some(root) = policy::root(repo)? {
                bail!("this repository already has policy {root}");
            }
            let trust = Trust::load_identities(repo)?;
            let (signer, me) = me(repo, &trust)?;
            let mut ids = vec![me];
            for who in &owners {
                ids.push(resolve(repo, &trust, who)?);
            }
            let root = policy::genesis(repo, &trust, &signer, &ids)?;
            let path = policy::write_root_file(repo, root)?;
            println!("created policy {root}");
            println!(
                "commit {} and run `fullgit sync`; other clones trust it after `fullgit init`",
                path.strip_prefix(repo.workdir().unwrap_or(&path))
                    .unwrap_or(&path)
                    .display()
            );
        }
        PolicyCmd::Show => {
            let trust = Trust::load(repo)?;
            let Some((root, policy)) = &trust.policy else {
                println!("no policy: nothing is restricted");
                return Ok(());
            };
            println!("policy {root}");
            for role in Role::ALL.iter().rev() {
                for (id, _) in policy.roles().iter().filter(|(_, r)| *r == role) {
                    println!("{role:<11}  {}", describe(&trust, *id));
                }
            }
            for (group, members) in &policy.groups {
                println!("group {group}");
                for id in members {
                    println!("  {}", describe(&trust, *id));
                }
            }
        }
        PolicyCmd::Grant { who, role } => {
            let trust = Trust::load(repo)?;
            let (signer, _) = me(repo, &trust)?;
            let id = resolve(repo, &trust, &who)?;
            policy::grant(repo, &trust, &signer, id, role)?;
            println!("{} is now {role}", describe(&trust, id));
        }
        PolicyCmd::Revoke { who } => {
            let trust = Trust::load(repo)?;
            let (signer, _) = me(repo, &trust)?;
            let id = resolve(repo, &trust, &who)?;
            policy::revoke(repo, &trust, &signer, id)?;
            println!(
                "revoked {}; operations they signed that this clone has already seen stay valid",
                describe(&trust, id)
            );
        }
        PolicyCmd::Group(cmd) => {
            let trust = Trust::load(repo)?;
            let (signer, _) = me(repo, &trust)?;
            match cmd {
                GroupCmd::Add { group, who } => {
                    let id = resolve(repo, &trust, &who)?;
                    policy::group_add(repo, &trust, &signer, &group, id)?;
                }
                GroupCmd::Remove { group, who } => {
                    let id = resolve(repo, &trust, &who)?;
                    policy::group_remove(repo, &trust, &signer, &group, id)?;
                }
            }
        }
    }
    Ok(())
}
