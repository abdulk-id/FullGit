//! `fullgit policy`: roles, groups, branch rules and labels.

use anyhow::{Result, bail};
use clap::Subcommand;
use fullgit_core::{Role, Trust, policy};
use git2::Repository;

use crate::commands::pr::tip;
use crate::{current_user_with_signer, describe, resolve_identity};

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
    /// Show roles, groups, branch rules and labels.
    Show,
    /// Give an identity a role: reader, contributor, maintainer or owner.
    Grant { who: String, role: Role },
    /// Take away an identity's role.
    Revoke { who: String },
    /// Manage named groups, e.g. who can read a secret.
    #[command(subcommand)]
    Group(GroupCmd),
    /// Require approvals to merge pull requests into a branch. `fullgit pr
    /// merge` enforces it; the host still decides who may push the branch.
    Protect {
        branch: String,
        /// Approvals of the latest revision, from people other than its
        /// authors.
        #[arg(long, default_value_t = 1)]
        approvals: u32,
        /// Only count approvals from this group.
        #[arg(long)]
        group: Option<String>,
        /// Whose copy of the branch marks where `fullgit verify` starts.
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    /// Remove a branch's merge rule.
    Unprotect { branch: String },
    /// Manage the labels issues may carry. Maintainers may too.
    #[command(subcommand)]
    Label(LabelCmd),
}

#[derive(Subcommand)]
pub enum LabelCmd {
    Add {
        #[arg(required = true)]
        labels: Vec<String>,
    },
    /// Issues that carry a removed label stop showing it.
    Remove {
        #[arg(required = true)]
        labels: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum GroupCmd {
    Add { group: String, who: String },
    Remove { group: String, who: String },
}

/// Runs a `fullgit policy` subcommand.
pub fn run(repo: &Repository, cmd: PolicyCmd) -> Result<()> {
    match cmd {
        PolicyCmd::Init { owners } => {
            if let Some(root) = policy::root(repo)? {
                bail!("this repository already has policy {root}");
            }
            let trust = Trust::load_identities(repo)?;
            let (signer, my_id) = current_user_with_signer(repo, &trust)?;
            let mut ids: Vec<git2::Oid> = vec![my_id];
            for who in &owners {
                ids.push(resolve_identity(repo, &trust, who)?);
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
            for (branch, rule) in &policy.rules {
                let from = rule
                    .group
                    .as_ref()
                    .map_or(String::new(), |g| format!(" from {g}"));
                println!(
                    "branch {branch}: merging takes {} approval(s){from}",
                    rule.approvals
                );
            }
            let labels: Vec<_> = policy.labels.iter().map(String::as_str).collect();
            match labels.is_empty() {
                true => println!("no labels"),
                false => println!("labels: {}", labels.join(", ")),
            }
        }
        PolicyCmd::Grant { who, role } => {
            let trust = Trust::load(repo)?;
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let id: git2::Oid = resolve_identity(repo, &trust, &who)?;
            policy::grant(repo, &trust, &signer, id, role)?;
            println!("{} is now {role}", describe(&trust, id));
        }
        PolicyCmd::Revoke { who } => {
            let trust = Trust::load(repo)?;
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let id: git2::Oid = resolve_identity(repo, &trust, &who)?;
            policy::revoke(repo, &trust, &signer, id)?;
            println!(
                "revoked {}; operations they signed that this clone has already seen stay valid",
                describe(&trust, id)
            );
        }
        PolicyCmd::Protect {
            branch,
            approvals,
            group,
            remote,
        } => {
            if approvals == 0 {
                bail!("use `fullgit policy unprotect {branch}`");
            }
            let trust = Trust::load(repo)?;
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            // Changing a rule keeps where it began.
            let since = match trust
                .policy
                .as_ref()
                .and_then(|(_, p)| p.rules.get(&branch))
            {
                Some(rule) => rule.since,
                None => tip(repo, &remote, &branch).ok(),
            };
            policy::protect(
                repo,
                &trust,
                &signer,
                &branch,
                approvals,
                group.as_deref(),
                since,
            )?;
            println!("merging into {branch} now takes {approvals} approval(s)");
        }
        PolicyCmd::Unprotect { branch } => {
            let trust = Trust::load(repo)?;
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            policy::protect(repo, &trust, &signer, &branch, 0, None, None)?;
            println!("{branch} has no merge rule");
        }
        PolicyCmd::Group(cmd) => {
            let trust = Trust::load(repo)?;
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            match cmd {
                GroupCmd::Add { group, who } => {
                    let id: git2::Oid = resolve_identity(repo, &trust, &who)?;
                    policy::group_add(repo, &trust, &signer, &group, id)?;
                }
                GroupCmd::Remove { group, who } => {
                    let id: git2::Oid = resolve_identity(repo, &trust, &who)?;
                    policy::group_remove(repo, &trust, &signer, &group, id)?;
                }
            }
        }
        PolicyCmd::Label(cmd) => {
            let trust = Trust::load(repo)?;
            let (signer, _) = current_user_with_signer(repo, &trust)?;
            let (labels, add) = match cmd {
                LabelCmd::Add { labels } => (labels, true),
                LabelCmd::Remove { labels } => (labels, false),
            };
            for l in &labels {
                match add {
                    true => policy::label_add(repo, &trust, &signer, l)?,
                    false => policy::label_remove(repo, &trust, &signer, l)?,
                };
            }
        }
    }
    Ok(())
}
