use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use fullgit_core::{SshKeygenSigner, refs, remote};
use git2::Repository;

#[derive(Parser)]
#[command(
    name = "fullgit",
    version,
    about = "Issues, PRs, permissions and secrets that travel with your git repo"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Configure a remote so `git fetch` also fetches refs/fullgit/*.
    Init {
        #[arg(default_value = "origin")]
        remote: String,
    },
    /// Push all refs/fullgit/* to a remote.
    Push {
        #[arg(default_value = "origin")]
        remote: String,
    },
    /// Low-level commands for inspecting and writing operation logs.
    #[command(subcommand)]
    Debug(DebugCmd),
}

#[derive(Subcommand)]
enum DebugCmd {
    /// Append a signed operation to an entity ref.
    Append {
        /// Ref, full or relative to refs/fullgit/ (e.g. `issues/test`).
        refname: String,
        /// Operation type, e.g. `issue.comment`.
        kind: String,
        /// JSON payload.
        #[arg(long, default_value = "null")]
        payload: String,
    },
    /// Print an entity's operations in replay order.
    Log { refname: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let repo = Repository::open_from_env().context("not inside a git repository")?;
    match cli.command {
        Cmd::Init { remote } => {
            if remote::install_fetch_refspec(&repo, &remote)? {
                println!("added fetch refspec {}", refs::fetch_refspec(&remote));
            } else {
                println!("{remote} already fetches refs/fullgit/*");
            }
        }
        Cmd::Push { remote } => {
            let status = Command::new("git")
                .args(["push", &remote, refs::PUSH_REFSPEC])
                .status()
                .context("running git push")?;
            if !status.success() {
                bail!("git push failed");
            }
        }
        Cmd::Debug(DebugCmd::Append {
            refname,
            kind,
            payload,
        }) => {
            let payload = serde_json::from_str(&payload).context("--payload is not valid JSON")?;
            let signer = SshKeygenSigner::from_git_config(&repo)?;
            let id = fullgit_core::append(&repo, &refname, &signer, &kind, payload)?;
            println!("{id}");
        }
        Cmd::Debug(DebugCmd::Log { refname }) => {
            let refname = refs::qualify(&refname);
            let head = repo
                .refname_to_id(&refname)
                .with_context(|| format!("no such ref {refname}"))?;
            for op in fullgit_core::load(&repo, &[head])? {
                let fingerprint = op.signer.fingerprint(Default::default());
                println!(
                    "{} lamport={} {} signer={fingerprint} payload={}",
                    op.id, op.op.lamport, op.op.kind, op.op.payload
                );
            }
        }
    }
    Ok(())
}
