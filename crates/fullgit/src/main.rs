mod commands;
mod web;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use fullgit_core::sync::{self, Outcome};
use fullgit_core::{
    Identity, Role, Signer, SshKeygenSigner, Trust, local, model, policy, refs, remote, secret,
    setup, sign,
};
use git2::{Oid, Repository};

#[derive(Parser)]
#[command(
    name = "fullgit",
    version,
    about = "Issues, PRs, permissions, secrets and per-user files that travel with your git repo"
)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

/// Top-level `fullgit` subcommands.
#[derive(Subcommand)]
enum CliCommand {
    /// Set up this clone: fetch refs/fullgit/* from a remote, trust the
    /// policy named by the committed .fullgit/root, and install the secret
    /// filter and hooks.
    Init {
        #[arg(default_value = "origin")]
        remote: String,
    },
    /// Fetch, merge and push all refs/fullgit/* with a remote.
    Sync {
        #[arg(default_value = "origin")]
        remote: String,
    },
    /// Identities: who you are, and the keys you sign with.
    #[command(subcommand)]
    Id(commands::id::IdCmd),
    /// The policy: who may do what.
    #[command(subcommand)]
    Policy(commands::policy::PolicyCmd),
    /// Secret files, encrypted to a policy group.
    #[command(subcommand)]
    Secret(commands::secret::SecretCmd),
    /// Per-user files, kept in your own encrypted snapshot.
    #[command(subcommand)]
    Local(commands::local::LocalCmd),
    /// Issues.
    #[command(subcommand)]
    Issue(commands::issue::IssueCmd),
    /// Pull requests and their review.
    #[command(subcommand)]
    Pr(commands::pr::PrCmd),
    /// Browse and work on issues and pull requests in your browser. Serves
    /// this clone on 127.0.0.1, to whoever has the URL it prints.
    Web {
        /// 0 picks a free port.
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Don't open a browser.
        #[arg(long)]
        no_open: bool,
        /// The remote that Sync and Merge use.
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    /// Check that every commit on a protected branch since it was
    /// protected was merged through a pull request. Uses this clone's copy:
    /// `git fetch` and `fullgit sync` first.
    Verify {
        /// The remote's default branch by default.
        branch: Option<String>,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    /// Check this clone's setup.
    Doctor,
    /// Low-level commands for inspecting and writing operation logs.
    #[command(subcommand)]
    Debug(DebugCmd),
    /// git's long-running filter process for secrets.
    #[command(hide = true)]
    FilterProcess,
    /// git's diff textconv for secrets.
    #[command(hide = true)]
    Textconv { file: PathBuf },
    /// Entry point for the hooks `fullgit init` installs.
    #[command(hide = true)]
    Hook {
        name: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

/// Hidden debugging subcommands.
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
    let cli: Cli = Cli::parse();
    let repo: Repository =
        Repository::open_from_env().context("not inside a git repository")?;
    match cli.command {
        CliCommand::Init { remote } => init(&repo, &remote)?,
        CliCommand::Sync { remote } => {
            // Without a key we can still fetch, fast-forward and push.
            let signer: Option<SshKeygenSigner> = SshKeygenSigner::from_git_config(&repo).ok();
            let report = sync::sync(&repo, &remote, signer.as_ref().map(|s| s as &dyn Signer))?;
            for (refname, outcome) in &report.refs {
                let name: &str = refname.strip_prefix(refs::PREFIX).unwrap_or(refname);
                match outcome {
                    Outcome::UpToDate => {}
                    Outcome::New => println!("new           {name}"),
                    Outcome::FastForwarded => println!("updated       {name}"),
                    Outcome::Merged => println!("merged        {name}"),
                    Outcome::Rejected(why) => eprintln!("warning: skipped {name}: {why}"),
                }
            }
            println!("synced with {remote}");
            if let Ok(trust) = Trust::load_identities(&repo)
                && let Ok((_, my_id)) = current_user_with_signer(&repo, &trust)
                && let Ok(head) = repo.refname_to_id(&local::refname(my_id))
                && local::state(&repo, my_id)?.base != Some(head)
            {
                println!(
                    "your per-user files were saved from another device; \
                     `fullgit local restore` brings them here"
                );
            }
        }
        CliCommand::Id(cmd) => commands::id::run(&repo, cmd)?,
        CliCommand::Policy(cmd) => commands::policy::run(&repo, cmd)?,
        CliCommand::Secret(cmd) => commands::secret::run(&repo, cmd)?,
        CliCommand::Local(cmd) => commands::local::run(&repo, cmd)?,
        CliCommand::Issue(cmd) => commands::issue::run(&repo, cmd)?,
        CliCommand::Pr(cmd) => commands::pr::run(&repo, cmd)?,
        CliCommand::Web {
            port,
            no_open,
            remote,
        } => {
            let path: PathBuf = repo.workdir().unwrap_or_else(|| repo.path()).to_owned();
            web::serve(
                &path,
                web::Options {
                    port,
                    open: !no_open,
                    remote,
                },
            )?;
        }
        CliCommand::Verify { branch, remote } => commands::pr::verify(&repo, branch, &remote)?,
        CliCommand::Doctor => commands::doctor::run(&repo)?,
        CliCommand::FilterProcess => commands::secret::filter_process(&repo)?,
        CliCommand::Textconv { file } => commands::secret::textconv(&repo, &file)?,
        CliCommand::Hook { name, args } => commands::hook::run(&repo, &name, &args)?,
        CliCommand::Debug(DebugCmd::Append {
            refname,
            kind,
            payload,
        }) => {
            let payload: serde_json::Value =
                serde_json::from_str(&payload).context("--payload is not valid JSON")?;
            let signer: SshKeygenSigner = signer_from_git_config(&repo)?;
            let id: Oid = fullgit_core::append(&repo, &refname, &signer, &kind, payload)?;
            println!("{id}");
        }
        CliCommand::Debug(DebugCmd::Log { refname }) => {
            let refname: String = refs::qualify(&refname);
            let head: Oid = repo
                .refname_to_id(&refname)
                .with_context(|| format!("no such ref {refname}"))?;
            for op in fullgit_core::load(&repo, &[head])? {
                println!(
                    "{} lamport={} {} signer={} payload={}",
                    op.id,
                    op.op.lamport,
                    op.op.kind,
                    sign::fingerprint(&op.signer),
                    op.op.payload
                );
            }
        }
    }
    Ok(())
}

/// Configures fetch refspecs, trusts policy, and installs git drivers and hooks.
fn init(repo: &Repository, remote: &str) -> Result<()> {
    if remote::install_fetch_refspec(repo, remote)? {
        println!("added fetch refspec {}", refs::fetch_refspec(remote));
    } else {
        println!("{remote} already fetches refs/fullgit/*");
    }
    // Fails if the committed root differs from the pinned one.
    let root: Option<Oid> = policy::root(repo)?;
    match (policy::pinned_root(repo)?, root) {
        (Some(pinned), _) => println!("trusting policy {pinned}"),
        (None, Some(committed)) => {
            policy::pin(repo, committed)?;
            println!(
                "trusting policy {committed} from {}; this clone will refuse a different one",
                policy::ROOT_FILE
            );
        }
        (None, None) => println!(
            "no policy yet; issues and pull requests need one. \
             `fullgit id create`, then `fullgit policy init`, creates it"
        ),
    }

    let exe: PathBuf = std::env::current_exe()?;
    setup::install_drivers(repo, &exe)?;
    println!("secret filter and diff driver run {}", exe.display());
    for name in setup::HOOKS {
        match setup::install_hook(repo, name, &exe)? {
            setup::Hook::Installed => println!("installed {name} hook"),
            setup::Hook::Unchanged => {}
            setup::Hook::Skipped(why) => eprintln!("warning: {name} hook: {why}"),
        }
    }
    let sealed: bool = secret::entries(repo)?.into_iter().any(|e| {
        repo.workdir()
            .and_then(|d| std::fs::read(d.join(&e.path)).ok())
            .is_some_and(|c| secret::Sealed::is_sealed(&c))
    });
    if sealed {
        println!(
            "some secrets are still encrypted; run `fullgit sync`, then `fullgit secret checkout`"
        );
    }
    Ok(())
}

/// Loads the SSH signer from git's `user.signingkey`.
pub(crate) fn signer_from_git_config(repo: &Repository) -> Result<SshKeygenSigner> {
    SshKeygenSigner::from_git_config(repo)
        .context("fullgit signs with git's user.signingkey (an SSH key)")
}

/// Your signer and the identity holding its key.
pub(crate) fn current_user_with_signer(
    repo: &Repository,
    trust: &Trust,
) -> Result<(SshKeygenSigner, Oid)> {
    let signer: SshKeygenSigner = signer_from_git_config(repo)?;
    let id: Oid = identity_of(trust, &signer)?;
    Ok((signer, id))
}

/// The identity holding `signer`'s key.
pub(crate) fn identity_of(trust: &Trust, signer: &dyn Signer) -> Result<Oid> {
    match trust
        .identities_with_key(signer.public_key().key_data())
        .as_slice()
    {
        [id] => Ok(*id),
        [] => bail!("your signing key belongs to no identity; run `fullgit id create`"),
        ids => bail!(
            "your signing key belongs to several identities: {}",
            ids.iter()
                .map(|i| short_oid(*i))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Resolves `me`, an email, or an id prefix to an identity oid.
pub(crate) fn resolve_identity(repo: &Repository, trust: &Trust, who: &str) -> Result<Oid> {
    if who == "me" {
        return Ok(current_user_with_signer(repo, trust)?.1);
    }
    if who.contains('@') {
        let found: Vec<Oid> = trust
            .identities
            .iter()
            .filter(|(_, i)| i.email.eq_ignore_ascii_case(who))
            .map(|(id, _)| *id)
            .collect();
        return match found.as_slice() {
            [id] => Ok(*id),
            [] => bail!("no identity has email {who}"),
            _ => bail!("several identities have email {who}; use an id"),
        };
    }
    let id: Oid = model::resolve::<Identity>(repo, who)?;
    if !trust.identities.contains_key(&id) {
        bail!("identity {id} is invalid");
    }
    Ok(id)
}

/// Human-readable role name for an identity, or `-` if none.
pub(crate) fn role_name(trust: &Trust, id: Oid) -> &'static str {
    trust.role(id).map_or("-", Role::as_str)
}

/// One-line summary of an identity for CLI output.
pub(crate) fn describe(trust: &Trust, id: Oid) -> String {
    match trust.identities.get(&id) {
        Some(i) => format!("{} {} <{}>", short_oid(id), i.name, i.email),
        None => format!("{} (unknown identity)", short_oid(id)),
    }
}

/// Short hex prefix of an object id for display.
pub(crate) fn short_oid(id: Oid) -> String {
    id.to_string()[..12].to_owned()
}

/// `YYYY-MM-DD HH:MM UTC` for a Unix time.
pub(crate) fn date(secs: i64) -> String {
    let (days, rem): (i64, i64) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z: i64 = days + 719_468;
    let era: i64 = z.div_euclid(146_097);
    let doe: i64 = z - era * 146_097;
    let yoe: i64 = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy: i64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp: i64 = (5 * doy + 2) / 153;
    let day: i64 = doy - (153 * mp + 2) / 5 + 1;
    let month: i64 = if mp < 10 { mp + 3 } else { mp - 9 };
    let year: i64 = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}

// Names kept for the web UI module (unchanged API).
pub(crate) use resolve_identity as resolve;
pub(crate) use signer_from_git_config as signer;

#[cfg(test)]
mod tests {
    #[test]
    fn formats_dates() {
        assert_eq!(super::date(0), "1970-01-01 00:00 UTC");
        assert_eq!(super::date(1_792_238_400), "2026-10-17 12:00 UTC");
        assert_eq!(super::date(951_782_400), "2000-02-29 00:00 UTC");
    }
}
