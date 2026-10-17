use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use fullgit_core::sync::{self, Outcome};
use fullgit_core::{
    Identity, Role, Signer, SshKeygenSigner, Trust, identity, model, policy, refs, remote, sign,
};
use git2::{Oid, Repository};

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
    /// Configure a remote so `git fetch` also fetches refs/fullgit/*, and
    /// trust the policy named by the committed .fullgit/root.
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
    Id(IdCmd),
    /// The policy: who may do what.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Low-level commands for inspecting and writing operation logs.
    #[command(subcommand)]
    Debug(DebugCmd),
}

/// Identities are named by `me`, an email, or an id prefix.
#[derive(Subcommand)]
enum IdCmd {
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

/// Identities are named by `me`, an email, or an id prefix.
#[derive(Subcommand)]
enum PolicyCmd {
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
enum GroupCmd {
    Add { group: String, who: String },
    Remove { group: String, who: String },
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
        Cmd::Init { remote } => init(&repo, &remote)?,
        Cmd::Sync { remote } => {
            // Without a key we can still fetch, fast-forward and push.
            let signer = SshKeygenSigner::from_git_config(&repo).ok();
            let report = sync::sync(&repo, &remote, signer.as_ref().map(|s| s as &dyn Signer))?;
            for (refname, outcome) in &report.refs {
                let name = refname.strip_prefix(refs::PREFIX).unwrap_or(refname);
                match outcome {
                    Outcome::UpToDate => {}
                    Outcome::New => println!("new           {name}"),
                    Outcome::FastForwarded => println!("updated       {name}"),
                    Outcome::Merged => println!("merged        {name}"),
                    Outcome::Rejected(why) => eprintln!("warning: skipped {name}: {why}"),
                }
            }
            println!("synced with {remote}");
        }
        Cmd::Id(cmd) => id(&repo, cmd)?,
        Cmd::Policy(cmd) => policy_cmd(&repo, cmd)?,
        Cmd::Debug(DebugCmd::Append {
            refname,
            kind,
            payload,
        }) => {
            let payload = serde_json::from_str(&payload).context("--payload is not valid JSON")?;
            let signer = signer(&repo)?;
            let id = fullgit_core::append(&repo, &refname, &signer, &kind, payload)?;
            println!("{id}");
        }
        Cmd::Debug(DebugCmd::Log { refname }) => {
            let refname = refs::qualify(&refname);
            let head = repo
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

fn init(repo: &Repository, remote: &str) -> Result<()> {
    if remote::install_fetch_refspec(repo, remote)? {
        println!("added fetch refspec {}", refs::fetch_refspec(remote));
    } else {
        println!("{remote} already fetches refs/fullgit/*");
    }
    // Fails if the committed root differs from the pinned one.
    let root = policy::root(repo)?;
    match (policy::pinned_root(repo)?, root) {
        (Some(pinned), _) => println!("trusting policy {pinned}"),
        (None, Some(committed)) => {
            policy::pin(repo, committed)?;
            println!(
                "trusting policy {committed} from {}; this clone will refuse a different one",
                policy::ROOT_FILE
            );
        }
        (None, None) => println!("no policy yet; `fullgit policy init` creates one"),
    }
    Ok(())
}

fn id(repo: &Repository, cmd: IdCmd) -> Result<()> {
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

fn policy_cmd(repo: &Repository, cmd: PolicyCmd) -> Result<()> {
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

fn signer(repo: &Repository) -> Result<SshKeygenSigner> {
    SshKeygenSigner::from_git_config(repo)
        .context("fullgit signs with git's user.signingkey (an SSH key)")
}

/// Your signer and the identity holding its key.
fn me(repo: &Repository, trust: &Trust) -> Result<(SshKeygenSigner, Oid)> {
    let signer = signer(repo)?;
    match trust
        .identities_with_key(signer.public_key().key_data())
        .as_slice()
    {
        [id] => {
            let id = *id;
            Ok((signer, id))
        }
        [] => bail!("your signing key belongs to no identity; run `fullgit id create`"),
        ids => bail!(
            "your signing key belongs to several identities: {}",
            ids.iter().map(|i| short(*i)).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// `me`, an email, or an id prefix.
fn resolve(repo: &Repository, trust: &Trust, who: &str) -> Result<Oid> {
    if who == "me" {
        return Ok(me(repo, trust)?.1);
    }
    if who.contains('@') {
        let found: Vec<_> = trust
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
    let id = model::resolve::<Identity>(repo, who)?;
    if !trust.identities.contains_key(&id) {
        bail!("identity {id} is invalid");
    }
    Ok(id)
}

fn role_name(trust: &Trust, id: Oid) -> &'static str {
    trust.role(id).map_or("-", Role::as_str)
}

fn describe(trust: &Trust, id: Oid) -> String {
    match trust.identities.get(&id) {
        Some(i) => format!("{} {} <{}>", short(id), i.name, i.email),
        None => format!("{} (unknown identity)", short(id)),
    }
}

fn short(id: Oid) -> String {
    id.to_string()[..12].to_owned()
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
