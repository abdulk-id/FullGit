//! Shared fixtures: throwaway repos and SSH keys, driven by the system `git`
//! and `ssh-keygen`.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use fullgit_core::{Model, ReplayContext, Role, SshKeygenSigner, StoredOp};
use git2::Repository;
use tempfile::TempDir;

/// A minimal entity: one last-writer-wins value and a grow-only tag set.
/// Under a policy, contributors set the value and tagging takes a
/// maintainer; without one, anyone may, so sync can be tested alone.
#[derive(Debug, Default, PartialEq)]
pub struct Register {
    pub value: String,
    pub tags: BTreeSet<String>,
}

impl Model for Register {
    const NAMESPACE: &'static str = "registers";
    const NEEDS_POLICY: bool = false;

    fn apply(&mut self, op: &StoredOp, ctx: &ReplayContext) -> Result<(), String> {
        let needs = if op.op.kind == "reg.tag" {
            Role::Maintainer
        } else {
            Role::Contributor
        };
        if ctx.trust.policy.is_some() {
            ctx.actor(op).require(needs)?;
        }
        let field = |k: &str| {
            op.op.payload[k]
                .as_str()
                .map(str::to_owned)
                .ok_or(format!("missing {k}"))
        };
        match (op.parents.is_empty(), op.op.kind.as_str()) {
            (true, "reg.create") => self.value = field("value")?,
            (true, kind) => return Err(format!("{kind} cannot create a register")),
            (false, "reg.set") => self.value = field("value")?,
            (false, "reg.tag") => {
                self.tags.insert(field("tag")?);
            }
            (false, kind) => return Err(format!("unknown operation {kind}")),
        }
        Ok(())
    }
}

pub fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

pub struct Fixture {
    pub dir: TempDir,
    /// The default key, from [`Fixture::new`].
    pub key: PathBuf,
}

impl Fixture {
    pub fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let key = keygen(dir.path(), "test");
        Self { dir, key }
    }

    pub fn signer(&self) -> SshKeygenSigner {
        SshKeygenSigner::new(&self.key).unwrap()
    }

    /// A signer with its own fresh key.
    pub fn new_signer(&self, name: &str) -> SshKeygenSigner {
        SshKeygenSigner::new(keygen(self.dir.path(), name)).unwrap()
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn repo(&self, name: &str) -> (PathBuf, Repository) {
        let path = self.path(name);
        git(self.dir.path(), &["init", "-q", path.to_str().unwrap()]);
        configure(&path);
        let repo = Repository::open(&path).unwrap();
        (path, repo)
    }

    pub fn bare(&self, name: &str) -> PathBuf {
        let path = self.path(name);
        git(
            self.dir.path(),
            &["init", "-q", "--bare", path.to_str().unwrap()],
        );
        path
    }

    pub fn clone(&self, remote: &Path, name: &str) -> (PathBuf, Repository) {
        let path = self.path(name);
        git(
            self.dir.path(),
            &[
                "clone",
                "-q",
                remote.to_str().unwrap(),
                path.to_str().unwrap(),
            ],
        );
        configure(&path);
        let repo = Repository::open(&path).unwrap();
        (path, repo)
    }
}

fn configure(path: &Path) {
    git(path, &["config", "user.name", "Test"]);
    git(path, &["config", "user.email", "test@example.com"]);
}

pub fn keygen(dir: &Path, name: &str) -> PathBuf {
    let key = dir.join(format!("id_{name}"));
    let status = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            &format!("{name}@example.com"),
            "-f",
        ])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    key
}
