//! Helpers for running the `fullgit` binary against throwaway repos.
#![allow(dead_code)]

#[path = "../../../fullgit-core/tests/common/mod.rs"]
pub mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::{Fixture, git, keygen};

pub struct Out {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

pub fn run(dir: &Path, program: &str, args: &[&str]) -> Out {
    run_with(dir, program, args, &[])
}

pub fn run_with(dir: &Path, program: &str, args: &[&str], env: &[(&str, &str)]) -> Out {
    let out = Command::new(program)
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_EDITOR")
        .envs(env.iter().copied())
        .output()
        .unwrap();
    Out {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

pub fn fg(dir: &Path, args: &[&str]) -> Out {
    run(dir, env!("CARGO_BIN_EXE_fullgit"), args)
}

pub fn fg_with(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Out {
    run_with(dir, env!("CARGO_BIN_EXE_fullgit"), args, env)
}

pub fn fg_ok(dir: &Path, args: &[&str]) -> String {
    let out = fg(dir, args);
    assert!(
        out.ok,
        "fullgit {args:?} failed:\n{}{}",
        out.stdout, out.stderr
    );
    out.stdout
}

pub fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

/// A clone with its own key and identity, set up with `fullgit init`.
pub fn user(fx: &Fixture, remote: &Path, name: &str) -> PathBuf {
    let (path, _) = fx.clone(remote, name);
    let key = keygen(fx.dir.path(), name);
    git(&path, &["config", "user.signingkey", key.to_str().unwrap()]);
    fg_ok(&path, &["init"]);
    let email = format!("{name}@example.com");
    fg_ok(&path, &["id", "create", "--name", name, "--email", &email]);
    fg_ok(&path, &["sync"]);
    path
}

/// Adopts fullgit as the README does: `owner` creates the policy and pushes
/// it as `master`, and grants each of `members` a role, by the email
/// `user` gave them. Every clone ends up trusting the policy.
pub fn adopt(owner: &Path, members: &[(&Path, &str)]) {
    fg_ok(owner, &["policy", "init"]);
    git(owner, &["add", ".fullgit/root"]);
    git(owner, &["commit", "-q", "-m", "Adopt fullgit"]);
    git(owner, &["push", "-q", "origin", "HEAD:master"]);
    fg_ok(owner, &["sync"]);
    for (dir, role) in members {
        let name = dir.file_name().unwrap().to_str().unwrap();
        fg_ok(
            owner,
            &["policy", "grant", &format!("{name}@example.com"), role],
        );
    }
    fg_ok(owner, &["sync"]);
    for (dir, _) in members {
        git(dir, &["pull", "-q", "origin", "master"]);
        fg_ok(dir, &["init"]);
        fg_ok(dir, &["sync"]);
    }
}
