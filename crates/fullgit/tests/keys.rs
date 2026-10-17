//! Signing keys with a passphrase, typed at the terminal.

mod cli;

use std::process::Command;

use cli::common::{Fixture, git};

/// Without ssh-agent, ssh-keygen asks for the passphrase on the terminal.
/// fullgit must leave the terminal to it rather than feed it data.
#[test]
fn asks_for_the_passphrase_on_the_terminal() {
    let fx = Fixture::new();
    let key = fx.path("locked");
    let made = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "s3cret", "-C", "t", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let (dir, _) = fx.repo("r");
    git(
        &dir,
        &[
            "config",
            "user.signingkey",
            &format!("{}.pub", key.display()),
        ],
    );

    // `script` gives the command a terminal, and types the passphrase once
    // the prompt is up: the prompt discards anything typed before it.
    let fullgit = env!("CARGO_BIN_EXE_fullgit");
    let shell = format!("(sleep 1; echo s3cret) | script -qec '{fullgit} id create' /dev/null");
    let out = Command::new("sh")
        .arg("-c")
        .arg(shell)
        .current_dir(&dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("SSH_AUTH_SOCK")
        .env("DISPLAY", ":0") // as in a desktop session, where ssh-askpass would be tried
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Enter passphrase") && stdout.contains("created identity"),
        "{stdout}"
    );
}
