//! SSH signatures in the format git uses for `gpg.format=ssh` commit signing.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ssh_key::public::KeyData;
use ssh_key::{PublicKey, SshSig};

use crate::{Error, Result};

/// Signature namespace. Matches git's, so `git verify-commit` accepts our
/// operation commits.
pub const NAMESPACE: &str = "git";

pub trait Signer {
    fn public_key(&self) -> &PublicKey;
    /// Returns an armored `-----BEGIN SSH SIGNATURE-----` block over `data`.
    fn sign_as(&self, namespace: &str, data: &[u8]) -> Result<String>;

    /// Signs in git's namespace, as for a commit.
    fn sign(&self, data: &[u8]) -> Result<String> {
        self.sign_as(NAMESPACE, data)
    }
}

/// Signs by running `ssh-keygen -Y sign`, as git does. Pointing `key_path` at
/// a `.pub` file makes ssh-keygen use the matching key from ssh-agent.
pub struct SshKeygenSigner {
    key_path: PathBuf,
    public_key: PublicKey,
}

impl SshKeygenSigner {
    pub fn new(key_path: impl Into<PathBuf>) -> Result<Self> {
        let key_path = key_path.into();
        let pub_path = if key_path.extension().is_some_and(|e| e == "pub") {
            key_path.clone()
        } else {
            let mut p = key_path.clone().into_os_string();
            p.push(".pub");
            PathBuf::from(p)
        };
        let public_key = PublicKey::read_openssh_file(&pub_path)
            .map_err(|e| Error::Signature(format!("reading {}: {e}", pub_path.display())))?;
        Ok(Self {
            key_path,
            public_key,
        })
    }

    /// Uses the repository's `user.signingkey`, the same key git signs with.
    pub fn from_git_config(repo: &git2::Repository) -> Result<Self> {
        let key = repo
            .config()?
            .get_path("user.signingkey")
            .map_err(|_| Error::Signature("user.signingkey is not set".into()))?;
        Self::new(expand_home(&key))
    }
}

impl Signer for SshKeygenSigner {
    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn sign_as(&self, namespace: &str, data: &[u8]) -> Result<String> {
        let mut child = Command::new("ssh-keygen")
            .args(["-q", "-Y", "sign", "-n", namespace, "-f"])
            .arg(&self.key_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child.stdin.take().expect("piped stdin").write_all(data)?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(Error::Signature(format!(
                "ssh-keygen -Y sign failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        String::from_utf8(out.stdout).map_err(|e| Error::Signature(e.to_string()))
    }
}

/// Verifies an armored SSH signature over `data` and returns the signing key.
/// Says nothing about whether that key is *trusted*; that is the policy's job.
pub fn verify(data: &[u8], armored: &str) -> Result<KeyData> {
    verify_as(NAMESPACE, data, armored)
}

pub fn verify_as(namespace: &str, data: &[u8], armored: &str) -> Result<KeyData> {
    let sig = SshSig::from_pem(armored).map_err(|e| Error::Signature(e.to_string()))?;
    let key = sig.public_key().clone();
    PublicKey::from(key.clone())
        .verify(namespace, data, &sig)
        .map_err(|e| Error::Signature(e.to_string()))?;
    Ok(key)
}

/// A key as `ssh-ed25519 AAAA...`, without a comment.
pub fn key_to_string(key: &KeyData) -> String {
    PublicKey::from(key.clone())
        .to_openssh()
        .expect("encoding a public key into a String cannot fail")
}

pub fn key_from_string(s: &str) -> Result<KeyData> {
    PublicKey::from_openssh(s.trim())
        .map(|k| k.key_data().clone())
        .map_err(|e| Error::Signature(format!("not an OpenSSH public key: {e}")))
}

pub fn fingerprint(key: &KeyData) -> String {
    key.fingerprint(Default::default()).to_string()
}

pub fn expand_home(path: &Path) -> PathBuf {
    match (path.strip_prefix("~"), std::env::var_os("HOME")) {
        (Ok(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => path.to_owned(),
    }
}
