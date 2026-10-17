//! SSH signatures in the format git uses for `gpg.format=ssh` commit signing.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ssh_key::public::KeyData;
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

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
        let ed25519_only = || {
            format!(
                "{} is not an ed25519 key; fullgit only supports those so far \
                 (`ssh-keygen -t ed25519` makes one)",
                pub_path.display()
            )
        };
        let public_key = PublicKey::read_openssh_file(&pub_path).map_err(|e| match e {
            ssh_key::Error::AlgorithmUnknown => Error::Signature(ed25519_only()),
            e => Error::Signature(format!("reading {}: {e}", pub_path.display())),
        })?;
        if public_key.algorithm() != ssh_key::Algorithm::Ed25519 {
            return Err(Error::Signature(ed25519_only()));
        }
        Ok(Self {
            key_path,
            public_key,
        })
    }

    /// The private key's file: `key_path` without `.pub`.
    pub fn private_key_path(&self) -> PathBuf {
        match self.key_path.extension() {
            Some(e) if e == "pub" => self.key_path.with_extension(""),
            _ => self.key_path.clone(),
        }
    }

    /// Whether signing would stop to ask for a passphrase: the key file is
    /// encrypted, and ssh-agent doesn't hold the key. A key file that can't
    /// be read is taken to live in an agent.
    pub fn needs_passphrase(&self) -> bool {
        let Ok(key) = PrivateKey::read_openssh_file(&self.private_key_path()) else {
            return false;
        };
        key.is_encrypted() && !self.in_agent()
    }

    fn in_agent(&self) -> bool {
        let Ok(out) = Command::new("ssh-add")
            .arg("-L")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        else {
            return false;
        };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| PublicKey::from_openssh(l).ok())
            .any(|k| k.key_data() == self.public_key.key_data())
    }

    /// Decrypts the private key into memory with its passphrase.
    pub fn unlock(&self, passphrase: &str) -> Result<KeySigner> {
        let path = self.private_key_path();
        let key = PrivateKey::read_openssh_file(&path)
            .map_err(|e| Error::Signature(format!("reading {}: {e}", path.display())))?;
        let key = match key.is_encrypted() {
            true => key
                .decrypt(passphrase)
                .map_err(|_| Error::Signature("wrong passphrase".into()))?,
            false => key,
        };
        if key.public_key().key_data() != self.public_key.key_data() {
            return Err(Error::Signature(format!(
                "{} doesn't match its public key",
                path.display()
            )));
        }
        Ok(KeySigner {
            public_key: key.public_key().clone(),
            key,
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
        // Like git: sign a file, and leave stdin alone, so ssh-keygen can ask
        // for a passphrase on the terminal.
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("data");
        std::fs::write(&file, data)?;
        let out = Command::new("ssh-keygen")
            .args(["-q", "-Y", "sign", "-n", namespace, "-f"])
            .arg(&self.key_path)
            .arg(&file)
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?
            .wait_with_output()?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let mut msg = format!("ssh-keygen -Y sign failed: {}", stderr.trim());
            if stderr.contains("passphrase") || stderr.contains("askpass") {
                msg.push_str(
                    "\nthe key needs its passphrase, and there was no terminal to ask on; \
                     load it into ssh-agent with `ssh-add`",
                );
            }
            return Err(Error::Signature(msg));
        }
        let mut sig = file.into_os_string();
        sig.push(".sig");
        Ok(std::fs::read_to_string(sig)?)
    }
}

/// Signs with a private key held in memory, as ssh-agent does. For
/// `fullgit web`, which has no terminal to ask for a passphrase on each
/// signature. The key is wiped from memory when dropped.
#[derive(Clone)]
pub struct KeySigner {
    key: PrivateKey,
    public_key: PublicKey,
}

impl Signer for KeySigner {
    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn sign_as(&self, namespace: &str, data: &[u8]) -> Result<String> {
        // What ssh-keygen -Y sign writes.
        self.key
            .sign(namespace, HashAlg::Sha512, data)
            .and_then(|sig| sig.to_pem(LineEnding::LF))
            .map_err(|e| Error::Signature(e.to_string()))
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
