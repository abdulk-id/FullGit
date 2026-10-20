//! Secret files: plaintext in the working tree, sealed in the repository.
//!
//! A sealed file is age-encrypted to the current keys of every member of a
//! policy group, and signed by whoever sealed it:
//!
//! ```text
//! fullgit-secret v1
//! group: dev
//! recipient: SHA256:...          (one per key, sorted)
//! -----BEGIN AGE ENCRYPTED FILE-----
//! ...
//! -----END AGE ENCRYPTED FILE-----
//! -----BEGIN SSH SIGNATURE-----  (over everything above)
//! ...
//! -----END SSH SIGNATURE-----
//! ```
//!
//! The signature matters because age doesn't authenticate the sender:
//! without it, anyone with push access could replace a secret with their
//! own ciphertext. A sealed file is only opened if its signer is a member of
//! the group, or an owner.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::SecretString;
use git2::{Oid, Repository};
use ssh_key::public::KeyData;

use crate::sign::{self, Signer};
use crate::trust::{Role, Trust};
use crate::{Error, Result};

pub const MAGIC: &str = "fullgit-secret v1";
/// Name of the git filter and diff drivers, as used in `.gitattributes`.
pub const DRIVER: &str = "fullgit";
/// The `.gitattributes` attribute naming a secret's group.
pub const GROUP_ATTR: &str = "fullgit-group";
pub const SIGNATURE_NAMESPACE: &str = "fullgit-secret";
const SIGNATURE_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const AGE_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

/// A parsed sealed file. Parsing checks the format only; [`Sealed::verify`]
/// checks the signer and [`Sealed::open`] decrypts.
#[derive(Debug, Clone)]
pub struct Sealed {
    pub group: String,
    /// Fingerprints of the keys it was encrypted to, sorted.
    pub recipients: Vec<String>,
    armored: String,
    signed: String,
    signature: String,
}

impl Sealed {
    pub fn is_sealed(bytes: &[u8]) -> bool {
        bytes.starts_with(MAGIC.as_bytes()) && matches!(bytes.get(MAGIC.len()), Some(b'\n' | b'\r'))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if !Self::is_sealed(bytes) {
            return Err("not a fullgit secret".into());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "not UTF-8")?;
        let sig_at = text.find(SIGNATURE_BEGIN).ok_or("no signature")?;
        let (signed, signature) = text.split_at(sig_at);
        let age_at = signed.find(AGE_BEGIN).ok_or("no age ciphertext")?;
        let (header, armored) = signed.split_at(age_at);

        let mut lines = header.lines();
        lines.next(); // MAGIC
        let mut group = None;
        let mut recipients = Vec::new();
        for line in lines {
            match line.split_once(": ") {
                Some(("group", g)) => group = Some(g.to_owned()),
                Some(("recipient", r)) => recipients.push(r.to_owned()),
                _ => return Err(format!("unexpected header line {line:?}")),
            }
        }
        Ok(Self {
            group: group.ok_or("no group")?,
            recipients,
            armored: armored.to_owned(),
            signed: signed.to_owned(),
            signature: signature.to_owned(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        format!("{}{}", self.signed, self.signature).into_bytes()
    }

    /// The key that sealed this file. Says nothing about whether it may.
    pub fn signer(&self) -> Result<KeyData> {
        sign::verify_as(SIGNATURE_NAMESPACE, self.signed.as_bytes(), &self.signature)
    }

    /// Checks that the signer is a member of the group, or an owner, and
    /// returns their identity.
    pub fn verify(&self, trust: &Trust) -> Result<Oid, String> {
        let key = self.signer().map_err(|e| e.to_string())?;
        let Some((_, policy)) = &trust.policy else {
            return Err("there is no policy to check the signer against".into());
        };
        let ids = trust.identities_with_key(&key);
        let members = policy.groups.get(&self.group);
        ids.iter()
            .copied()
            .find(|id| {
                members.is_some_and(|m| m.contains(id)) || policy.role(*id) == Some(Role::Owner)
            })
            .ok_or_else(|| {
                format!(
                    "sealed by {}, who is neither in {} nor an owner",
                    sign::fingerprint(&key),
                    self.group
                )
            })
    }

    pub fn open(&self, key: &DecryptionKey) -> Result<Vec<u8>, String> {
        decrypt(&self.armored, key)
    }
}

/// The keys a secret of `group` is encrypted to: the current keys of every
/// member, sorted by fingerprint.
pub fn recipients(trust: &Trust, group: &str) -> Result<Vec<KeyData>> {
    let (_, policy): &(Oid, crate::policy::Policy) = trust
        .policy
        .as_ref()
        .ok_or_else(|| Error::Policy("secrets need a policy; run `fullgit policy init`".into()))?;
    let members = policy
        .groups
        .get(group)
        .ok_or_else(|| Error::Policy(format!("group {group} doesn't exist")))?;
    let mut keys: Vec<KeyData> = members
        .iter()
        .filter_map(|id| trust.identities.get(id))
        .flat_map(|i| i.keys.iter().cloned())
        .collect();
    keys.sort_by_key(sign::fingerprint);
    keys.dedup();
    if keys.is_empty() {
        return Err(Error::Policy(format!("group {group} has no keys")));
    }
    Ok(keys)
}

/// Encrypts `plaintext` to `group` and signs it.
pub fn seal(trust: &Trust, signer: &dyn Signer, group: &str, plaintext: &[u8]) -> Result<Sealed> {
    let keys = recipients(trust, group)?;
    let armored = encrypt(&keys, plaintext)?;
    let mut signed = format!("{MAGIC}\ngroup: {group}\n");
    for k in &keys {
        signed.push_str(&format!("recipient: {}\n", sign::fingerprint(k)));
    }
    signed.push_str(&armored);
    if !signed.ends_with('\n') {
        signed.push('\n');
    }
    let signature = signer.sign_as(SIGNATURE_NAMESPACE, signed.as_bytes())?;
    let bytes = format!("{signed}{signature}");
    Sealed::parse(bytes.as_bytes()).map_err(|e| Error::Signature(format!("sealed badly: {e}")))
}

/// Age-encrypts `plaintext` to SSH `keys`, armored.
pub fn encrypt(keys: &[KeyData], plaintext: &[u8]) -> Result<String> {
    let age_recipients = keys
        .iter()
        .map(|k| {
            age::ssh::Recipient::from_str(&sign::key_to_string(k))
                .map_err(|e| Error::Signature(format!("unusable recipient key: {e:?}")))
        })
        .collect::<Result<Vec<_>>>()?;
    let encryptor =
        age::Encryptor::with_recipients(age_recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| Error::Signature(format!("age: {e}")))?;
    let mut armored = Vec::new();
    let armor =
        age::armor::ArmoredWriter::wrap_output(&mut armored, age::armor::Format::AsciiArmor)?;
    let mut writer = encryptor.wrap_output(armor)?;
    writer.write_all(plaintext)?;
    writer.finish()?.finish()?;
    Ok(String::from_utf8(armored).expect("age armor is ASCII"))
}

/// Decrypts what [`encrypt`] produced.
pub fn decrypt(armored: &str, key: &DecryptionKey) -> Result<Vec<u8>, String> {
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(armored.as_bytes()))
        .map_err(|e| format!("invalid ciphertext: {e}"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&key.identity as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::NoMatchingKeys => "not encrypted to your key".to_owned(),
            e => e.to_string(),
        })?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| e.to_string())?;
    Ok(plaintext)
}

/// A private SSH key that can decrypt secrets. Passphrase-protected keys are
/// unlocked once, by prompting on the terminal.
pub struct DecryptionKey {
    identity: age::ssh::Identity,
    pub path: PathBuf,
}

impl DecryptionKey {
    /// `fullgit.identityFile`, or else the private half of
    /// `user.signingkey`. Decryption needs the key file itself: ssh-agent
    /// can sign, but can't decrypt.
    pub fn from_git_config(repo: &Repository) -> Result<Self> {
        let config = repo.config()?;
        let path = match config.get_path("fullgit.identityFile") {
            Ok(p) => p,
            Err(_) => {
                let signing = config.get_path("user.signingkey").map_err(|_| {
                    Error::Signature("set user.signingkey or fullgit.identityFile".into())
                })?;
                let signing = sign::expand_home(&signing);
                match signing.to_str().and_then(|s| s.strip_suffix(".pub")) {
                    Some(private) => PathBuf::from(private),
                    None => signing,
                }
            }
        };
        Self::from_file(&sign::expand_home(&path))
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|e| {
            Error::Signature(format!(
                "can't read private key {} ({e}); set fullgit.identityFile",
                path.display()
            ))
        })?;
        let identity = age::ssh::Identity::from_buffer(
            std::io::BufReader::new(file),
            Some(path.display().to_string()),
        )?;
        let identity = match identity {
            age::ssh::Identity::Unencrypted(_) => identity,
            age::ssh::Identity::Encrypted(key) => {
                let mut tries = 0;
                loop {
                    let prompt = format!("Passphrase for {}: ", path.display());
                    let pass = rpassword::prompt_password(prompt)?;
                    match key.decrypt(SecretString::from(pass)) {
                        Ok(k) => break k.into(),
                        Err(_) if tries < 2 => tries += 1,
                        Err(e) => return Err(Error::Signature(e.to_string())),
                    }
                }
            }
            age::ssh::Identity::Unsupported(_) => {
                return Err(Error::Signature(format!(
                    "{} is not a key type age supports",
                    path.display()
                )));
            }
        };
        Ok(Self {
            identity,
            path: path.to_owned(),
        })
    }
}

/// Whether `path` is marked as a secret, and its group if so.
pub fn group_of(repo: &Repository, path: &Path) -> Result<Option<String>> {
    let flags = git2::AttrCheckFlags::FILE_THEN_INDEX;
    if repo.get_attr(path, "filter", flags)? != Some(DRIVER) {
        return Ok(None);
    }
    Ok(Some(
        repo.get_attr(path, GROUP_ATTR, flags)?
            .filter(|g| !g.is_empty() && *g != "true")
            .ok_or_else(|| {
                Error::Policy(format!(
                    "{} is a secret without a {GROUP_ATTR} attribute",
                    path.display()
                ))
            })?
            .to_owned(),
    ))
}

/// A secret in the index.
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: String,
    pub group: String,
    pub blob: Oid,
}

/// Every index entry marked as a secret.
pub fn entries(repo: &Repository) -> Result<Vec<Entry>> {
    let index = repo.index()?;
    let mut out = Vec::new();
    for e in index.iter() {
        // Conflicted paths (stages 1-3) have no single blob to check.
        if (e.flags >> 12) & 3 != 0 {
            continue;
        }
        let path = String::from_utf8_lossy(&e.path).into_owned();
        if let Some(group) = group_of(repo, Path::new(&path))? {
            out.push(Entry {
                path,
                group,
                blob: e.id,
            });
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rekeyed {
    /// Already sealed to the group's current keys.
    UpToDate,
    /// Resealed in the index. `lost` are fingerprints of keys that could
    /// read the previous version but not this one: rotate those values, as
    /// git history still holds what they could read.
    Resealed {
        lost: Vec<String>,
    },
    Failed(String),
}

/// Reseals secrets in the index whose recipients differ from their group's
/// current keys. `only` limits it to some paths. The working tree is left
/// alone; commit the result.
pub fn rekey(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    key: &DecryptionKey,
    only: &[String],
) -> Result<Vec<(String, Rekeyed)>> {
    let mut index = repo.index()?;
    let mut out = Vec::new();
    for e in entries(repo)? {
        if !only.is_empty() && !only.contains(&e.path) {
            continue;
        }
        let blob = repo.find_blob(e.blob)?;
        let outcome = (|| {
            let sealed = Sealed::parse(blob.content())
                .map_err(|_| "not sealed; `git add` it first".to_owned())?;
            let current: Vec<String> = recipients(trust, &e.group)
                .map_err(|err| err.to_string())?
                .iter()
                .map(sign::fingerprint)
                .collect();
            if sealed.recipients == current && sealed.group == e.group {
                return Ok(Rekeyed::UpToDate);
            }
            // Resealing re-signs, so only reseal what we would trust.
            sealed.verify(trust)?;
            let plaintext = sealed.open(key)?;
            let resealed =
                seal(trust, signer, &e.group, &plaintext).map_err(|err| err.to_string())?;
            let id = repo
                .blob(&resealed.to_bytes())
                .map_err(|err| err.to_string())?;
            let mut entry = index
                .get_path(Path::new(&e.path), 0)
                .ok_or("vanished from the index")?;
            entry.id = id;
            index.add(&entry).map_err(|err| err.to_string())?;
            let lost = sealed
                .recipients
                .iter()
                .filter(|r| !current.contains(r))
                .cloned()
                .collect();
            Ok(Rekeyed::Resealed { lost })
        })()
        .unwrap_or_else(Rekeyed::Failed);
        out.push((e.path, outcome));
    }
    index.write()?;
    Ok(out)
}

/// Checks out again every secret whose working-tree file is still sealed
/// (or missing), so the filter can decrypt it now: after `fullgit init` in
/// an existing clone, or after being added to a group. Returns the paths
/// that are still sealed afterwards.
pub fn checkout(repo: &Repository) -> Result<Vec<String>> {
    let workdir = repo
        .workdir()
        .ok_or_else(|| Error::Policy("a bare repository has no working tree".into()))?;
    let mut paths = Vec::new();
    for e in entries(repo)? {
        let file = workdir.join(&e.path);
        match std::fs::read(&file) {
            Ok(content) if Sealed::is_sealed(&content) => {
                std::fs::remove_file(&file)?;
                paths.push(e.path);
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => paths.push(e.path),
            Err(err) => return Err(err.into()),
        }
    }
    if paths.is_empty() {
        return Ok(paths);
    }
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(workdir)
        .args(["checkout", "--"])
        .args(&paths)
        .status()?;
    if !status.success() {
        return Err(Error::Git(git2::Error::from_str("git checkout failed")));
    }
    let mut still = Vec::new();
    for p in paths {
        if std::fs::read(workdir.join(&p)).is_ok_and(|c| Sealed::is_sealed(&c)) {
            still.push(p);
        }
    }
    Ok(still)
}

/// Marks `path` (relative to the repository root) as a secret of `group`
/// in the root `.gitattributes`, replacing any earlier line for it.
pub fn mark(repo: &Repository, path: &str, group: &str) -> Result<PathBuf> {
    let workdir = repo
        .workdir()
        .ok_or_else(|| Error::Policy("a bare repository has no working tree".into()))?;
    let bad = |s: &str| s.is_empty() || s.chars().any(|c| c.is_whitespace() || c == '#');
    if bad(path) || bad(group) {
        return Err(Error::Policy(format!(
            "{path:?} / {group:?}: paths and groups can't be empty or contain spaces or #"
        )));
    }
    let pattern = format!("/{path}");
    let line = format!("{pattern} filter={DRIVER} diff={DRIVER} -merge -text {GROUP_ATTR}={group}");
    let file = workdir.join(".gitattributes");
    replace_line(&file, &pattern, &line)?;
    Ok(file)
}

/// Replaces the line for `pattern` in a `.gitattributes`-style `file` with
/// `line`, or appends it.
pub(crate) fn replace_line(file: &Path, pattern: &str, line: &str) -> Result<()> {
    let existing = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let mut lines: Vec<&str> = existing
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(pattern))
        .collect();
    lines.push(line);
    std::fs::write(file, lines.join("\n") + "\n")?;
    Ok(())
}

/// Whether `HEAD` holds `path` unsealed: its values are then in history in
/// plaintext and need rotating.
pub fn committed_unsealed(repo: &Repository, path: &str) -> Result<bool> {
    let Ok(head) = repo.head() else {
        return Ok(false);
    };
    let tree = head.peel_to_tree()?;
    let Ok(entry) = tree.get_path(Path::new(path)) else {
        return Ok(false);
    };
    let Ok(blob) = repo.find_blob(entry.id()) else {
        return Ok(false);
    };
    Ok(!Sealed::is_sealed(blob.content()))
}
