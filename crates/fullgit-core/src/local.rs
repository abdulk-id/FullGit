//! Per-user files (e.g. `mise.local.toml`): ignored by git, and saved
//! instead as one snapshot per user, encrypted to that user's own keys, as
//! signed `local.save` operations on `refs/fullgit/users/<identity>/local`.
//!
//! A snapshot is a single archive, so file names stay hidden too:
//!
//! ```text
//! fullgit-local v1
//! <mode> <length> <path>     (per file, sorted by path, then the content
//! <content>                   and a newline)
//! ```
//!
//! Each clone remembers in `$GIT_DIR/fullgit/local.json` which head of the
//! ref its files were last saved to or restored from (its *base*), and what
//! that snapshot held. Saving over a head this clone hasn't seen (another
//! device saved since) is refused until restored; restoring overwrites a
//! file only if it is unchanged since the base.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use git2::{AttrValue, Oid, Repository};
use serde::{Deserialize, Serialize};
use serde_json::json;
use ssh_key::public::KeyData;

use crate::entity::{self, MERGE_KIND};
use crate::secret::{self, DecryptionKey};
use crate::sign::{self, Signer};
use crate::trust::Trust;
use crate::{Error, Result, payload, refs};

/// The `.gitattributes` attribute marking per-user files.
pub const ATTR: &str = "fullgit-local";
pub const SAVE_KIND: &str = "local.save";
const MAGIC: &str = "fullgit-local v1";

pub fn refname(identity: Oid) -> String {
    format!("{}users/{identity}/local", refs::PREFIX)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub executable: bool,
    pub content: Vec<u8>,
}

impl File {
    fn mode(&self) -> &'static str {
        if self.executable { "100755" } else { "100644" }
    }

    /// Identifies the content and mode, for change detection.
    pub fn hash(&self) -> Oid {
        let mut bytes = format!("{}\n", self.mode()).into_bytes();
        bytes.extend_from_slice(&self.content);
        Oid::hash_object(git2::ObjectType::Blob, &bytes).expect("hashing can't fail")
    }
}

/// Repository-relative path → file.
pub type Files = BTreeMap<String, File>;

pub fn pack(files: &Files) -> Vec<u8> {
    let mut out = format!("{MAGIC}\n").into_bytes();
    for (path, f) in files {
        out.extend(format!("{} {} {path}\n", f.mode(), f.content.len()).into_bytes());
        out.extend_from_slice(&f.content);
        out.push(b'\n');
    }
    out
}

pub fn unpack(mut bytes: &[u8]) -> Result<Files, String> {
    fn line<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], String> {
        let end = bytes
            .iter()
            .position(|&b| b == b'\n')
            .ok_or("truncated snapshot")?;
        let (l, rest) = bytes.split_at(end);
        *bytes = &rest[1..];
        Ok(l)
    }
    if line(&mut bytes)? != MAGIC.as_bytes() {
        return Err("not a fullgit-local snapshot".into());
    }
    let mut files = Files::new();
    while !bytes.is_empty() {
        let header = std::str::from_utf8(line(&mut bytes)?).map_err(|_| "header is not UTF-8")?;
        let mut parts = header.splitn(3, ' ');
        let (Some(mode), Some(len), Some(path)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(format!("bad header {header:?}"));
        };
        let executable = match mode {
            "100644" => false,
            "100755" => true,
            _ => return Err(format!("bad mode {mode}")),
        };
        let len: usize = len.parse().map_err(|_| format!("bad length {len}"))?;
        if bytes.len() < len + 1 || bytes[len] != b'\n' {
            return Err("truncated snapshot".into());
        }
        let content = bytes[..len].to_vec();
        bytes = &bytes[len + 1..];
        files.insert(
            path.to_owned(),
            File {
                executable,
                content,
            },
        );
    }
    Ok(files)
}

/// What [`State::files`] would hold for `files`.
pub fn hashes(files: &Files) -> BTreeMap<String, Oid> {
    files.iter().map(|(p, f)| (p.clone(), f.hash())).collect()
}

/// A valid `local.save` operation.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub id: Oid,
    /// Commit time, from the saving device's clock.
    pub time: i64,
    /// The key that saved it: which device.
    pub signer: KeyData,
    /// Fingerprints of the keys it is encrypted to, sorted.
    pub recipients: Vec<String>,
    armored: String,
}

impl Snapshot {
    pub fn open(&self, key: &DecryptionKey) -> Result<Files, String> {
        unpack(&secret::decrypt(&self.armored, key)?)
    }
}

/// Someone's snapshot ref.
#[derive(Debug, Default)]
pub struct History {
    pub head: Option<Oid>,
    /// Valid snapshots in replay order: the last is the current one.
    pub snapshots: Vec<Snapshot>,
    /// Operations ignored because the identity didn't sign them, or they
    /// aren't snapshots. Anyone with push access can write the ref.
    pub ignored: usize,
}

impl History {
    pub fn latest(&self) -> Option<&Snapshot> {
        self.snapshots.last()
    }
}

pub fn history(repo: &Repository, trust: &Trust, identity: Oid) -> Result<History> {
    let owner = trust
        .identities
        .get(&identity)
        .ok_or_else(|| Error::NotFound(format!("identity {identity}")))?;
    let Ok(head) = repo.refname_to_id(&refname(identity)) else {
        return Ok(History::default());
    };
    let ops = entity::load(repo, &[head])?;
    let root = ops.first().map(|o| o.id).unwrap_or(head);
    let mut history = History {
        head: Some(head),
        ..History::default()
    };
    for op in ops {
        if op.op.kind == MERGE_KIND {
            continue;
        }
        let parsed = (|| {
            if op.op.kind != SAVE_KIND {
                return Err(format!("unexpected {}", op.op.kind));
            }
            if !owner.signs(repo, &op.signer, root, op.id) {
                return Err("not signed by the identity".to_owned());
            }
            let p = &op.op.payload;
            let recipients = p["recipients"]
                .as_array()
                .ok_or("no recipients")?
                .iter()
                .map(|r| r.as_str().map(str::to_owned).ok_or("bad recipient"))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Snapshot {
                id: op.id,
                time: repo
                    .find_commit(op.id)
                    .map_err(|e| e.to_string())?
                    .time()
                    .seconds(),
                signer: op.signer.clone(),
                recipients,
                armored: payload::str(p, "sealed")?.to_owned(),
            })
        })();
        match parsed {
            Ok(s) => history.snapshots.push(s),
            Err(_) => history.ignored += 1,
        }
    }
    Ok(history)
}

/// What this clone last saved or restored.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct State {
    /// Head of the snapshot ref then.
    pub base: Option<Oid>,
    /// What the snapshot at `base` holds, as [`File::hash`]es.
    pub files: BTreeMap<String, Oid>,
}

#[derive(Serialize, Deserialize)]
struct StateFile {
    identity: String,
    base: Option<String>,
    files: BTreeMap<String, String>,
}

fn state_path(repo: &Repository) -> PathBuf {
    repo.path().join("fullgit").join("local.json")
}

/// This clone's state for `identity`; empty if it never saved or restored.
pub fn state(repo: &Repository, identity: Oid) -> Result<State> {
    let text = match std::fs::read(state_path(repo)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(State::default()),
        Err(e) => return Err(e.into()),
    };
    let file: StateFile = serde_json::from_slice(&text)?;
    if file.identity != identity.to_string() {
        return Ok(State::default());
    }
    let parse = |s: &str| Oid::from_str(s).map_err(Error::from);
    Ok(State {
        base: file.base.as_deref().map(parse).transpose()?,
        files: file
            .files
            .iter()
            .map(|(p, h)| Ok((p.clone(), parse(h)?)))
            .collect::<Result<_>>()?,
    })
}

fn store_state(repo: &Repository, identity: Oid, state: &State) -> Result<()> {
    let file = StateFile {
        identity: identity.to_string(),
        base: state.base.map(|b| b.to_string()),
        files: state
            .files
            .iter()
            .map(|(p, h)| (p.clone(), h.to_string()))
            .collect(),
    };
    let path = state_path(repo);
    std::fs::create_dir_all(path.parent().expect("has a parent"))?;
    std::fs::write(path, serde_json::to_vec_pretty(&file)?)?;
    Ok(())
}

/// Whether `path` is marked as a per-user file.
pub fn is_local(repo: &Repository, path: &Path) -> Result<bool> {
    let flags = git2::AttrCheckFlags::FILE_THEN_INDEX;
    let value = repo.get_attr(path, ATTR, flags)?;
    Ok(matches!(AttrValue::from_string(value), AttrValue::True))
}

/// Per-user files in this clone.
#[derive(Debug, Default)]
pub struct Declared {
    /// Present and untracked: what a snapshot holds.
    pub files: Vec<String>,
    /// Tracked by git, so not saved. They shouldn't be committed at all.
    pub tracked: Vec<String>,
}

/// Finds per-user files: the patterns marked `fullgit-local` in the root
/// `.gitattributes` or `$GIT_DIR/info/attributes` narrow the search, and
/// git's attribute lookup decides.
pub fn declared(repo: &Repository) -> Result<Declared> {
    let Some(workdir) = repo.workdir() else {
        return Ok(Declared::default());
    };
    let mut specs = Vec::new();
    for file in [
        workdir.join(".gitattributes"),
        repo.path().join("info/attributes"),
    ] {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for line in text.lines() {
            let mut words = line.split_whitespace();
            let Some(pattern) = words.next() else {
                continue;
            };
            if pattern.starts_with('#') || pattern.starts_with("[attr]") || pattern.ends_with('/') {
                continue;
            }
            if words.any(|a| a == ATTR || a.starts_with(&format!("{ATTR}="))) {
                specs.push(pathspec(pattern));
            }
        }
    }
    if specs.is_empty() {
        return Ok(Declared::default());
    }
    let mut out = Declared::default();
    for (flag, list) in [("--others", &mut out.files), ("--cached", &mut out.tracked)] {
        let output = Command::new("git")
            .arg("-C")
            .arg(workdir)
            .args(["ls-files", "-z", flag, "--"])
            .args(&specs)
            .output()?;
        if !output.status.success() {
            return Err(Error::Git(git2::Error::from_str(&format!(
                "git ls-files failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))));
        }
        for path in output.stdout.split(|&b| b == 0).filter(|p| !p.is_empty()) {
            let path = String::from_utf8_lossy(path).into_owned();
            if is_local(repo, Path::new(&path))? && !list.contains(&path) {
                list.push(path);
            }
        }
        list.sort();
    }
    Ok(out)
}

/// A gitattributes pattern as a pathspec matching at least the same files.
fn pathspec(pattern: &str) -> String {
    match pattern.strip_prefix('/') {
        Some(anchored) => format!(":(glob){anchored}"),
        None if pattern.contains('/') => format!(":(glob){pattern}"),
        None => format!(":(glob)**/{pattern}"),
    }
}

/// Reads per-user files from the working tree.
pub fn collect(repo: &Repository, paths: &[String]) -> Result<Files> {
    let workdir = workdir(repo)?;
    let mut files = Files::new();
    for path in paths {
        if let Some(f) = read(&workdir.join(path))? {
            files.insert(path.clone(), f);
        }
    }
    Ok(files)
}

fn read(path: &Path) -> Result<Option<File>> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => m,
        Ok(_) => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = {
        let _ = meta;
        false
    };
    Ok(Some(File {
        executable,
        content: std::fs::read(path)?,
    }))
}

fn workdir(repo: &Repository) -> Result<&Path> {
    repo.workdir()
        .ok_or_else(|| Error::Policy("a bare repository has no working tree".into()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Saved {
    /// The current snapshot already holds these files, for these keys.
    UpToDate,
    Saved {
        id: Oid,
        files: usize,
    },
    /// Another device saved since this clone last saved or restored; saving
    /// would replace that. Restore first, or force.
    Behind,
}

/// Saves the per-user files as `identity`'s new snapshot, encrypted to the
/// identity's current keys.
pub fn save(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    identity: Oid,
    force: bool,
) -> Result<Saved> {
    let owner = trust
        .identities
        .get(&identity)
        .ok_or_else(|| Error::NotFound(format!("identity {identity}")))?;
    if !owner.keys.contains(signer.public_key().key_data()) {
        return Err(Error::Signature(format!(
            "your signing key doesn't belong to identity {identity}"
        )));
    }
    let files = collect(repo, &declared(repo)?.files)?;
    let history = history(repo, trust, identity)?;
    let state = state(repo, identity)?;
    if history.head.is_some() && history.head != state.base && !force {
        return Ok(Saved::Behind);
    }

    let mut keys = owner.keys.clone();
    keys.sort_by_key(sign::fingerprint);
    let recipients: Vec<String> = keys.iter().map(sign::fingerprint).collect();
    let current = match history.latest() {
        Some(s) => s.recipients == recipients && state.files == hashes(&files),
        None => files.is_empty(),
    };
    if current && history.head == state.base {
        return Ok(Saved::UpToDate);
    }

    let armored = secret::encrypt(&keys, &pack(&files))?;
    let id = entity::append(
        repo,
        &refname(identity),
        signer,
        SAVE_KIND,
        json!({ "sealed": armored, "recipients": recipients }),
    )?;
    store_state(
        repo,
        identity,
        &State {
            base: Some(id),
            files: hashes(&files),
        },
    )?;
    Ok(Saved::Saved {
        id,
        files: files.len(),
    })
}

/// What [`restore`] did, by path.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Restored {
    pub written: Vec<String>,
    pub unchanged: Vec<String>,
    /// Changed here since this clone's base, and different in the snapshot:
    /// left alone.
    pub conflicts: Vec<String>,
    /// In the snapshot but not written: no longer a per-user file, tracked
    /// by git, or an unsafe path.
    pub skipped: Vec<(String, String)>,
    /// Here but not in the snapshot: left alone, and saved next time.
    pub extra: Vec<String>,
}

/// Writes `files` (a snapshot of `identity`'s, opened by the caller) into
/// the working tree. `head` is the snapshot ref's head they were read at;
/// without conflicts, it becomes this clone's base.
pub fn restore(
    repo: &Repository,
    identity: Oid,
    head: Oid,
    files: &Files,
    force: bool,
) -> Result<Restored> {
    let workdir = workdir(repo)?;
    let state = state(repo, identity)?;
    let index = repo.index()?;
    let mut out = Restored::default();
    let mut restored = Files::new();
    for (path, file) in files {
        if let Err(why) = check_path(path) {
            out.skipped.push((path.clone(), why));
            continue;
        }
        if index.get_path(Path::new(path), 0).is_some() {
            out.skipped.push((path.clone(), "tracked by git".into()));
            continue;
        }
        if !is_local(repo, Path::new(path))? {
            out.skipped
                .push((path.clone(), "no longer a per-user file".into()));
            continue;
        }
        let target = workdir.join(path);
        match read(&target)? {
            Some(here) if here == *file => out.unchanged.push(path.clone()),
            Some(here) if !force && state.files.get(path) != Some(&here.hash()) => {
                out.conflicts.push(path.clone());
                continue;
            }
            _ => {
                write(&target, file)?;
                out.written.push(path.clone());
            }
        }
        restored.insert(path.clone(), file.clone());
    }
    for path in declared(repo)?.files {
        if !files.contains_key(&path) {
            out.extra.push(path);
        }
    }
    if out.conflicts.is_empty() {
        store_state(
            repo,
            identity,
            &State {
                base: Some(head),
                files: hashes(&restored),
            },
        )?;
    }
    Ok(out)
}

/// Rejects paths that could escape the working tree or touch `.git`.
fn check_path(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    let ok = !path.is_empty()
        && p.components().all(|c| match c {
            Component::Normal(s) => !s.eq_ignore_ascii_case(".git"),
            _ => false,
        });
    if ok {
        Ok(())
    } else {
        Err("unsafe path".into())
    }
}

fn write(target: &Path, file: &File) -> Result<()> {
    if let Some(dir) = target.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(target, &file.content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if file.executable { 0o755 } else { 0o644 };
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Marks `path` (relative to the repository root) as a per-user file in the
/// root `.gitattributes`, and ignores it in the root `.gitignore`.
pub fn mark(repo: &Repository, path: &str) -> Result<()> {
    let workdir = workdir(repo)?;
    let special = |c: char| c.is_whitespace() || "#!*?[]\\\"".contains(c);
    if path.is_empty() || path.chars().any(special) || check_path(path).is_err() {
        return Err(Error::Policy(format!(
            "{path:?}: per-user paths can't contain spaces, glob characters or `.git`; \
             write a pattern in .gitattributes by hand instead"
        )));
    }
    let pattern = format!("/{path}");
    secret::replace_line(
        &workdir.join(".gitattributes"),
        &pattern,
        &format!("{pattern} {ATTR}"),
    )?;
    if !repo.is_path_ignored(path)? {
        secret::replace_line(&workdir.join(".gitignore"), &pattern, &pattern)?;
    }
    Ok(())
}
