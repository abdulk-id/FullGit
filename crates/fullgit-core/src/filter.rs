//! The git filter for secrets, speaking git's long-running filter protocol
//! (`filter.<driver>.process`, see gitattributes(5)): one process serves a
//! whole git command instead of one process per file.
//!
//! - clean (working tree → repository): seals plaintext. If the plaintext
//!   matches what the index already holds, the index blob is returned as is;
//!   sealing is randomized, so otherwise every `git status` would see a
//!   change.
//! - smudge (repository → working tree): verifies and decrypts. If that is
//!   not possible (not a recipient, no key, untrusted signer) the sealed
//!   file is checked out unchanged, and the reason reported once at the end.

use std::io::{self, BufRead, Read, Write};
use std::path::Path;

use git2::Repository;

use crate::secret::{self, DecryptionKey, Sealed};
use crate::sign::SshKeygenSigner;
use crate::trust::Trust;

/// Longest payload of one pkt-line.
const MAX_PKT: usize = 65516;

#[derive(Debug, PartialEq, Eq)]
enum Pkt {
    Data(Vec<u8>),
    Flush,
    Eof,
}

fn read_pkt(r: &mut impl Read) -> io::Result<Pkt> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(Pkt::Eof),
        Err(e) => return Err(e),
    }
    let len = std::str::from_utf8(&len)
        .ok()
        .and_then(|s| usize::from_str_radix(s, 16).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad pkt-line length"))?;
    match len {
        0 => Ok(Pkt::Flush),
        1..=4 => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected special pkt-line",
        )),
        _ => {
            let mut data = vec![0; len - 4];
            r.read_exact(&mut data)?;
            Ok(Pkt::Data(data))
        }
    }
}

fn write_pkt(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    write!(w, "{:04x}", data.len() + 4)?;
    w.write_all(data)
}

fn write_text(w: &mut impl Write, line: &str) -> io::Result<()> {
    write_pkt(w, format!("{line}\n").as_bytes())
}

/// Writes a flush packet and pushes everything out: git is waiting for it.
fn flush(w: &mut impl Write) -> io::Result<()> {
    w.write_all(b"0000")?;
    w.flush()
}

/// Reads `key=value` lines up to a flush. `None` at end of input.
fn read_list(r: &mut impl Read) -> io::Result<Option<Vec<String>>> {
    let mut lines = Vec::new();
    loop {
        match read_pkt(r)? {
            Pkt::Data(d) => {
                let s = String::from_utf8_lossy(&d);
                lines.push(s.strip_suffix('\n').unwrap_or(&s).to_owned());
            }
            Pkt::Flush => return Ok(Some(lines)),
            Pkt::Eof if lines.is_empty() => return Ok(None),
            Pkt::Eof => return Err(io::ErrorKind::UnexpectedEof.into()),
        }
    }
}

fn read_content(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut content = Vec::new();
    loop {
        match read_pkt(r)? {
            Pkt::Data(d) => content.extend_from_slice(&d),
            Pkt::Flush => return Ok(content),
            Pkt::Eof => return Err(io::ErrorKind::UnexpectedEof.into()),
        }
    }
}

fn expect(r: &mut impl Read, want: &[&str]) -> io::Result<()> {
    let got = read_list(r)?.unwrap_or_default();
    if got != want {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected {want:?} from git, got {got:?}"),
        ));
    }
    Ok(())
}

/// What a filter does with one file.
pub trait Handler {
    fn clean(&mut self, path: &str, content: Vec<u8>) -> Result<Vec<u8>, String>;
    fn smudge(&mut self, path: &str, content: Vec<u8>) -> Result<Vec<u8>, String>;
}

/// Serves git's filter protocol until git closes the pipe.
pub fn serve(
    r: &mut impl BufRead,
    w: &mut impl Write,
    handler: &mut dyn Handler,
) -> io::Result<()> {
    expect(r, &["git-filter-client", "version=2"])?;
    write_text(w, "git-filter-server")?;
    write_text(w, "version=2")?;
    flush(w)?;
    let offered = read_list(r)?.unwrap_or_default();
    for cap in ["capability=clean", "capability=smudge"] {
        if offered.iter().any(|c| c == cap) {
            write_text(w, cap)?;
        }
    }
    flush(w)?;

    while let Some(headers) = read_list(r)? {
        let get = |key: &str| {
            headers
                .iter()
                .find_map(|h| h.strip_prefix(key)?.strip_prefix('='))
                .unwrap_or_default()
                .to_owned()
        };
        let (command, path) = (get("command"), get("pathname"));
        let content = read_content(r)?;
        let result = match command.as_str() {
            "clean" => handler.clean(&path, content),
            "smudge" => handler.smudge(&path, content),
            other => Err(format!("unsupported command {other}")),
        };
        match result {
            Ok(out) => {
                write_text(w, "status=success")?;
                flush(w)?;
                for chunk in out.chunks(MAX_PKT) {
                    write_pkt(w, chunk)?;
                }
                flush(w)?;
                flush(w)?; // keep status=success
            }
            Err(why) => {
                eprintln!("fullgit: {path}: {why}");
                write_text(w, "status=error")?;
                flush(w)?;
            }
        }
    }
    Ok(())
}

/// Loads what it needs (trust, keys) on first use, once per git command.
pub struct SecretFilter<'r> {
    repo: &'r Repository,
    trust: Option<Result<Trust, String>>,
    key: Option<Result<DecryptionKey, String>>,
    signer: Option<Result<SshKeygenSigner, String>>,
    /// Files smudge left sealed, and why.
    pub left_sealed: Vec<(String, String)>,
}

impl<'r> SecretFilter<'r> {
    pub fn new(repo: &'r Repository) -> Self {
        Self {
            repo,
            trust: None,
            key: None,
            signer: None,
            left_sealed: Vec::new(),
        }
    }

    fn trust(&mut self) -> Result<&Trust, String> {
        let repo = self.repo;
        lazy(&mut self.trust, || Trust::load(repo))
    }

    fn key(&mut self) -> Result<&DecryptionKey, String> {
        let repo = self.repo;
        lazy(&mut self.key, || DecryptionKey::from_git_config(repo))
    }

    /// Verifies and decrypts a sealed file.
    pub fn open(&mut self, sealed: &Sealed) -> Result<Vec<u8>, String> {
        sealed.verify(self.trust()?)?;
        sealed.open(self.key()?)
    }

    /// The plaintext of the index's version of `path`, if it is sealed for
    /// `group` and we can decrypt it.
    fn indexed_plaintext(&mut self, path: &str, group: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let mut index = self.repo.index().ok()?;
        index.read(false).ok()?;
        let entry = index.get_path(Path::new(path), 0)?;
        let blob = self.repo.find_blob(entry.id).ok()?;
        let sealed = Sealed::parse(blob.content()).ok()?;
        if sealed.group != group {
            return None;
        }
        let plaintext = sealed.open(self.key().ok()?).ok()?;
        Some((plaintext, blob.content().to_vec()))
    }
}

impl Handler for SecretFilter<'_> {
    fn clean(&mut self, path: &str, content: Vec<u8>) -> Result<Vec<u8>, String> {
        // Already sealed: a file we couldn't decrypt on checkout.
        if Sealed::is_sealed(&content) {
            return Ok(content);
        }
        let group = secret::group_of(self.repo, Path::new(path))
            .map_err(|e| e.to_string())?
            .ok_or("not marked as a secret")?;
        if let Some((plaintext, sealed)) = self.indexed_plaintext(path, &group)
            && plaintext == content
        {
            return Ok(sealed);
        }
        let repo = self.repo;
        let trust = lazy(&mut self.trust, || Trust::load(repo))?;
        let signer = lazy(&mut self.signer, || SshKeygenSigner::from_git_config(repo))?;
        let sealed = secret::seal(trust, signer, &group, &content)
            .map_err(|e| format!("can't seal: {e}"))?;
        // Anyone can encrypt to the group's public keys, but checkouts
        // would refuse to open it; better to say so now.
        sealed
            .verify(trust)
            .map_err(|why| format!("can't seal: {why}"))?;
        Ok(sealed.to_bytes())
    }

    fn smudge(&mut self, path: &str, content: Vec<u8>) -> Result<Vec<u8>, String> {
        if !Sealed::is_sealed(&content) {
            return Ok(content);
        }
        let opened = Sealed::parse(&content).and_then(|s| self.open(&s));
        match opened {
            Ok(plaintext) => Ok(plaintext),
            Err(why) => {
                self.left_sealed.push((path.to_owned(), why));
                Ok(content)
            }
        }
    }
}

/// Loads a value on first use and remembers the outcome, error included.
fn lazy<T>(
    slot: &mut Option<Result<T, String>>,
    load: impl FnOnce() -> crate::Result<T>,
) -> Result<&T, String> {
    slot.get_or_insert_with(|| load().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Upper;
    impl Handler for Upper {
        fn clean(&mut self, _: &str, content: Vec<u8>) -> Result<Vec<u8>, String> {
            Ok(content.to_ascii_uppercase())
        }
        fn smudge(&mut self, path: &str, _: Vec<u8>) -> Result<Vec<u8>, String> {
            Err(format!("no smudge for {path}"))
        }
    }

    fn pkts(lines: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for l in lines {
            if l.is_empty() {
                flush(&mut out).unwrap();
            } else {
                write_pkt(&mut out, l.as_bytes()).unwrap();
            }
        }
        out
    }

    #[test]
    fn speaks_the_long_running_filter_protocol() {
        let big = "x".repeat(MAX_PKT + 10);
        let mut input = pkts(&[
            "git-filter-client\n",
            "version=2\n",
            "",
            "capability=clean\n",
            "capability=smudge\n",
            "capability=delay\n",
            "",
            "command=clean\n",
            "pathname=a.env\n",
            "",
            "hello ",
            "world",
            "",
            "command=smudge\n",
            "pathname=b.env\n",
            "",
            "",
        ]);
        // A file larger than one packet.
        input.extend(pkts(&["command=clean\n", "pathname=big\n", ""]));
        input.extend(pkts(&[&big[..MAX_PKT], &big[MAX_PKT..], ""]));

        let mut output = Vec::new();
        serve(&mut input.as_slice(), &mut output, &mut Upper).unwrap();

        let mut r = output.as_slice();
        let mut list = || read_list(&mut r).unwrap().unwrap();
        assert_eq!(list(), ["git-filter-server", "version=2"]);
        assert_eq!(list(), ["capability=clean", "capability=smudge"]);
        assert_eq!(list(), ["status=success"]);
        let mut r2 = r;
        assert_eq!(read_content(&mut r2).unwrap(), b"HELLO WORLD");
        assert_eq!(read_list(&mut r2).unwrap().unwrap(), Vec::<String>::new());
        assert_eq!(read_list(&mut r2).unwrap().unwrap(), ["status=error"]);
        assert_eq!(read_list(&mut r2).unwrap().unwrap(), ["status=success"]);
        assert_eq!(
            read_content(&mut r2).unwrap(),
            big.to_uppercase().as_bytes()
        );
        assert_eq!(read_list(&mut r2).unwrap().unwrap(), Vec::<String>::new());
        assert_eq!(read_pkt(&mut r2).unwrap(), Pkt::Eof);
    }
}
