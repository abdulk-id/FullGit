//! Per-clone setup: the filter and diff drivers for secrets, and hooks.

use std::path::{Path, PathBuf};

use git2::Repository;

use crate::Result;
use crate::secret::DRIVER;

/// Marks hooks fullgit wrote, so it only ever rewrites its own.
const HOOK_MARKER: &str = "# Installed by fullgit.";

pub const HOOKS: [&str; 2] = ["pre-commit", "pre-push"];

/// Points git's `fullgit` filter and diff drivers at `exe`.
///
/// The filter is `required`: if sealing fails, `git add` fails instead of
/// storing plaintext. Smudge never fails; it leaves files sealed instead.
pub fn install_drivers(repo: &Repository, exe: &Path) -> Result<()> {
    let exe: String = sh_quote(&exe.display().to_string());
    let mut config: git2::Config = repo.config()?;
    config.set_str(
        &format!("filter.{DRIVER}.process"),
        &format!("{exe} filter-process"),
    )?;
    config.set_bool(&format!("filter.{DRIVER}.required"), true)?;
    config.set_str(
        &format!("diff.{DRIVER}.textconv"),
        &format!("{exe} textconv"),
    )?;
    Ok(())
}

/// Whether the drivers are configured, and the command they run.
pub fn drivers(repo: &Repository) -> Result<Option<String>> {
    Ok(repo
        .config()?
        .get_string(&format!("filter.{DRIVER}.process"))
        .ok())
}

#[derive(Debug, PartialEq, Eq)]
pub enum Hook {
    Installed,
    Unchanged,
    /// Not installed, with the reason.
    Skipped(String),
}

pub fn install_hook(repo: &Repository, name: &str, exe: &Path) -> Result<Hook> {
    let Some(dir) = hooks_dir(repo)? else {
        return Ok(Hook::Skipped(format!(
            "core.hooksPath is set; call `fullgit hook {name}` from your {name} hook"
        )));
    };
    let path: PathBuf = dir.join(name);
    let script: String = format!(
        "#!/bin/sh\n{HOOK_MARKER} `fullgit init` rewrites this file.\nexec {} hook {name} \"$@\"\n",
        sh_quote(&exe.display().to_string())
    );
    match std::fs::read_to_string(&path) {
        Ok(existing) if existing == script => return Ok(Hook::Unchanged),
        Ok(existing) if !existing.contains(HOOK_MARKER) => {
            return Ok(Hook::Skipped(format!(
                "{} exists; add `fullgit hook {name} \"$@\"` to it",
                path.display()
            )));
        }
        _ => {}
    }
    std::fs::create_dir_all(&dir)?;
    std::fs::write(&path, script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(Hook::Installed)
}

/// Whether hook `name` runs fullgit.
pub fn hook_installed(repo: &Repository, name: &str) -> Result<bool> {
    Ok(match hooks_dir(repo)? {
        Some(dir) => std::fs::read_to_string(dir.join(name))
            .is_ok_and(|s| s.contains(HOOK_MARKER) || s.contains("fullgit hook")),
        None => false,
    })
}

/// `$GIT_DIR/hooks`, or `None` if `core.hooksPath` points elsewhere (often
/// a tracked directory, which fullgit shouldn't edit).
fn hooks_dir(repo: &Repository) -> Result<Option<PathBuf>> {
    if repo.config()?.get_path("core.hooksPath").is_ok() {
        return Ok(None);
    }
    Ok(Some(repo.path().join("hooks")))
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}
