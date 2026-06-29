use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("F* binary not found at {0}")]
    FstarNotFound(PathBuf),
    #[error("failed to invoke F*: {0}")]
    FstarInvocation(std::io::Error),
}

pub enum VerifyResult {
    Pass,
    Fail { message: String },
}

pub struct FstarRunner {
    fstar_path: PathBuf,
    include_dirs: Vec<PathBuf>,
}

impl FstarRunner {
    pub fn new(fstar_path: PathBuf, include_dirs: Vec<PathBuf>) -> Self {
        Self {
            fstar_path,
            include_dirs,
        }
    }

    /// Look for the F* binary relative to the project root, falling back to
    /// a PATH lookup via `which`.
    pub fn find_fstar(project_root: &Path, include_dirs: Vec<PathBuf>) -> Result<Self, VerifyError> {
        let local = project_root.join("third_party/fstar/bin/fstar.exe");
        if local.is_file() {
            return Ok(Self::new(local, include_dirs));
        }

        if let Some(path) = which_fstar() {
            return Ok(Self::new(path, include_dirs));
        }

        Err(VerifyError::FstarNotFound(local))
    }

    /// Run F* on the given file and return whether verification succeeded.
    ///
    /// F* handles caching automatically via --cache_checked_modules.
    /// If .checked files exist next to the .fst files (from a previous
    /// make check-obj or container build), F* will skip re-verification.
    pub fn verify(&self, fstar_file: &Path) -> Result<VerifyResult, VerifyError> {
        let mut cmd = Command::new(&self.fstar_path);

        for dir in &self.include_dirs {
            cmd.arg("--include").arg(dir);
        }

        cmd.args(["--cache_checked_modules"]);
        cmd.args(["--fuel", "8", "--ifuel", "2", "--z3rlimit", "30"]);
        cmd.args(["--message_format", "json"]);

        cmd.arg(fstar_file);

        let output = cmd.output().map_err(VerifyError::FstarInvocation)?;

        if output.status.success() {
            Ok(VerifyResult::Pass)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let message = format!("{stdout}\n{stderr}");
            Ok(VerifyResult::Fail { message })
        }
    }
}

/// Try to locate `fstar.exe` on the system PATH using `which`.
fn which_fstar() -> Option<PathBuf> {
    let output = Command::new("which")
        .arg("fstar.exe")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let path_str = String::from_utf8_lossy(&output.stdout);
    let path_str = path_str.trim();
    if path_str.is_empty() {
        return None;
    }

    Some(PathBuf::from(path_str))
}
