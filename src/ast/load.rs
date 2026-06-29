//! AST loading from multiple sources.
//!
//! Supports three ways to obtain a Clang JSON AST:
//!
//! 1. **Pre-generated JSON** — the user runs their own clang command
//!    with the right flags and provides the JSON file directly.
//!
//! 2. **compile_commands.json** — the user points at a compilation
//!    database (as produced by CMake, Bear, etc.) and we replay the
//!    recorded clang command with `-ast-dump=json` injected.
//!
//! 3. **Direct clang invocation** — we run a bare `clang -target bpf`
//!    command ourselves. Only works for simple programmes without
//!    complex include paths or defines.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use super::clang_ast::Node;

/// Parsed Clang JSON AST with the source filename for filtering.
pub struct LoadedAst {
    pub root: Node,
    pub source_name: String,
}

/// Load an AST from a pre-generated JSON file (or stdin if path is "-").
pub fn load_from_json(json_path: &Path, source_name: &str) -> Result<LoadedAst> {
    let data = if json_path == Path::new("-") {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("reading JSON AST from stdin")?;
        buf
    } else {
        std::fs::read(json_path)
            .with_context(|| format!("reading JSON AST from {}", json_path.display()))?
    };

    let root: Node = serde_json::from_slice(&data)
        .context("parsing Clang JSON AST")?;

    Ok(LoadedAst {
        root,
        source_name: source_name.to_string(),
    })
}

/// Load an AST by running clang directly on a source file.
///
/// This is the simple path — it works for programmes that don't need
/// special include paths or defines beyond `-target bpf`.
pub fn load_from_source(source_path: &Path) -> Result<LoadedAst> {
    let output = Command::new("clang")
        .args(["-target", "bpf", "-Xclang", "-ast-dump=json", "-fsyntax-only"])
        .arg(source_path)
        .output()
        .context("running clang")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("clang failed:\n{stderr}");
    }

    let root: Node = serde_json::from_slice(&output.stdout)
        .context("parsing Clang JSON AST")?;

    let source_name = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    Ok(LoadedAst { root, source_name })
}

/// A single entry from compile_commands.json.
#[derive(Debug, serde::Deserialize)]
struct CompileCommand {
    /// The working directory for the command.
    directory: String,
    /// The source file (absolute or relative to directory).
    file: String,
    /// The compile command as a single string (optional).
    command: Option<String>,
    /// The compile command as an argument vector (optional).
    arguments: Option<Vec<String>>,
}

/// Load an AST using a compile_commands.json compilation database.
///
/// Finds the entry for `source_path`, extracts the clang flags, and
/// replays the command with `-Xclang -ast-dump=json -fsyntax-only`
/// replacing the original output flags.
pub fn load_from_compile_commands(
    db_path: &Path,
    source_path: &Path,
) -> Result<LoadedAst> {
    let db_data = std::fs::read_to_string(db_path)
        .with_context(|| format!("reading {}", db_path.display()))?;

    let entries: Vec<CompileCommand> = serde_json::from_str(&db_data)
        .with_context(|| format!("parsing {}", db_path.display()))?;

    // Canonicalise the source path for matching.
    let canon_source = std::fs::canonicalize(source_path)
        .unwrap_or_else(|_| source_path.to_path_buf());

    let entry = find_compile_entry(&entries, &canon_source)
        .with_context(|| {
            let files: Vec<&str> = entries.iter().map(|e| e.file.as_str()).collect();
            format!(
                "no entry for '{}' in {}.\navailable files: {:?}",
                source_path.display(),
                db_path.display(),
                files
            )
        })?;

    let args = extract_clang_args(entry)?;
    let workdir = PathBuf::from(&entry.directory);

    eprintln!(
        "compile_commands.json: replaying clang for {}",
        source_path.display()
    );

    let mut cmd = Command::new(&args[0]);
    cmd.current_dir(&workdir);

    // Inject AST dump flags, skip output-related flags from the
    // original command.
    let mut skip_next = false;
    for arg in &args[1..] {
        if skip_next {
            skip_next = false;
            continue;
        }
        // Skip flags that conflict with -fsyntax-only / -ast-dump
        match arg.as_str() {
            "-o" | "--output" => {
                skip_next = true;
                continue;
            }
            "-c" => continue,
            s if s.starts_with("-o") && s.len() > 2 => continue,
            _ => {}
        }
        cmd.arg(arg);
    }

    cmd.args(["-Xclang", "-ast-dump=json", "-fsyntax-only"]);

    let output = cmd.output().context("running clang from compile_commands.json")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("clang (from compile_commands.json) failed:\n{stderr}");
    }

    let root: Node = serde_json::from_slice(&output.stdout)
        .context("parsing Clang JSON AST")?;

    let source_name = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    Ok(LoadedAst { root, source_name })
}

/// Find the compile_commands.json entry matching a source file.
fn find_compile_entry<'a>(
    entries: &'a [CompileCommand],
    canon_source: &Path,
) -> Option<&'a CompileCommand> {
    for entry in entries {
        // The file field may be absolute or relative to directory.
        let entry_path = if Path::new(&entry.file).is_absolute() {
            PathBuf::from(&entry.file)
        } else {
            PathBuf::from(&entry.directory).join(&entry.file)
        };

        let canon_entry = std::fs::canonicalize(&entry_path)
            .unwrap_or(entry_path);

        if canon_entry == canon_source {
            return Some(entry);
        }
    }

    // Fallback: match by filename only (for when paths don't
    // canonicalise cleanly, e.g. in containers).
    let source_name = canon_source.file_name()?;
    for entry in entries {
        let entry_name = Path::new(&entry.file).file_name();
        if entry_name == Some(source_name) {
            return Some(entry);
        }
    }

    None
}

/// Extract the argument vector from a compile_commands entry.
///
/// compile_commands.json supports two formats:
/// - `arguments`: a JSON array of strings (preferred)
/// - `command`: a single shell command string (needs splitting)
fn extract_clang_args(entry: &CompileCommand) -> Result<Vec<String>> {
    if let Some(ref args) = entry.arguments {
        if args.is_empty() {
            bail!("empty arguments array in compile_commands.json entry");
        }
        return Ok(args.clone());
    }

    if let Some(ref cmd) = entry.command {
        let args = shlex::split(cmd)
            .context("failed to parse command string in compile_commands.json")?;
        if args.is_empty() {
            bail!("empty command in compile_commands.json entry");
        }
        return Ok(args);
    }

    bail!("compile_commands.json entry has neither 'arguments' nor 'command'");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_args_from_arguments_field() {
        let entry = CompileCommand {
            directory: "/build".into(),
            file: "main.c".into(),
            command: None,
            arguments: Some(vec![
                "clang".into(),
                "-target".into(),
                "bpf".into(),
                "-c".into(),
                "main.c".into(),
            ]),
        };
        let args = extract_clang_args(&entry).unwrap();
        assert_eq!(args[0], "clang");
        assert!(args.contains(&"-target".to_string()));
    }

    #[test]
    fn extract_args_from_command_field() {
        let entry = CompileCommand {
            directory: "/build".into(),
            file: "main.c".into(),
            command: Some("clang -target bpf -c main.c".into()),
            arguments: None,
        };
        let args = extract_clang_args(&entry).unwrap();
        assert_eq!(args[0], "clang");
        assert!(args.contains(&"-target".to_string()));
    }

    #[test]
    fn extract_args_from_command_field_with_quotes() {
        let entry = CompileCommand {
            directory: "/build".into(),
            file: "main.c".into(),
            command: Some(r#"clang -DFOO="bar baz" -target bpf -c main.c"#.into()),
            arguments: None,
        };
        let args = extract_clang_args(&entry).unwrap();
        assert_eq!(args[0], "clang");
        assert!(args.contains(&"bar baz".to_string()) || args.contains(&"-DFOO=bar baz".to_string()));
    }

    #[test]
    fn extract_args_neither_field() {
        let entry = CompileCommand {
            directory: "/build".into(),
            file: "main.c".into(),
            command: None,
            arguments: None,
        };
        assert!(extract_clang_args(&entry).is_err());
    }

    #[test]
    fn find_entry_by_absolute_path() {
        let entries = vec![CompileCommand {
            directory: "/home/user/project".into(),
            file: "/home/user/project/src/main.c".into(),
            command: Some("clang -c src/main.c".into()),
            arguments: None,
        }];
        let result = find_compile_entry(&entries, Path::new("/home/user/project/src/main.c"));
        assert!(result.is_some());
    }

    #[test]
    fn find_entry_by_relative_path() {
        let entries = vec![CompileCommand {
            directory: "/home/user/project".into(),
            file: "src/main.c".into(),
            command: Some("clang -c src/main.c".into()),
            arguments: None,
        }];
        // Fallback to filename matching when canonicalisation fails
        let result = find_compile_entry(&entries, Path::new("/somewhere/else/main.c"));
        assert!(result.is_some());
    }

    #[test]
    fn find_entry_no_match() {
        let entries = vec![CompileCommand {
            directory: "/build".into(),
            file: "other.c".into(),
            command: Some("clang -c other.c".into()),
            arguments: None,
        }];
        let result = find_compile_entry(&entries, Path::new("/build/main.c"));
        assert!(result.is_none());
    }
}
