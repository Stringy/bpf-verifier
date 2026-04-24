# Verification Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When verification fails, show the user which check failed, what the normalised proof obligation looks like, the relevant spec postcondition, and BPF source locations — instead of just "FAIL: test does not satisfy spec".

**Architecture:** Parse F*'s stderr to extract labelled `dump` output (already emitted by the tactics we modified: `NORMALISED_GOAL`, `TYPE_SAFETY_GOAL`, `NULL_SAFETY_GOAL`, `STACK_BOUNDS_GOAL`). Also parse JSON-formatted errors via `--message_format json` to identify which proof declaration failed. Combine with the spec file content and DWARF source locations from the generated F* source to produce a structured diagnostic message.

**Tech Stack:** Rust, serde_json (new dependency for parsing F* JSON errors)

---

## File Structure

- **`src/verify/diagnostic.rs`** (create) — Parse F* output into structured diagnostics. Contains: `FstarDiagnostic` struct, `parse_fstar_output()` function, `extract_goal()` helper.
- **`src/verify/runner.rs`** (modify) — Change `VerifyResult::Fail` to carry structured diagnostics. Add `--message_format json` to the F* invocation.
- **`src/verify/mod.rs`** (modify) — Export the new `diagnostic` module.
- **`src/main.rs`** (modify) — Replace the one-line "FAIL" message with formatted diagnostic output. Read spec file on failure, extract source locations from generated F* source.

---

### Task 1: Parse F* dump output

**Files:**
- Create: `src/verify/diagnostic.rs`
- Modify: `src/verify/mod.rs`

The F* `dump` output has this format on stderr:
```
proof-state: State dump @ depth 0 (NORMALISED_GOAL):
Location: Verify_test.fst(61,2-61,35)
Goal 1/1

  |-
  _
  :
  squash (forall (init: bpf_state).
        l_True ==> Scalar 1uL == Scalar 0uL \/ Scalar 1uL == Scalar 5uL)
```

We need to extract the label and the goal type.

- [ ] **Step 1: Write test for parsing a single dump block**

```rust
// In src/verify/diagnostic.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normalised_goal_dump() {
        let stderr = r#"proof-state: State dump @ depth 0 (NORMALISED_GOAL):
Location: Verify_test.fst(61,2-61,35)
Goal 1/1

  |-
  _
  :
  squash (forall (init: bpf_state).
        l_True ==> Scalar 1uL == Scalar 0uL \/ Scalar 1uL == Scalar 5uL)

* Error 19 at /tmp/Verify_test.fst(61,2-61,3):
  - Assertion failed
"#;
        let dumps = parse_dumps(stderr);
        assert_eq!(dumps.len(), 1);
        assert_eq!(dumps[0].label, "NORMALISED_GOAL");
        assert!(dumps[0].goal.contains("Scalar 1uL == Scalar 0uL"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test parse_normalised_goal_dump`
Expected: FAIL — `parse_dumps` not defined

- [ ] **Step 3: Implement `parse_dumps`**

```rust
// In src/verify/diagnostic.rs

/// A single dump block extracted from F* tactic output.
#[derive(Debug, Clone)]
pub struct DumpBlock {
    /// The label passed to `dump` in the tactic (e.g. "NORMALISED_GOAL").
    pub label: String,
    /// The goal type as printed by F* (everything after the `:` line).
    pub goal: String,
}

/// Parse F*'s stderr for `proof-state: State dump` blocks.
///
/// Each block starts with `proof-state: State dump @ depth N (LABEL):`
/// and contains a goal after the `  :` line. Blocks end at the next
/// `proof-state:` line or at an `* Error` / `* Warning` line.
pub fn parse_dumps(stderr: &str) -> Vec<DumpBlock> {
    let mut dumps = Vec::new();
    let mut lines = stderr.lines().peekable();

    while let Some(line) = lines.next() {
        // Look for dump header: "proof-state: State dump @ depth N (LABEL):"
        let Some(label) = extract_dump_label(line) else {
            continue;
        };

        // Skip lines until we find the goal type marker "  :"
        let mut found_colon = false;
        let mut goal_lines = Vec::new();

        for line in lines.by_ref() {
            if !found_colon {
                if line.trim() == ":" {
                    found_colon = true;
                }
                continue;
            }

            // Stop at the next dump block or F* error/warning
            if line.starts_with("proof-state:") || line.starts_with("* ") {
                break;
            }

            goal_lines.push(line);
        }

        if found_colon {
            let goal = goal_lines.join("\n").trim().to_string();
            dumps.push(DumpBlock { label, goal });
        }
    }

    dumps
}

fn extract_dump_label(line: &str) -> Option<String> {
    // Pattern: "proof-state: State dump @ depth N (LABEL):"
    let rest = line.strip_prefix("proof-state: State dump")?;
    let open = rest.find('(')?;
    let close = rest.find(')')?;
    if open < close {
        Some(rest[open + 1..close].to_string())
    } else {
        None
    }
}
```

- [ ] **Step 4: Add module to `src/verify/mod.rs`**

Add `pub mod diagnostic;` to `src/verify/mod.rs`.

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test parse_normalised_goal_dump`
Expected: PASS

- [ ] **Step 6: Write test for multiple dump blocks**

```rust
#[test]
fn parse_multiple_dumps() {
    let stderr = r#"proof-state: State dump @ depth 0 (TYPE_SAFETY_GOAL):
Location: Verify_test.fst(49,2-49,26)
Goal 1/1

  |- _ : squash (true == true)

proof-state: State dump @ depth 0 (NULL_SAFETY_GOAL):
Location: Verify_test.fst(55,2-55,26)
Goal 1/1

  |- _ : squash (true == true)

proof-state: State dump @ depth 0 (NORMALISED_GOAL):
Location: Verify_test.fst(61,2-61,35)
Goal 1/1

  |-
  _
  :
  squash (forall (init: bpf_state).
        l_True ==> Scalar 1uL == Scalar 0uL \/ Scalar 1uL == Scalar 5uL)

* Error 19 at /tmp/Verify_test.fst(61,2-61,3):
"#;
    let dumps = parse_dumps(stderr);
    assert_eq!(dumps.len(), 3);
    assert_eq!(dumps[0].label, "TYPE_SAFETY_GOAL");
    assert_eq!(dumps[1].label, "NULL_SAFETY_GOAL");
    assert_eq!(dumps[2].label, "NORMALISED_GOAL");
    // Safety goals normalise to trivial
    assert!(dumps[0].goal.contains("true == true"));
    // Functional goal shows the actual obligation
    assert!(dumps[2].goal.contains("Scalar 1uL"));
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `cargo test parse_multiple_dumps`
Expected: PASS (implementation already handles multiple blocks)

- [ ] **Step 8: Commit**

```
git add src/verify/diagnostic.rs src/verify/mod.rs
git commit -m "feat: parse F* dump output into structured diagnostics"
```

---

### Task 2: Identify which proof failed from F* JSON errors

**Files:**
- Modify: `Cargo.toml` (add serde_json)
- Modify: `src/verify/runner.rs`
- Modify: `src/verify/diagnostic.rs`

F* with `--message_format json` emits one JSON object per line on stderr for errors. The `ctx` field tells us which declaration failed:
```json
{"msg":["Assertion failed","..."],"level":"Error","number":19,
 "ctx":["While synthesizing term with a tactic",
        "While typechecking the top-level declaration `let proof`"]}
```

The dump blocks (`proof-state: ...`) are still emitted as plain text, interleaved with the JSON lines.

- [ ] **Step 1: Add serde_json dependency**

Run: `cargo add serde_json`

- [ ] **Step 2: Write test for identifying the failed proof stage**

```rust
// In src/verify/diagnostic.rs

#[test]
fn identify_failed_proof_from_json() {
    let stderr = r#"{"msg":["Assertion failed"],"level":"Error","number":19,"range":{"def":{"file_name":"/tmp/Verify_test.fst","start_pos":{"line":61,"col":2},"end_pos":{"line":61,"col":35}},"use":{"file_name":"/tmp/Verify_test.fst","start_pos":{"line":61,"col":2},"end_pos":{"line":61,"col":3}}},"number":19,"ctx":["While synthesizing term with a tactic","While typechecking the top-level declaration `let proof`"]}"#;
    let stage = parse_failed_stage(stderr);
    assert_eq!(stage, Some(FailedStage::FunctionalCorrectness));
}

#[test]
fn identify_type_safety_failure() {
    let stderr = r#"{"msg":["tactic failed"],"level":"Error","number":228,"ctx":["While typechecking the top-level declaration `let ts_proof`"]}"#;
    let stage = parse_failed_stage(stderr);
    assert_eq!(stage, Some(FailedStage::TypeSafety));
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test identify_failed_proof`
Expected: FAIL — `parse_failed_stage` and `FailedStage` not defined

- [ ] **Step 4: Implement `FailedStage` and `parse_failed_stage`**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailedStage {
    StackBounds,
    TypeSafety,
    NullSafety,
    FunctionalCorrectness,
}

impl std::fmt::Display for FailedStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StackBounds => write!(f, "stack bounds safety"),
            Self::TypeSafety => write!(f, "type safety"),
            Self::NullSafety => write!(f, "null safety"),
            Self::FunctionalCorrectness => write!(f, "functional correctness"),
        }
    }
}

/// Parse F* JSON error output to determine which proof stage failed.
///
/// Looks for Error-level JSON objects whose `ctx` field names a known
/// proof declaration (`let proof`, `let ts_proof`, `let ns_proof`,
/// or an `assert_norm` for stack bounds witnesses).
pub fn parse_failed_stage(stderr: &str) -> Option<FailedStage> {
    for line in stderr.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if obj.get("level").and_then(|l| l.as_str()) != Some("Error") {
            continue;
        }
        let ctx = obj.get("ctx").and_then(|c| c.as_array());
        let Some(ctx) = ctx else { continue };
        for entry in ctx {
            let Some(s) = entry.as_str() else { continue };
            if s.contains("`let proof`") {
                return Some(FailedStage::FunctionalCorrectness);
            }
            if s.contains("`let ts_proof`") {
                return Some(FailedStage::TypeSafety);
            }
            if s.contains("`let ns_proof`") {
                return Some(FailedStage::NullSafety);
            }
            if s.contains("`let sb_proof`") || s.contains("assert_norm") {
                return Some(FailedStage::StackBounds);
            }
        }
    }
    None
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test identify_failed_proof && cargo test identify_type_safety`
Expected: PASS

- [ ] **Step 6: Add `--message_format json` to the F* invocation in runner.rs**

In `src/verify/runner.rs`, modify the `verify` method to add the flag:

```rust
// In the verify method, after the existing args:
cmd.args(["--message_format", "json"]);
```

- [ ] **Step 7: Run full test suite**

Run: `cargo test`
Expected: All 47 tests pass. The JSON format doesn't change success/failure exit codes.

- [ ] **Step 8: Commit**

```
git add Cargo.toml Cargo.lock src/verify/diagnostic.rs src/verify/runner.rs
git commit -m "feat: parse F* JSON errors to identify which proof stage failed"
```

---

### Task 3: Extract spec postcondition and source locations

**Files:**
- Modify: `src/verify/diagnostic.rs`

When reporting a failure, we want to show:
1. The postcondition from the user's spec file (with line numbers)
2. The BPF C source locations from the generated F* comments

- [ ] **Step 1: Write test for extracting spec postcondition**

```rust
#[test]
fn extract_spec_postcondition() {
    let spec_content = r#"module BranchResult

open FStar.UInt64
open BPF.State
open BPF.Spec

(* The map lookup can succeed or fail, so there are two possible
   return values. The spec captures both branches as a disjunction. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 0uL \/
    state_get_reg final_st r0 == Scalar 5uL
  )
"#;
    let post = extract_postcondition(spec_content);
    assert!(post.is_some());
    let post = post.unwrap();
    assert_eq!(post.start_line, 10);
    assert!(post.text.contains("Scalar 0uL"));
    assert!(post.text.contains("Scalar 5uL"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test extract_spec_postcondition`
Expected: FAIL

- [ ] **Step 3: Implement `extract_postcondition`**

```rust
/// A postcondition extracted from a spec file, with its location.
#[derive(Debug, Clone)]
pub struct SpecPostcondition {
    /// 1-based line number where the spec definition starts.
    pub start_line: usize,
    /// The text of the spec definition (from `let spec` to the end).
    pub text: String,
}

/// Extract the spec definition from a spec file's contents.
///
/// Looks for `let spec` (the conventional name for user specs) and
/// captures everything from that line to the next blank line or EOF.
pub fn extract_postcondition(spec_content: &str) -> Option<SpecPostcondition> {
    let lines: Vec<&str> = spec_content.lines().collect();
    let start = lines.iter().position(|l| l.starts_with("let spec"))?;
    let mut end = lines.len();
    for i in (start + 1)..lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.is_empty() || (trimmed.starts_with("let ") && !trimmed.starts_with("let spec")) {
            end = i;
            break;
        }
    }
    let text = lines[start..end].join("\n");
    Some(SpecPostcondition {
        start_line: start + 1,
        text,
    })
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test extract_spec_postcondition`
Expected: PASS

- [ ] **Step 5: Write test for extracting C source locations from generated F***

```rust
#[test]
fn extract_source_locations_from_generated() {
    let generated = r#"let program : bpf_program = [
  BPF_ALU32_IMM MOV r1 (0l)  (* BranchResult.bpf.c:13 *);
  BPF_STX W32 r10 r1 (-4l)  (* BranchResult.bpf.c:14 *);
  BPF_CALL MAP_LOOKUP_ELEM  (* BranchResult.bpf.c:15 *);
  BPF_JMP64_IMM JNE r1 (0l) (1)  (* BranchResult.bpf.c:16 *);
  BPF_ALU32_IMM MOV r0 (0l);
  BPF_EXIT  (* BranchResult.bpf.c:19 *)
]"#;
    let locs = extract_source_locations(generated);
    assert_eq!(locs.len(), 5);
    assert_eq!(locs[0], "BranchResult.bpf.c:13");
    assert_eq!(locs[4], "BranchResult.bpf.c:19");
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cargo test extract_source_locations_from_generated`
Expected: FAIL

- [ ] **Step 7: Implement `extract_source_locations`**

```rust
/// Extract unique C source locations from the generated F* source.
///
/// The codegen annotates each instruction with `(* file:line *)` comments
/// from DWARF debug info. This extracts a deduplicated, ordered list.
pub fn extract_source_locations(generated_source: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut locs = Vec::new();

    for line in generated_source.lines() {
        if let Some(start) = line.find("(* ") {
            if let Some(end) = line[start..].find(" *)") {
                let loc = &line[start + 3..start + end];
                if loc.contains(':') && !loc.contains("Stack") && seen.insert(loc.to_string()) {
                    locs.push(loc.to_string());
                }
            }
        }
    }

    locs
}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `cargo test extract_source_locations_from_generated`
Expected: PASS

- [ ] **Step 9: Commit**

```
git add src/verify/diagnostic.rs
git commit -m "feat: extract spec postcondition and source locations for diagnostics"
```

---

### Task 4: Assemble and format diagnostic output

**Files:**
- Modify: `src/verify/diagnostic.rs`

Combine all the parsed information into a formatted diagnostic message.

- [ ] **Step 1: Write test for formatting a functional correctness failure**

```rust
#[test]
fn format_functional_failure_diagnostic() {
    let diag = Diagnostic {
        stage: FailedStage::FunctionalCorrectness,
        normalised_goal: Some("squash (forall (init: bpf_state).\n        l_True ==> Scalar 1uL == Scalar 0uL \\/ Scalar 1uL == Scalar 5uL)".to_string()),
        spec_file: Some("BranchResult.fst".to_string()),
        spec_postcondition: Some(SpecPostcondition {
            start_line: 10,
            text: "let spec : bpf_spec =\n  post_only (fun final_st ->\n    state_get_reg final_st r0 == Scalar 0uL \\/\n    state_get_reg final_st r0 == Scalar 5uL\n  )".to_string(),
        }),
        source_locations: vec![
            "BranchResult.bpf.c:15".to_string(),
            "BranchResult.bpf.c:16".to_string(),
            "BranchResult.bpf.c:19".to_string(),
        ],
    };
    let output = diag.format();
    assert!(output.contains("functional correctness"));
    assert!(output.contains("Scalar 1uL == Scalar 0uL"));
    assert!(output.contains("BranchResult.fst:10"));
    assert!(output.contains("BranchResult.bpf.c:15"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test format_functional_failure`
Expected: FAIL — `Diagnostic` not defined

- [ ] **Step 3: Implement `Diagnostic` struct and `format` method**

```rust
/// All information needed to display a verification failure to the user.
#[derive(Debug)]
pub struct Diagnostic {
    pub stage: FailedStage,
    pub normalised_goal: Option<String>,
    pub spec_file: Option<String>,
    pub spec_postcondition: Option<SpecPostcondition>,
    pub source_locations: Vec<String>,
}

impl Diagnostic {
    /// Format the diagnostic as a human-readable error message.
    pub fn format(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!("  {self.stage} check failed\n"));

        if let Some(goal) = &self.normalised_goal {
            out.push_str("\n  Normalised proof obligation (what F* tried to prove):\n");
            for line in goal.lines() {
                out.push_str(&format!("    {line}\n"));
            }
        }

        if let (Some(file), Some(post)) = (&self.spec_file, &self.spec_postcondition) {
            out.push_str(&format!("\n  Spec ({file}:{}):\n", post.start_line));
            for line in post.text.lines() {
                out.push_str(&format!("    {line}\n"));
            }
        }

        if !self.source_locations.is_empty() {
            out.push_str("\n  BPF source locations:\n");
            for loc in &self.source_locations {
                out.push_str(&format!("    {loc}\n"));
            }
        }

        out
    }

    /// Build a diagnostic from F* output and context.
    pub fn from_fstar_output(
        stderr: &str,
        generated_source: &str,
        spec_file: Option<&str>,
        spec_content: Option<&str>,
    ) -> Option<Self> {
        let stage = parse_failed_stage(stderr)?;

        let dumps = parse_dumps(stderr);
        let normalised_goal = dumps.iter()
            .find(|d| d.label == "NORMALISED_GOAL")
            .map(|d| d.goal.clone());

        let spec_postcondition = spec_content.and_then(extract_postcondition);
        let source_locations = extract_source_locations(generated_source);

        Some(Diagnostic {
            stage,
            normalised_goal,
            spec_file: spec_file.map(String::from),
            spec_postcondition,
            source_locations,
        })
    }
}
```

Note: the `format` method uses `self.stage` via its `Display` impl, not raw struct field access. The exact format string is: `format!("  {} check failed\n", self.stage)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test format_functional_failure`
Expected: PASS

- [ ] **Step 5: Write test for `from_fstar_output` integration**

```rust
#[test]
fn build_diagnostic_from_fstar_output() {
    let stderr = concat!(
        "proof-state: State dump @ depth 0 (NORMALISED_GOAL):\n",
        "Location: Verify_test.fst(61,2-61,35)\n",
        "Goal 1/1\n",
        "\n",
        "  |-\n",
        "  _\n",
        "  :\n",
        "  squash (Scalar 1uL == Scalar 5uL)\n",
        "\n",
        r#"{"msg":["Assertion failed"],"level":"Error","number":19,"ctx":["While typechecking the top-level declaration `let proof`"]}"#,
        "\n",
    );
    let generated = "BPF_EXIT  (* test.bpf.c:10 *)";
    let spec = "module T\nopen BPF.Spec\nlet spec : bpf_spec =\n  returns_value 5uL\n";

    let diag = Diagnostic::from_fstar_output(stderr, generated, Some("T.fst"), Some(spec));
    assert!(diag.is_some());
    let diag = diag.unwrap();
    assert_eq!(diag.stage, FailedStage::FunctionalCorrectness);
    assert!(diag.normalised_goal.unwrap().contains("Scalar 1uL"));
    assert_eq!(diag.source_locations, vec!["test.bpf.c:10"]);
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cargo test build_diagnostic_from_fstar_output`
Expected: PASS

- [ ] **Step 7: Commit**

```
git add src/verify/diagnostic.rs
git commit -m "feat: assemble and format structured verification diagnostics"
```

---

### Task 5: Wire diagnostics into runner and main

**Files:**
- Modify: `src/verify/runner.rs`
- Modify: `src/main.rs`

Connect the diagnostic pipeline: runner returns raw stderr, main builds and displays the diagnostic.

- [ ] **Step 1: Change `VerifyResult::Fail` to carry both stdout and stderr separately**

In `src/verify/runner.rs`, modify:

```rust
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyResult {
    Pass,
    Fail { stderr: String },
}
```

And update the `verify` method to always populate stderr:

```rust
if output.status.success() {
    Ok(VerifyResult::Pass)
} else {
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    Ok(VerifyResult::Fail { stderr })
}
```

- [ ] **Step 2: Update main.rs to build and display diagnostics on failure**

In `src/main.rs`, modify the `verify_program` function. Change the `VerifyResult::Fail` arm to build a diagnostic:

```rust
Ok(VerifyResult::Fail { stderr }) => {
    if verbose {
        eprintln!("{stderr}");
    }

    // Build diagnostic from F* output
    let spec_content = spec_path.and_then(|p| std::fs::read_to_string(p).ok());
    let spec_filename = spec_path
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(String::from);

    if let Some(diag) = Diagnostic::from_fstar_output(
        &stderr,
        &fstar_source,
        spec_filename.as_deref(),
        spec_content.as_deref(),
    ) {
        eprintln!("{}", diag.format());
    }

    Ok(false)
}
```

This requires `fstar_source` to be available at the point where we handle the result. Currently `fstar_source` is a local variable in `verify_program` — it's already in scope, so no refactoring needed.

Add the import at the top of `main.rs`:
```rust
use bpf_verifier::verify::diagnostic::Diagnostic;
```

- [ ] **Step 3: Update the output line in `run_verify`**

Change the `Ok(false)` arm in `run_verify` to not duplicate the message:

```rust
Ok(false) => {
    println!("  FAIL: {} does not satisfy spec", prog.section_name);
    failed += 1;
}
```

This stays as-is — the diagnostic is printed to stderr by `verify_program`, and the FAIL summary goes to stdout. The diagnostic appears before the FAIL line because `verify_program` prints it.

- [ ] **Step 4: Run the full test suite**

Run: `cargo test`
Expected: All 47 tests pass

- [ ] **Step 5: Manual test with the broken BranchResult spec**

Temporarily change `tests/corpus/good/BranchResult.fst` to use `Scalar 5uL`, then run:
```
cargo run -- verify <obj> --spec "test:tests/corpus/good/BranchResult.fst"
```

Expected output should include the diagnostic showing the normalised goal, spec location, and source locations. Revert the spec change after testing.

- [ ] **Step 6: Commit**

```
git add src/verify/runner.rs src/main.rs
git commit -m "feat: display structured diagnostics on verification failure"
```

---

### Task 6: Handle non-JSON fallback

**Files:**
- Modify: `src/verify/diagnostic.rs`

If `--message_format json` causes issues with some F* versions, or if the JSON parsing finds no errors, fall back to identifying the stage from the plain-text `* Error` lines.

- [ ] **Step 1: Write test for plain-text fallback**

```rust
#[test]
fn fallback_to_plain_text_error() {
    let stderr = r#"* Error 19 at /tmp/Verify_test.fst(61,2-61,3):
  - Assertion failed
  - See also /tmp/Verify_test.fst(61,2-61,35)
"#;
    // No JSON lines — should fall back to plain text parsing
    let stage = parse_failed_stage(stderr);
    assert_eq!(stage, Some(FailedStage::FunctionalCorrectness));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test fallback_to_plain_text`
Expected: FAIL — current `parse_failed_stage` only looks at JSON lines

- [ ] **Step 3: Add plain-text fallback to `parse_failed_stage`**

After the JSON parsing loop, add a second pass that looks for `* Error` lines and extracts line numbers. Then check those line numbers against known proof declaration patterns in the generated source. However, since we don't have the generated source in `parse_failed_stage`, use a simpler heuristic: look for the `ctx` in the plain-text error:

```rust
// Plain-text F* errors don't include ctx, but we can match on
// the error message patterns from tactic failures
if stderr.contains("While typechecking the top-level declaration `let proof`") {
    return Some(FailedStage::FunctionalCorrectness);
}
// ... similar for ts_proof, ns_proof
```

Actually, plain-text F* output doesn't include the `ctx` field either. The simplest fallback: if we found dump blocks but no JSON errors, use the last dump block's label to infer the stage.

```rust
// At the end of parse_failed_stage, after the JSON loop returns None:
// Fallback: if the stderr has Error lines but no JSON, try matching
// dump labels — the last dump before an error is likely the failing stage
let dumps = parse_dumps(stderr);
if stderr.contains("* Error") || stderr.contains("Assertion failed") {
    if let Some(last) = dumps.last() {
        return match last.label.as_str() {
            "NORMALISED_GOAL" => Some(FailedStage::FunctionalCorrectness),
            "STACK_BOUNDS_GOAL" => Some(FailedStage::StackBounds),
            "TYPE_SAFETY_GOAL" => Some(FailedStage::TypeSafety),
            "NULL_SAFETY_GOAL" => Some(FailedStage::NullSafety),
            _ => None,
        };
    }
}
None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test fallback_to_plain_text`
Expected: PASS

Wait — this test has no dump blocks either. The fallback needs to handle the case with neither JSON nor dumps. In that case, the stage is unknown and we return `None`, which is fine — the diagnostic will just show the raw error. Update the test expectation:

```rust
#[test]
fn fallback_to_plain_text_error() {
    // No JSON, no dumps — can't determine stage
    let stderr = r#"* Error 19 at /tmp/Verify_test.fst(61,2-61,3):
  - Assertion failed
"#;
    let stage = parse_failed_stage(stderr);
    assert_eq!(stage, None);
}

#[test]
fn fallback_to_dump_labels() {
    let stderr = concat!(
        "proof-state: State dump @ depth 0 (NORMALISED_GOAL):\n",
        "Location: Verify_test.fst(61,2-61,35)\n",
        "Goal 1/1\n",
        "\n",
        "  |-\n",
        "  _\n",
        "  :\n",
        "  squash (Scalar 1uL == Scalar 5uL)\n",
        "\n",
        "* Error 19 at /tmp/Verify_test.fst(61,2-61,3):\n",
        "  - Assertion failed\n",
    );
    let stage = parse_failed_stage(stderr);
    assert_eq!(stage, Some(FailedStage::FunctionalCorrectness));
}
```

- [ ] **Step 5: Run all diagnostic tests**

Run: `cargo test diagnostic`
Expected: All pass

- [ ] **Step 6: Commit**

```
git add src/verify/diagnostic.rs
git commit -m "feat: fallback stage detection from dump labels when JSON unavailable"
```

---

### Task 7: End-to-end validation

**Files:**
- No file changes — validation only

- [ ] **Step 1: Run the full test suite**

Run: `cargo test`
Expected: All 47 tests pass

- [ ] **Step 2: Manual test — functional correctness failure**

Temporarily edit `tests/corpus/good/BranchResult.fst` to use `Scalar 5uL`, then:

```bash
cargo run -- verify <BranchResult.bpf.o path> --spec "test:tests/corpus/good/BranchResult.fst"
```

Expected output (on stderr + stdout) should look approximately like:

```
  functional correctness check failed

  Normalised proof obligation (what F* tried to prove):
    squash (forall (init: bpf_state).
          l_True ==> Scalar 1uL == Scalar 0uL \/ Scalar 1uL == Scalar 5uL)

  Spec (BranchResult.fst:10):
    let spec : bpf_spec =
      post_only (fun final_st ->
        state_get_reg final_st r0 == Scalar 0uL \/
        state_get_reg final_st r0 == Scalar 5uL
      )

  BPF source locations:
    BranchResult.bpf.c:13
    BranchResult.bpf.c:14
    BranchResult.bpf.c:15
    BranchResult.bpf.c:16
    BranchResult.bpf.c:19

  FAIL: test does not satisfy spec
```

Revert `BranchResult.fst` after testing.

- [ ] **Step 3: Manual test — crash-safety failure (no spec)**

Use one of the `bad/` corpus programmes without a spec:

```bash
cargo run -- verify <WrongReturn.bpf.o path>
```

Verify the diagnostic still works when no spec file is provided.

- [ ] **Step 4: Run clippy**

Run: `cargo clippy`
Expected: No warnings
