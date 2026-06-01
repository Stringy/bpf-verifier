use std::path::Path;

use ariadne::{CharSet, Config, Label, Report, ReportKind};

/// A single dump block extracted from F* tactic output.
#[derive(Debug, Clone)]
pub struct DumpBlock {
    pub label: String,
    pub goal: String,
}

pub fn parse_dumps(stderr: &str) -> Vec<DumpBlock> {
    let mut dumps = Vec::new();
    let lines: Vec<&str> = stderr.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Look for dump block start
        if line.starts_with("proof-state: State dump")
            && let Some(label) = extract_dump_label(line)
        {
            // Skip lines until we find the goal type marker
            i += 1;
            let mut goal_lines = Vec::new();
            let mut found_colon = false;

            while i < lines.len() {
                let current = lines[i];

                if current.starts_with("proof-state: State dump")
                    || current.starts_with("* Error")
                    || current.starts_with("* Warning")
                    || current.starts_with('{')
                    || current.starts_with("TAC>>") {
                    break;
                }

                // Check for inline format: "  |- _ : squash (true == true)"
                if !found_colon && current.contains("|-") && current.contains(" : ") {
                    // Extract everything after " : "
                    if let Some(pos) = current.find(" : ") {
                        let goal_text = &current[pos + 3..];
                        goal_lines.push(goal_text.to_string());
                        found_colon = true;
                        i += 1;
                        continue;
                    }
                }

                // Check for multi-line format: a line whose trimmed content is just ":"
                if !found_colon && current.trim() == ":" {
                    found_colon = true;
                    i += 1;
                    continue;
                }

                // Collect goal lines after we've found the colon
                if found_colon {
                    goal_lines.push(current.to_string());
                }

                i += 1;
            }

            let goal = goal_lines.join("\n").trim().to_string();
            dumps.push(DumpBlock { label, goal });
            continue;
        }

        i += 1;
    }

    dumps
}

fn extract_dump_label(line: &str) -> Option<String> {
    line.find('(')
        .and_then(|start| {
            line[start + 1..].find(')')
                .map(|end| line[start + 1..start + 1 + end].to_string())
        })
}

/// Represents which proof stage failed during F* verification.
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
            FailedStage::StackBounds => write!(f, "stack bounds safety"),
            FailedStage::TypeSafety => write!(f, "type safety"),
            FailedStage::NullSafety => write!(f, "null safety"),
            FailedStage::FunctionalCorrectness => write!(f, "functional correctness"),
        }
    }
}

pub fn parse_failed_stage(stderr: &str) -> Option<FailedStage> {
    for line in stderr.lines() {
        if !line.starts_with('{') {
            continue;
        }

        let Ok(json) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };

        if json.get("level").and_then(|v| v.as_str()) != Some("Error") {
            continue;
        }

        let Some(ctx) = json.get("ctx").and_then(|v| v.as_array()) else {
            continue;
        };

        for ctx_item in ctx {
            let Some(ctx_str) = ctx_item.as_str() else {
                continue;
            };

            if ctx_str.contains("`let proof`") {
                return Some(FailedStage::FunctionalCorrectness);
            }
            if ctx_str.contains("`let ts_proof`") {
                return Some(FailedStage::TypeSafety);
            }
            if ctx_str.contains("`let ns_proof`") {
                return Some(FailedStage::NullSafety);
            }
            if ctx_str.contains("`let sb_proof`") || ctx_str.contains("assert_norm") {
                return Some(FailedStage::StackBounds);
            }
        }
    }

    let dumps = parse_dumps(stderr);
    if (stderr.contains("Error") || stderr.contains("Assertion failed"))
        && let Some(last) = dumps.last()
    {
        return match last.label.as_str() {
            "NORMALISED_GOAL" => Some(FailedStage::FunctionalCorrectness),
            "STACK_BOUNDS_GOAL" => Some(FailedStage::StackBounds),
            "TYPE_SAFETY_GOAL" => Some(FailedStage::TypeSafety),
            "NULL_SAFETY_GOAL" => Some(FailedStage::NullSafety),
            _ => None,
        };
    }

    None
}

/// Spec postcondition extracted from a spec file.
#[derive(Debug, Clone)]
pub struct SpecPostcondition {
    pub start_line: usize,  // 1-based, first line of the body (after `let spec = ...`)
    pub end_line: usize,    // 1-based, last line of the body
    pub text: String,
}

pub fn extract_postcondition(spec_content: &str) -> Option<SpecPostcondition> {
    let lines: Vec<&str> = spec_content.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("let spec") {
            let mut body_lines = Vec::new();
            let body_start = i + 1; // skip the `let spec` header line

            for &next_line in lines.iter().skip(i + 1) {
                if next_line.trim().is_empty() {
                    break;
                }
                if next_line.starts_with("let ") && !next_line.trim_start().starts_with("let spec") {
                    break;
                }
                body_lines.push(next_line);
            }

            if body_lines.is_empty() {
                // Single-line spec like `let spec = returns_value 42uL`
                return Some(SpecPostcondition {
                    start_line: i + 1,
                    end_line: i + 1,
                    text: line.to_string(),
                });
            }

            let end_line = body_start + body_lines.len(); // 1-based
            return Some(SpecPostcondition {
                start_line: body_start + 1, // 1-based
                end_line,
                text: body_lines.join("\n"),
            });
        }
    }

    None
}

/// An instruction from the generated F* source with its PC and source location.
#[derive(Debug, Clone)]
pub struct InstructionInfo {
    pub pc: usize,
    pub instruction: String,
    pub source_loc: Option<String>,
}

pub fn extract_r0_origin(dumps: &[DumpBlock]) -> Option<usize> {
    let dump = dumps.iter().find(|d| d.label == "R0_ORIGIN")?;
    let goal = dump.goal.trim();
    let eq_pos = goal.rfind(" == ")?;
    let after_eq = goal[eq_pos + 4..].trim().trim_end_matches(')');
    after_eq.trim().parse().ok()
}

pub fn extract_instruction_at_pc(generated_source: &str, pc: usize) -> Option<InstructionInfo> {
    let mut current_pc = 0;
    for line in generated_source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("BPF_") {
            continue;
        }

        if current_pc == pc {
            let (insn, loc) = if let Some(start) = trimmed.find("(* ")
                && let Some(end) = trimmed.rfind(" *)")
                && end > start
            {
                let insn = trimmed[..start].trim().trim_end_matches(';').trim();
                let loc = trimmed[start + 3..end].trim();
                (insn.to_string(), Some(loc.to_string()))
            } else {
                let insn = trimmed.trim_end_matches(';').trim();
                (insn.to_string(), None)
            };
            return Some(InstructionInfo {
                pc,
                instruction: insn,
                source_loc: loc,
            });
        }
        current_pc += 1;
    }
    None
}

/// Complete diagnostic information for a verification failure.
#[derive(Debug)]
pub struct Diagnostic {
    pub stage: FailedStage,
    pub r0_origin: Option<InstructionInfo>,
    pub spec_file: Option<String>,
    pub spec_content: Option<String>,
    pub spec_postcondition: Option<SpecPostcondition>,
    pub c_source_file: Option<String>,
    pub c_source_content: Option<String>,
    pub c_source_line: Option<u32>,
    pub normalised_goal: Option<String>,
}

/// Compute the byte offset of the start of a 1-based line in source text.
fn line_to_byte_offset(source: &str, line: usize) -> usize {
    source
        .lines()
        .take(line.saturating_sub(1))
        .map(|l| l.len() + 1) // +1 for newline
        .sum()
}

/// Compute the byte range spanning an entire 1-based line (excluding newline).
fn line_byte_range(source: &str, line: usize) -> std::ops::Range<usize> {
    let start = line_to_byte_offset(source, line);
    let line_text = source[start..].lines().next().unwrap_or("");
    start..start + line_text.len()
}


/// Try to resolve a C source file path: DWARF path first, then adjacent to the object file.
pub fn resolve_c_source(
    source_loc: &str,
    dwarf_paths: &[Option<crate::elf::parser::SourceLoc>],
    program_path: Option<&Path>,
) -> Option<(String, String)> {
    let (basename, _line_str) = source_loc.rsplit_once(':')?;

    // Try DWARF full path first
    if let Some(sl) = dwarf_paths.iter().filter_map(|s| s.as_ref()).find(|sl| sl.file == basename)
        && let Ok(content) = std::fs::read_to_string(&sl.path)
    {
        return Some((sl.path.clone(), content));
    }

    // Fall back to looking adjacent to the .bpf.o file
    if let Some(prog_path) = program_path
        && let Some(dir) = prog_path.parent()
    {
        let adjacent = dir.join(basename);
        if let Ok(content) = std::fs::read_to_string(&adjacent) {
            return Some((adjacent.display().to_string(), content));
        }
    }

    None
}

impl Diagnostic {
    pub fn from_fstar_output(
        stderr: &str,
        generated_source: &str,
        spec_file: Option<&str>,
        spec_content: Option<&str>,
    ) -> Option<Self> {
        let stage = parse_failed_stage(stderr)?;

        let dumps = parse_dumps(stderr);
        let normalised_goal = dumps
            .iter()
            .find(|d| d.label == "NORMALISED_GOAL")
            .map(|d| d.goal.clone());

        let r0_origin = extract_r0_origin(&dumps)
            .and_then(|pc| extract_instruction_at_pc(generated_source, pc));

        let spec_postcondition = spec_content.and_then(extract_postcondition);

        Some(Diagnostic {
            stage,
            r0_origin,
            spec_file: spec_file.map(|s| s.to_string()),
            spec_content: spec_content.map(|s| s.to_string()),
            spec_postcondition,
            c_source_file: None,
            c_source_content: None,
            c_source_line: None,
            normalised_goal,
        })
    }

    /// Attach C source context (resolved separately by the caller).
    pub fn with_c_source(mut self, file: String, content: String, line: u32) -> Self {
        self.c_source_file = Some(file);
        self.c_source_content = Some(content);
        self.c_source_line = Some(line);
        self
    }

    /// Render the diagnostic as a human-readable error message with
    /// source annotations (Rust-style, via ariadne).
    pub fn format(self) -> String {
        let config = Config::default()
            .with_char_set(CharSet::Unicode);

        let spec_id: String = self.spec_file.unwrap_or_else(|| "spec.fst".into());
        let c_id: String = self.c_source_file.unwrap_or_else(|| "source.bpf.c".into());
        let spec_src = self.spec_content.unwrap_or_default();
        let c_src = self.c_source_content.unwrap_or_default();

        let anchor_span = if !spec_src.is_empty() && self.spec_postcondition.is_some() {
            (spec_id.clone(), 0..0)
        } else {
            (c_id.clone(), 0..0)
        };

        let mut builder = Report::build(ReportKind::Error, anchor_span)
            .with_config(config)
            .with_message(format!("{} check failed", self.stage));

        if !spec_src.is_empty() && let Some(ref postcond) = self.spec_postcondition {
            for line_num in postcond.start_line..=postcond.end_line {
                let range = line_byte_range(&spec_src, line_num);
                if !spec_src[range.clone()].trim().is_empty() {
                    builder = builder.with_label(
                        Label::new((spec_id.clone(), range))
                    );
                }
            }
        }

        if !c_src.is_empty() && let Some(line) = self.c_source_line {
            let range = line_byte_range(&c_src, line as usize);
            let insn_msg = self.r0_origin.as_ref()
                .map(|o| format!("r0 set here ({})", o.instruction))
                .unwrap_or_else(|| "r0 set here".to_string());
            builder = builder.with_label(
                Label::new((c_id.clone(), range))
                    .with_message(insn_msg)
            );
        } else if let Some(ref origin) = self.r0_origin {
            let loc = origin.source_loc.as_deref().unwrap_or("unknown");
            builder = builder.with_note(format!(
                "r0 set at {} ({})", loc, origin.instruction
            ));
        }

        let report = builder.finish();

        let mut buf = Vec::new();
        let cache = ariadne::sources([
            (spec_id, spec_src),
            (c_id, c_src),
        ]);
        let _ = report.write(cache, &mut buf);
        String::from_utf8(buf).unwrap_or_default()
    }
}

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
        assert!(dumps[0].goal.contains("true == true"));
        assert!(dumps[2].goal.contains("Scalar 1uL"));
    }

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

    #[test]
    fn identify_null_safety_failure() {
        let stderr = r#"{"msg":["tactic failed"],"level":"Error","number":228,"ctx":["While typechecking the top-level declaration `let ns_proof`"]}"#;
        let stage = parse_failed_stage(stderr);
        assert_eq!(stage, Some(FailedStage::NullSafety));
    }

    #[test]
    fn identify_stack_bounds_failure() {
        let stderr = r#"{"msg":["tactic failed"],"level":"Error","number":228,"ctx":["While typechecking the top-level declaration `let sb_proof`"]}"#;
        let stage = parse_failed_stage(stderr);
        assert_eq!(stage, Some(FailedStage::StackBounds));
    }

    #[test]
    fn parse_mixed_json_and_dumps() {
        let stderr = r#"proof-state: State dump @ depth 0 (NORMALISED_GOAL):
Location: Verify_test.fst(61,2-61,35)
Goal 1/1

  |- _ : squash (true == true)

{"msg":["Assertion failed"],"level":"Error","number":19,"ctx":["While synthesizing term with a tactic","While typechecking the top-level declaration `let proof`"]}
"#;
        let stage = parse_failed_stage(stderr);
        assert_eq!(stage, Some(FailedStage::FunctionalCorrectness));
    }

    #[test]
    fn ignore_warnings() {
        let stderr = r#"{"msg":["Deprecated"],"level":"Warning","ctx":["While typechecking the top-level declaration `let proof`"]}"#;
        let stage = parse_failed_stage(stderr);
        assert_eq!(stage, None);
    }

    #[test]
    fn failed_stage_display() {
        assert_eq!(FailedStage::StackBounds.to_string(), "stack bounds safety");
        assert_eq!(FailedStage::TypeSafety.to_string(), "type safety");
        assert_eq!(FailedStage::NullSafety.to_string(), "null safety");
        assert_eq!(FailedStage::FunctionalCorrectness.to_string(), "functional correctness");
    }

    #[test]
    fn extract_spec_postcondition() {
        let spec_content = r#"module BranchResult

open FStar.UInt64
open BPF.State
open BPF.Spec

(* The map lookup can succeed or fail *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 0uL \/
    state_get_reg final_st r0 == Scalar 5uL
  )
"#;
        let post = extract_postcondition(spec_content);
        assert!(post.is_some());
        let post = post.unwrap();
        assert_eq!(post.start_line, 9);
        assert_eq!(post.end_line, 12);
        assert!(post.text.contains("Scalar 0uL"));
        assert!(post.text.contains("Scalar 5uL"));
    }

    #[test]
    fn extract_r0_origin_from_dumps() {
        let dumps = vec![
            DumpBlock { label: "R0_ORIGIN".to_string(), goal: "7 == 7".to_string() },
            DumpBlock { label: "NORMALISED_GOAL".to_string(), goal: "something".to_string() },
        ];
        assert_eq!(extract_r0_origin(&dumps), Some(7));
    }

    #[test]
    fn extract_instruction_at_pc_with_source() {
        let generated = concat!(
            "let program : bpf_program = [\n",
            "  BPF_ALU32_IMM MOV r1 (0l)  (* test.bpf.c:13 *);\n",
            "  BPF_STX W32 r10 r1 (-4l)  (* test.bpf.c:14 *);\n",
            "  BPF_ALU32_IMM MOV r0 (1l);\n",
            "  BPF_EXIT  (* test.bpf.c:19 *)\n",
            "]\n",
        );
        let info = extract_instruction_at_pc(generated, 2).unwrap();
        assert_eq!(info.pc, 2);
        assert_eq!(info.instruction, "BPF_ALU32_IMM MOV r0 (1l)");
        assert!(info.source_loc.is_none());

        let info = extract_instruction_at_pc(generated, 0).unwrap();
        assert_eq!(info.source_loc.as_deref(), Some("test.bpf.c:13"));
    }

    #[test]
    fn format_shows_spec_and_stage() {
        let diag = Diagnostic {
            stage: FailedStage::FunctionalCorrectness,
            r0_origin: Some(InstructionInfo {
                pc: 0,
                instruction: "BPF_ALU32_IMM MOV r0 (0l)".to_string(),
                source_loc: Some("test.bpf.c:5".to_string()),
            }),
            spec_file: Some("Test.fst".to_string()),
            spec_content: Some("module Test\nopen BPF.Spec\nlet spec : bpf_spec =\n  returns_value 1uL\n".to_string()),
            spec_postcondition: Some(SpecPostcondition {
                start_line: 4,
                end_line: 4,
                text: "  returns_value 1uL".to_string(),
            }),
            c_source_file: Some("test.bpf.c".to_string()),
            c_source_content: Some("int main() {\n    return 0;\n}\n".to_string()),
            c_source_line: Some(2),
            normalised_goal: None,
        };
        let output = diag.format();
        assert!(output.contains("functional correctness check failed"));
        assert!(output.contains("Test.fst"));
        assert!(output.contains("returns_value 1uL"));
        assert!(output.contains("test.bpf.c"));
        assert!(output.contains("r0 set here"));
    }

    #[test]
    fn format_without_c_source_shows_note() {
        let diag = Diagnostic {
            stage: FailedStage::FunctionalCorrectness,
            r0_origin: Some(InstructionInfo {
                pc: 0,
                instruction: "BPF_ALU32_IMM MOV r0 (0l)".to_string(),
                source_loc: Some("test.bpf.c:5".to_string()),
            }),
            spec_file: Some("Test.fst".to_string()),
            spec_content: Some("module Test\nopen BPF.Spec\nlet spec : bpf_spec =\n  returns_value 1uL\n".to_string()),
            spec_postcondition: Some(SpecPostcondition {
                start_line: 4,
                end_line: 4,
                text: "  returns_value 1uL".to_string(),
            }),
            c_source_file: None,
            c_source_content: None,
            c_source_line: None,
            normalised_goal: None,
        };
        let output = diag.format();
        assert!(output.contains("functional correctness check failed"));
        assert!(output.contains("r0 set at test.bpf.c:5"));
    }

    #[test]
    fn build_diagnostic_from_fstar_output() {
        let stderr = concat!(
            "proof-state: State dump @ depth 0 (R0_ORIGIN):\n",
            "Location: Verify_test.fst(42,2-42,25)\n",
            "Goal 1/1\n",
            "\n",
            "  |- _ : squash (forall (init: bpf_state). 3 == 3)\n",
            "\n",
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
        let generated = concat!(
            "  BPF_ALU32_IMM MOV r1 (0l);\n",
            "  BPF_STX W32 r10 r1 (-4l);\n",
            "  BPF_ALU64_REG MOV r2 r10;\n",
            "  BPF_ALU32_IMM MOV r0 (1l)  (* test.bpf.c:5 *);\n",
            "  BPF_EXIT  (* test.bpf.c:10 *)\n",
        );
        let spec = "module T\nopen BPF.Spec\nlet spec : bpf_spec =\n  returns_value 5uL\n";

        let diag = Diagnostic::from_fstar_output(stderr, generated, Some("T.fst"), Some(spec));
        assert!(diag.is_some());
        let diag = diag.unwrap();
        assert_eq!(diag.stage, FailedStage::FunctionalCorrectness);
        assert!(diag.normalised_goal.as_ref().unwrap().contains("Scalar 1uL"));
        let origin = diag.r0_origin.as_ref().unwrap();
        assert_eq!(origin.pc, 3);
        assert_eq!(origin.source_loc.as_deref(), Some("test.bpf.c:5"));
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

    #[test]
    fn fallback_no_dumps_no_json() {
        let stderr = "some random output\n";
        let stage = parse_failed_stage(stderr);
        assert_eq!(stage, None);
    }

    #[test]
    fn line_byte_offset_calculation() {
        let source = "line 1\nline 2\nline 3\n";
        assert_eq!(line_to_byte_offset(source, 1), 0);
        assert_eq!(line_to_byte_offset(source, 2), 7);
        assert_eq!(line_to_byte_offset(source, 3), 14);
    }
}
