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

                // Stop if we hit the next dump, an F* error, or a JSON message
                if current.starts_with("proof-state: State dump")
                    || current.starts_with("* Error")
                    || current.starts_with("* Warning")
                    || current.starts_with('{') {
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
    // Extract label from format: "proof-state: State dump @ depth 0 (LABEL):"
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

/// Parse F* stderr output to determine which proof stage failed.
///
/// F* with --message_format json emits one JSON object per line on stderr for
/// errors/warnings. The ctx field contains context about which declaration failed.
pub fn parse_failed_stage(stderr: &str) -> Option<FailedStage> {
    for line in stderr.lines() {
        // Skip non-JSON lines (like dump blocks)
        if !line.starts_with('{') {
            continue;
        }

        // Try to parse as JSON
        let Ok(json) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };

        // Only process Error-level messages
        if json.get("level").and_then(|v| v.as_str()) != Some("Error") {
            continue;
        }

        // Check the ctx array for declaration context
        let Some(ctx) = json.get("ctx").and_then(|v| v.as_array()) else {
            continue;
        };

        for ctx_item in ctx {
            let Some(ctx_str) = ctx_item.as_str() else {
                continue;
            };

            // Match against known proof declarations
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

    // Fallback: if we found dump blocks but no JSON errors, infer from
    // the last dump label before the error
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
    pub start_line: usize,  // 1-based
    pub text: String,
}

/// Extracts the spec definition from a spec file's contents.
///
/// Looks for `let spec` and captures everything from that line to the next blank line
/// or a new `let` definition.
pub fn extract_postcondition(spec_content: &str) -> Option<SpecPostcondition> {
    let lines: Vec<&str> = spec_content.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("let spec") {
            let start_line = i + 1; // 1-based line numbering
            let mut spec_lines = vec![*line];

            // Collect lines until we hit a blank line or another `let` definition
            for &next_line in lines.iter().skip(i + 1) {

                // Stop at blank line
                if next_line.trim().is_empty() {
                    break;
                }

                // Stop at new top-level definition
                if next_line.starts_with("let ") && !next_line.trim_start().starts_with("let spec") {
                    break;
                }

                spec_lines.push(next_line);
            }

            return Some(SpecPostcondition {
                start_line,
                text: spec_lines.join("\n"),
            });
        }
    }

    None
}

/// Extracts unique C source locations from the generated F* source.
///
/// The codegen annotates instructions with `(* file:line *)` comments from DWARF debug info.
pub fn extract_source_locations(generated_source: &str) -> Vec<String> {
    let mut locations = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in generated_source.lines() {
        // Look for (* ... *) comments
        if let Some(start) = line.find("(*")
            && let Some(end) = line[start..].find("*)")
        {
            let comment = &line[start + 2..start + end].trim();

            // Filter to only file:line format
            if comment.contains(':') {
                let location = comment.to_string();

                // Deduplicate while preserving order
                if seen.insert(location.clone()) {
                    locations.push(location);
                }
            }
        }
    }

    locations
}

/// An instruction from the generated F* source with its PC and source location.
#[derive(Debug, Clone)]
pub struct InstructionInfo {
    pub pc: usize,
    pub instruction: String,
    pub source_loc: Option<String>,
}

/// Extract the r0 origin PC from the R0_ORIGIN dump block.
///
/// The dump goal contains `N == N` where N is the PC number,
/// possibly wrapped in `squash (forall ... . N == N)`.
pub fn extract_r0_origin(dumps: &[DumpBlock]) -> Option<usize> {
    let dump = dumps.iter().find(|d| d.label == "R0_ORIGIN")?;
    let goal = dump.goal.trim();
    let eq_pos = goal.rfind(" == ")?;
    let after_eq = goal[eq_pos + 4..].trim().trim_end_matches(')');
    after_eq.trim().parse().ok()
}

/// Extract instruction info at a given PC from the generated F* source.
///
/// The instruction list in the generated source has the form:
///   BPF_ALU32_IMM MOV r0 (1l)  (* BranchResult.bpf.c:17 *);
/// Each line corresponds to a PC (0-indexed from the first instruction).
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
    pub normalised_goal: Option<String>,
    pub r0_origin: Option<InstructionInfo>,
    pub spec_file: Option<String>,
    pub spec_postcondition: Option<SpecPostcondition>,
    pub source_locations: Vec<String>,
}

impl Diagnostic {
    /// Build a diagnostic from F* output and related source files.
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
        let source_locations = extract_source_locations(generated_source);

        Some(Diagnostic {
            stage,
            normalised_goal,
            r0_origin,
            spec_file: spec_file.map(|s| s.to_string()),
            spec_postcondition,
            source_locations,
        })
    }

    /// Format the diagnostic as a human-readable error message.
    pub fn format(&self) -> String {
        let mut output = format!("  {} check failed\n", self.stage);

        if let Some(origin) = &self.r0_origin {
            output.push_str(&format!(
                "\n  r0 set by instruction {} ({})\n",
                origin.pc,
                origin.source_loc.as_deref().unwrap_or("no source location"),
            ));
            output.push_str(&format!("    {}\n", origin.instruction));
        }

        if let Some(goal) = &self.normalised_goal {
            output.push_str("\n  Normalised proof obligation (what F* tried to prove):\n");
            for line in goal.lines() {
                output.push_str(&format!("    {}\n", line));
            }
        }

        if let Some(spec_file) = &self.spec_file
            && let Some(postcond) = &self.spec_postcondition
        {
            output.push_str(&format!("\n  Spec ({}:{}):\n", spec_file, postcond.start_line));
            for line in postcond.text.lines() {
                output.push_str(&format!("    {}\n", line));
            }
        }

        output
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
        assert_eq!(post.start_line, 8);
        assert!(post.text.contains("Scalar 0uL"));
        assert!(post.text.contains("Scalar 5uL"));
    }

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
    fn format_functional_failure_diagnostic() {
        let diag = Diagnostic {
            stage: FailedStage::FunctionalCorrectness,
            normalised_goal: Some("squash (forall (init: bpf_state).\n        l_True ==> Scalar 1uL == Scalar 0uL \\/ Scalar 1uL == Scalar 5uL)".to_string()),
            r0_origin: Some(InstructionInfo {
                pc: 7,
                instruction: "BPF_ALU32_IMM MOV r0 (1l)".to_string(),
                source_loc: Some("BranchResult.bpf.c:17".to_string()),
            }),
            spec_file: Some("BranchResult.fst".to_string()),
            spec_postcondition: Some(SpecPostcondition {
                start_line: 10,
                text: "let spec : bpf_spec =\n  post_only (fun final_st ->\n    state_get_reg final_st r0 == Scalar 0uL \\/\n    state_get_reg final_st r0 == Scalar 5uL\n  )".to_string(),
            }),
            source_locations: vec![],
        };
        let output = diag.format();
        assert!(output.contains("functional correctness"));
        assert!(output.contains("instruction 7"));
        assert!(output.contains("BranchResult.bpf.c:17"));
        assert!(output.contains("BPF_ALU32_IMM MOV r0 (1l)"));
        assert!(output.contains("Scalar 1uL == Scalar 0uL"));
        assert!(output.contains("BranchResult.fst:10"));
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
}
