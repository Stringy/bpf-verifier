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

                // Stop if we hit the next dump or an error
                if current.starts_with("proof-state: State dump")
                    || current.starts_with("* Error")
                    || current.starts_with("* Warning") {
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

    None
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
}
