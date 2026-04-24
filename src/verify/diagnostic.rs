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
}
