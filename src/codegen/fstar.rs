use std::fmt::Write;

use crate::bpf::instruction::BpfInsn;

/// Generate F* source code for a verification module wrapping a BPF program.
///
/// The output contains the module declaration, standard imports, the program
/// literal (serialised via `BpfInsn::to_fstar`), trivial CO-RE relocation
/// stubs, and the proof obligation tying the program to the given spec.
pub fn generate_fstar(
    program_name: &str,
    instructions: &[BpfInsn],
    spec_module: &str,
    spec_name: &str,
) -> String {
    let mut out = String::new();

    // Module declaration
    writeln!(out, "module Verify_{program_name}").unwrap();
    writeln!(out).unwrap();

    // Imports
    writeln!(out, "open BPF.State").unwrap();
    writeln!(out, "open BPF.Semantics").unwrap();
    writeln!(out, "open BPF.Spec").unwrap();
    writeln!(out, "open BPF.Verify").unwrap();
    writeln!(out, "open {spec_module}").unwrap();
    writeln!(out).unwrap();

    // Program literal
    let insn_strs: Vec<String> = instructions.iter().map(|i| i.to_fstar()).collect();
    writeln!(out, "let program : bpf_program = [").unwrap();
    for (idx, s) in insn_strs.iter().enumerate() {
        if idx + 1 < insn_strs.len() {
            writeln!(out, "  {s};").unwrap();
        } else {
            writeln!(out, "  {s}").unwrap();
        }
    }
    writeln!(out, "]").unwrap();
    writeln!(out).unwrap();

    // Trivial CO-RE
    writeln!(out, "let relocation_sites = []").unwrap();
    writeln!(out, "let layout_constraints = trivial_constraints").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "let proof : squash (program_satisfies program {spec_name}) = ()"
    )
    .unwrap();

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::instruction::BpfInsn;

    #[test]
    fn generate_simple_program() {
        let instructions = vec![
            BpfInsn::decode(0x0000_0000_0000_10bf).unwrap(), // mov r0, r1
            BpfInsn::decode(0x0000_0000_0000_200f).unwrap(), // add r0, r2
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ];

        let output = generate_fstar("test_prog", &instructions, "TestSpec", "test_spec");

        assert!(output.contains("module Verify_test_prog"));
        assert!(output.contains("open BPF.State"));
        assert!(output.contains("open BPF.Semantics"));
        assert!(output.contains("open BPF.Spec"));
        assert!(output.contains("open BPF.Verify"));
        assert!(output.contains("open TestSpec"));
        assert!(output.contains("BPF_ALU64_REG MOV r0 r1"));
        assert!(output.contains("BPF_ALU64_REG ADD r0 r2"));
        assert!(output.contains("BPF_EXIT"));
        assert!(output.contains("program_satisfies program test_spec"));
        assert!(!output.contains("for_all_layouts"));
    }
}
