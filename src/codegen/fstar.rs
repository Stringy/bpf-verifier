use std::collections::HashMap;
use std::fmt::Write;

use askama::Template;

use crate::bpf::instruction::{AluOp, BpfInsn, Opcode, Source};

#[derive(Template)]
#[template(path = "verify.fst")]
struct VerifyModule {
    program_name: String,
    spec_module: String,
    spec_name: String,
    instructions: Vec<String>,
    hints: Vec<String>,
    has_map_calls: bool,
}

pub fn generate_fstar(
    program_name: &str,
    instructions: &[BpfInsn],
    spec_module: &str,
    spec_name: &str,
) -> String {
    let hints = generate_bitwise_hints(instructions);
    let has_map_calls = instructions.iter().any(|i| matches!(i.opcode, Opcode::Call));
    let tmpl = VerifyModule {
        program_name: program_name.to_string(),
        spec_module: spec_module.to_string(),
        spec_name: spec_name.to_string(),
        instructions: instructions.iter().map(|i| i.to_fstar()).collect(),
        hints,
        has_map_calls,
    };
    tmpl.render().expect("failed to render F* template")
}

fn is_bitwise_op(op: AluOp) -> bool {
    matches!(op, AluOp::And | AluOp::Or | AluOp::Xor)
}

fn bitwise_op_fstar(op: AluOp) -> &'static str {
    match op {
        AluOp::And => "logand",
        AluOp::Or => "logor",
        AluOp::Xor => "logxor",
        _ => unreachable!(),
    }
}

fn generate_bitwise_hints(instructions: &[BpfInsn]) -> Vec<String> {
    let mut hints = Vec::new();
    let mut reg_vals: [Option<i64>; 11] = [None; 11];
    let mut stack_vals: HashMap<i16, i64> = HashMap::new();

    for insn in instructions {
        match insn.opcode {
            Opcode::Alu32(AluOp::Mov, Source::Imm) | Opcode::Alu64(AluOp::Mov, Source::Imm) => {
                reg_vals[insn.dst.index() as usize] = Some(insn.imm as i64);
            }
            Opcode::Stx(_) => {
                let src_idx = insn.src.index() as usize;
                if let Some(v) = reg_vals[src_idx] {
                    stack_vals.insert(insn.offset, v);
                } else {
                    stack_vals.remove(&insn.offset);
                }
            }
            Opcode::Ldx(_) => {
                let dst_idx = insn.dst.index() as usize;
                reg_vals[dst_idx] = stack_vals.get(&insn.offset).copied();
            }
            Opcode::Alu32(op, Source::Imm) | Opcode::Alu64(op, Source::Imm)
                if is_bitwise_op(op) =>
            {
                let dst_idx = insn.dst.index() as usize;
                if let Some(dst_val) = reg_vals[dst_idx] {
                    let imm = insn.imm;
                    let op_name = bitwise_op_fstar(op);
                    let result = match op {
                        AluOp::And => dst_val & (imm as i64),
                        AluOp::Or => dst_val | (imm as i64),
                        AluOp::Xor => dst_val ^ (imm as i64),
                        _ => unreachable!(),
                    };
                    let idx = hints.len();
                    let mut hint = String::new();
                    writeln!(hint, "let bitwise_hint_{idx} (x: UInt32.t) : Lemma").unwrap();
                    writeln!(hint, "  (requires UInt32.v x = {dst_val})").unwrap();
                    writeln!(hint, "  (ensures UInt32.v (UInt32.{op_name} x {imm}ul) = {result}) =").unwrap();
                    write!(hint, "  assert_norm (UInt32.v (UInt32.{op_name} {dst_val}ul {imm}ul) = {result})").unwrap();
                    hints.push(hint);
                    reg_vals[dst_idx] = Some(result);
                } else {
                    reg_vals[dst_idx] = None;
                }
            }
            _ => {
                match insn.opcode {
                    Opcode::Alu32(_, _) | Opcode::Alu64(_, _) => {
                        reg_vals[insn.dst.index() as usize] = None;
                    }
                    _ => {}
                }
            }
        }
    }

    hints
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(output.contains("open BPF.Check.StackBounds"));
        assert!(output.contains("open BPF.Check.TypeSafety"));
        assert!(output.contains("open BPF.Tactic.Layered"));
        assert!(output.contains("open TestSpec"));
        assert!(output.contains("BPF_ALU64_REG MOV r0 r1"));
        assert!(output.contains("BPF_ALU64_REG ADD r0 r2"));
        assert!(output.contains("BPF_EXIT"));
        assert!(output.contains("stack_bounds_check program"));
        assert!(output.contains("stack_bounds_tac"));
        assert!(output.contains("type_check program"));
        assert!(output.contains("type_check_tac"));
        assert!(output.contains("program_satisfies program test_spec"));
    }
}
