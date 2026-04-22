use crate::bpf::instruction::{BpfInsn, Opcode};

#[derive(Debug)]
pub struct BasicBlock {
    pub start: usize,
    pub end: usize,
}

impl BasicBlock {
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

pub fn find_basic_blocks(instructions: &[BpfInsn]) -> Vec<BasicBlock> {
    if instructions.is_empty() {
        return vec![];
    }

    let mut leaders = vec![false; instructions.len()];
    leaders[0] = true;

    for (i, insn) in instructions.iter().enumerate() {
        match insn.opcode {
            Opcode::JmpJa => {
                let target = (i as isize + 1 + insn.offset as isize) as usize;
                if target < instructions.len() {
                    leaders[target] = true;
                }
            }
            Opcode::Jmp64(_, _) | Opcode::Jmp32(_, _) => {
                let target = (i as isize + 1 + insn.offset as isize) as usize;
                if target < instructions.len() {
                    leaders[target] = true;
                }
                if i + 1 < instructions.len() {
                    leaders[i + 1] = true;
                }
            }
            _ => {}
        }
    }

    let mut blocks = Vec::new();
    let mut start = 0;

    for (i, &is_leader) in leaders.iter().enumerate().skip(1) {
        if is_leader {
            blocks.push(BasicBlock { start, end: i });
            start = i;
        }
    }
    blocks.push(BasicBlock {
        start,
        end: instructions.len(),
    });

    blocks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::instruction::{JmpOp, Source};

    fn make_insn(opcode: Opcode, offset: i16) -> BpfInsn {
        BpfInsn {
            opcode,
            dst: crate::bpf::instruction::Reg::R0,
            src: crate::bpf::instruction::Reg::R0,
            offset,
            imm: 0,
            imm64: None,
        }
    }

    #[test]
    fn linear_programme_is_one_block() {
        let insns = vec![
            make_insn(Opcode::Alu32(crate::bpf::instruction::AluOp::Mov, Source::Imm), 0),
            make_insn(Opcode::Alu32(crate::bpf::instruction::AluOp::Add, Source::Imm), 0),
            make_insn(Opcode::Exit, 0),
        ];
        let blocks = find_basic_blocks(&insns);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start, 0);
        assert_eq!(blocks[0].end, 3);
    }

    #[test]
    fn branch_splits_into_blocks() {
        let insns = vec![
            make_insn(Opcode::Alu32(crate::bpf::instruction::AluOp::Mov, Source::Imm), 0),
            make_insn(Opcode::Jmp32(JmpOp::Jeq, Source::Imm), 1), // jump over next insn
            make_insn(Opcode::Alu32(crate::bpf::instruction::AluOp::Mov, Source::Imm), 0),
            make_insn(Opcode::Exit, 0),
        ];
        let blocks = find_basic_blocks(&insns);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].start, 0);
        assert_eq!(blocks[0].end, 2);
        assert_eq!(blocks[1].start, 2);
        assert_eq!(blocks[1].end, 3);
        assert_eq!(blocks[2].start, 3);
        assert_eq!(blocks[2].end, 4);
    }
}
