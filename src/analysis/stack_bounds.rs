use std::collections::HashMap;

use crate::bpf::instruction::{AluOp, BpfInsn, MemWidth, Opcode, Source};

#[derive(Debug, Clone, PartialEq)]
pub enum AbsReg {
    FramePtr(i64),
    CtxPtr(i64),
    RingBufPtr(u64),
    Other,
}

impl AbsReg {
    pub fn to_fstar(&self) -> String {
        match self {
            AbsReg::FramePtr(off) => {
                if *off < 0 {
                    format!("AbsFramePtr ({})", off)
                } else {
                    format!("AbsFramePtr {}", off)
                }
            }
            AbsReg::CtxPtr(off) => {
                if *off < 0 {
                    format!("AbsCtxPtr ({})", off)
                } else {
                    format!("AbsCtxPtr {}", off)
                }
            }
            AbsReg::RingBufPtr(id) => format!("AbsRingBufPtr {}", id),
            AbsReg::Other => "AbsOther".to_string(),
        }
    }
}

fn default_reg(reg: u8) -> AbsReg {
    match reg {
        10 => AbsReg::FramePtr(0),
        1 => AbsReg::CtxPtr(0),
        _ => AbsReg::Other,
    }
}

#[derive(Debug, Clone)]
pub struct RegState {
    regs: [AbsReg; 11],
}

impl RegState {
    pub fn init() -> Self {
        Self {
            regs: std::array::from_fn(|i| default_reg(i as u8)),
        }
    }

    pub fn get(&self, reg: u8) -> &AbsReg {
        &self.regs[reg as usize]
    }

    pub fn set(&mut self, reg: u8, val: AbsReg) {
        self.regs[reg as usize] = val;
    }

    pub fn to_fstar(&self) -> String {
        let entries: Vec<String> = self.regs.iter().enumerate()
            .filter(|(i, v)| **v != default_reg(*i as u8))
            .map(|(i, v)| format!("({}, {})", i, v.to_fstar()))
            .collect();
        if entries.is_empty() {
            "[]".to_string()
        } else {
            format!("[{}]", entries.join("; "))
        }
    }

    fn join(&self, other: &RegState) -> RegState {
        let mut result = RegState::init();
        for i in 0..11u8 {
            let joined = match (self.get(i), other.get(i)) {
                (AbsReg::FramePtr(a), AbsReg::FramePtr(b)) if a == b => AbsReg::FramePtr(*a),
                (AbsReg::CtxPtr(a), AbsReg::CtxPtr(b)) if a == b => AbsReg::CtxPtr(*a),
                (AbsReg::RingBufPtr(a), AbsReg::RingBufPtr(b)) if a == b => AbsReg::RingBufPtr(*a),
                _ => AbsReg::Other,
            };
            result.set(i, joined);
        }
        result.set(10, AbsReg::FramePtr(0));
        // Note: r1 is NOT preserved as CtxPtr after joins — helper calls
        // clobber r1-r5, so the ctx pointer is typically saved to r6-r9
        result
    }
}

#[derive(Debug, Clone, Default)]
pub struct TargetMap {
    entries: HashMap<i32, RegState>,
}

impl TargetMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn to_fstar(&self) -> String {
        if self.entries.is_empty() {
            return "[]".to_string();
        }
        let mut pairs: Vec<(i32, String)> = self.entries.iter()
            .map(|(pc, state)| (*pc, state.to_fstar()))
            .collect();
        pairs.sort_by_key(|(pc, _)| *pc);
        let formatted: Vec<String> = pairs.iter()
            .map(|(pc, s)| format!("({}, {})", pc, s))
            .collect();
        format!("[{}]", formatted.join("; "))
    }
}

pub struct WitnessStep {
    pub pc: usize,
    pub insn_fstar: String,
    pub state_fstar: String,
    pub targets_fstar: String,
}

impl WitnessStep {
    pub fn to_fstar(&self) -> String {
        format!(
            "let _ = assert_norm (Some? (check_insn_sb (to_abs_state_sb {}) ({}) {} (to_target_map_sb {})))",
            self.state_fstar, self.insn_fstar, self.pc, self.targets_fstar
        )
    }
}

pub struct AnalysisResult {
    pub passed: bool,
    pub failing_pc: Option<usize>,
    pub steps: Vec<WitnessStep>,
}

fn width_bytes(w: MemWidth) -> u8 {
    match w {
        MemWidth::B => 1,
        MemWidth::H => 2,
        MemWidth::W => 4,
        MemWidth::DW => 8,
    }
}

fn stack_offset_valid(offset: i64, width: u8) -> bool {
    let idx = 512 + offset;
    idx >= 0 && idx + width as i64 <= 512
}

fn check_mem_access(base: &AbsReg, insn_off: i16, w: MemWidth) -> bool {
    match base {
        AbsReg::FramePtr(ptr_off) => {
            let eff_off = ptr_off + insn_off as i64;
            stack_offset_valid(eff_off, width_bytes(w))
        }
        AbsReg::CtxPtr(_) => true,
        AbsReg::RingBufPtr(_) => true,
        AbsReg::Other => true,
    }
}

pub fn analyse(instructions: &[BpfInsn]) -> AnalysisResult {
    let mut state = RegState::init();
    let mut targets = TargetMap::new();
    let mut steps = Vec::new();

    // Phase 1: find loop heads
    for (pc, insn) in instructions.iter().enumerate() {
        if let Some(off) = branch_offset(insn) {
            let target_pc = pc as i32 + 1 + off as i32;
            if target_pc <= pc as i32 {
                let mut widened = RegState::init();
                for r in 0..=5u8 {
                    widened.set(r, AbsReg::Other);
                }
                targets.entries.insert(target_pc, widened);
            }
        }
    }

    // Phase 2: abstract interpretation
    for (pc, insn) in instructions.iter().enumerate() {
        let state_before = state.clone();
        let targets_before = targets.clone();

        // Merge branch targets at this pc
        if let Some(saved) = targets.entries.remove(&(pc as i32)) {
            state = state.join(&saved);
        }

        let ok = transfer(&mut state, &mut targets, insn, pc);

        steps.push(WitnessStep {
            pc,
            insn_fstar: insn.to_fstar(),
            state_fstar: state_before.to_fstar(),
            targets_fstar: targets_before.to_fstar(),
        });

        if !ok {
            return AnalysisResult { passed: false, failing_pc: Some(pc), steps };
        }
    }

    AnalysisResult { passed: true, failing_pc: None, steps }
}

fn branch_offset(insn: &BpfInsn) -> Option<i16> {
    match insn.opcode {
        Opcode::Jmp64(_, _) | Opcode::Jmp32(_, _) | Opcode::JmpJa => Some(insn.offset),
        _ => None,
    }
}

fn transfer(state: &mut RegState, targets: &mut TargetMap, insn: &BpfInsn, pc: usize) -> bool {
    let dst = insn.dst.index();
    let src = insn.src.index();

    match insn.opcode {
        Opcode::Alu64(op, Source::Reg) => {
            match op {
                AluOp::Mov => state.set(dst, state.get(src).clone()),
                _ => state.set(dst, AbsReg::Other),
            }
            true
        }
        Opcode::Alu64(op, Source::Imm) => {
            match op {
                AluOp::Mov => state.set(dst, AbsReg::Other),
                AluOp::Add => {
                    let v = match state.get(dst) {
                        AbsReg::FramePtr(off) => AbsReg::FramePtr(off + insn.imm as i64),
                        AbsReg::CtxPtr(off) => AbsReg::CtxPtr(off + insn.imm as i64),
                        AbsReg::RingBufPtr(_) | AbsReg::Other => AbsReg::Other,
                    };
                    state.set(dst, v);
                }
                AluOp::Sub => {
                    let v = match state.get(dst) {
                        AbsReg::FramePtr(off) => AbsReg::FramePtr(off - insn.imm as i64),
                        AbsReg::CtxPtr(off) => AbsReg::CtxPtr(off - insn.imm as i64),
                        AbsReg::RingBufPtr(_) | AbsReg::Other => AbsReg::Other,
                    };
                    state.set(dst, v);
                }
                _ => state.set(dst, AbsReg::Other),
            }
            true
        }
        Opcode::Alu32(_, _) => { state.set(dst, AbsReg::Other); true }
        Opcode::LdImm64 => { state.set(dst, AbsReg::Other); true }
        Opcode::Ldx(w) => {
            if !check_mem_access(state.get(src), insn.offset, w) {
                return false;
            }
            state.set(dst, AbsReg::Other);
            true
        }
        Opcode::Stx(w) => check_mem_access(state.get(dst), insn.offset, w),
        Opcode::St(w) => check_mem_access(state.get(dst), insn.offset, w),
        Opcode::Jmp64(_, _) | Opcode::Jmp32(_, _) => {
            let target_pc = pc as i32 + 1 + insn.offset as i32;
            if target_pc > pc as i32 {
                targets.entries.entry(target_pc)
                    .and_modify(|existing| *existing = existing.join(state))
                    .or_insert_with(|| state.clone());
            }
            true
        }
        Opcode::JmpJa => true,
        Opcode::Call => {
            for r in 0..=5u8 { state.set(r, AbsReg::Other); }
            true
        }
        Opcode::Exit => true,
        Opcode::Unknown(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_program_passes() {
        let insns = vec![
            BpfInsn::decode(0x0000_0000_0000_10bf).unwrap(), // mov r0, r1
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ];
        let result = analyse(&insns);
        assert!(result.passed);
        assert_eq!(result.steps.len(), 2);
    }

    #[test]
    fn witness_steps_serialise() {
        let insns = vec![
            BpfInsn::decode(0x0000_0000_0000_10bf).unwrap(), // mov r0, r1
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ];
        let result = analyse(&insns);
        for step in &result.steps {
            let s = step.to_fstar();
            assert!(s.contains("check_insn_sb"));
            assert!(s.contains("assert_norm"));
        }
    }
}
