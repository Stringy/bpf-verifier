use crate::bpf::helpers::{get_helper, HelperReturn};
use crate::bpf::instruction::{AluOp, BpfInsn, JmpOp, MemWidth, Opcode, Source};

#[derive(Debug, Clone, PartialEq)]
pub enum AbsValue {
    Concrete(u64),
    FramePtr(i64),
    CtxPtr(i64),
    MapValuePtr(usize),
    RingBufPtr(usize),
    Null,
    Symbolic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathChoice {
    NonNull,
    AsNull,
}

impl PathChoice {
    pub fn to_fstar(&self) -> &'static str {
        match self {
            PathChoice::NonNull => "NonNull",
            PathChoice::AsNull => "AsNull",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RingBufWrite {
    pub id: usize,
    pub offset: i64,
    pub width: MemWidth,
    pub value: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PathResult {
    pub path_id: usize,
    pub schedule: Vec<PathChoice>,
    pub return_value: Option<u64>,
    pub ringbuf_writes: Vec<RingBufWrite>,
}

#[derive(Debug, Clone)]
pub struct DataflowResult {
    pub paths: Vec<PathResult>,
    pub has_nullable_helpers: bool,
}

#[derive(Debug, Clone)]
struct PathState {
    regs: [AbsValue; 11],
    pc: usize,
    next_ptr_id: usize,
    schedule: Vec<PathChoice>,
    schedule_cursor: usize,
    ringbuf_writes: Vec<RingBufWrite>,
}

impl PathState {
    fn init() -> Self {
        let mut regs: [AbsValue; 11] = std::array::from_fn(|_| AbsValue::Symbolic);
        regs[1] = AbsValue::CtxPtr(0);
        regs[10] = AbsValue::FramePtr(0);
        Self {
            regs,
            pc: 0,
            next_ptr_id: 0,
            schedule: Vec::new(),
            schedule_cursor: 0,
            ringbuf_writes: Vec::new(),
        }
    }

    fn get(&self, reg: u8) -> &AbsValue {
        &self.regs[reg as usize]
    }

    fn set(&mut self, reg: u8, val: AbsValue) {
        self.regs[reg as usize] = val;
    }
}

pub fn analyse(instructions: &[BpfInsn]) -> DataflowResult {
    let nullable_count = count_nullable_helpers(instructions);
    if nullable_count == 0 {
        return DataflowResult {
            paths: vec![single_path(instructions)],
            has_nullable_helpers: false,
        };
    }

    let schedules = enumerate_schedules(nullable_count);
    let mut paths = Vec::new();

    for (path_id, schedule) in schedules.into_iter().enumerate() {
        if let Some(result) = execute_path(instructions, &schedule, path_id) {
            paths.push(result);
        }
    }

    DataflowResult {
        paths,
        has_nullable_helpers: true,
    }
}

fn count_nullable_helpers(instructions: &[BpfInsn]) -> usize {
    instructions
        .iter()
        .filter(|insn| {
            if let Opcode::Call = insn.opcode {
                get_helper(insn.imm).is_some_and(|h| {
                    matches!(h.ret_type, HelperReturn::MapPtr | HelperReturn::RingBufPtr)
                })
            } else {
                false
            }
        })
        .count()
}

fn enumerate_schedules(count: usize) -> Vec<Vec<PathChoice>> {
    let total = 1usize << count;
    (0..total)
        .map(|bits| {
            (0..count)
                .map(|i| {
                    if bits & (1 << i) == 0 {
                        PathChoice::NonNull
                    } else {
                        PathChoice::AsNull
                    }
                })
                .collect()
        })
        .collect()
}

fn single_path(instructions: &[BpfInsn]) -> PathResult {
    let mut state = PathState::init();
    for (pc, insn) in instructions.iter().enumerate() {
        state.pc = pc;
        if matches!(insn.opcode, Opcode::Exit) {
            break;
        }
        transfer_abstract(&mut state, insn);
    }
    let return_value = match state.get(0) {
        AbsValue::Concrete(v) => Some(*v),
        _ => None,
    };
    PathResult {
        path_id: 0,
        schedule: Vec::new(),
        return_value,
        ringbuf_writes: state.ringbuf_writes,
    }
}

fn execute_path(
    instructions: &[BpfInsn],
    schedule: &[PathChoice],
    path_id: usize,
) -> Option<PathResult> {
    let mut state = PathState::init();
    state.schedule = schedule.to_vec();
    let mut fuel = instructions.len() * 2;

    loop {
        if fuel == 0 || state.pc >= instructions.len() {
            return None;
        }
        fuel -= 1;

        let insn = &instructions[state.pc];

        if matches!(insn.opcode, Opcode::Exit) {
            let return_value = match state.get(0) {
                AbsValue::Concrete(v) => Some(*v),
                _ => None,
            };
            return Some(PathResult {
                path_id,
                schedule: schedule.to_vec(),
                return_value,
                ringbuf_writes: state.ringbuf_writes,
            });
        }

        if !transfer_with_branches(&mut state, insn, instructions) {
            return None;
        }
    }
}

fn transfer_abstract(state: &mut PathState, insn: &BpfInsn) {
    let dst = insn.dst.index();
    let src = insn.src.index();

    match insn.opcode {
        Opcode::Alu64(op, Source::Reg) => match op {
            AluOp::Mov => state.set(dst, state.get(src).clone()),
            _ => state.set(dst, AbsValue::Symbolic),
        },
        Opcode::Alu64(op, Source::Imm) => match op {
            AluOp::Mov => state.set(dst, AbsValue::Concrete(insn.imm as u64)),
            AluOp::Add => {
                let v = match state.get(dst) {
                    AbsValue::FramePtr(off) => AbsValue::FramePtr(off + insn.imm as i64),
                    AbsValue::CtxPtr(off) => AbsValue::CtxPtr(off + insn.imm as i64),
                    AbsValue::Concrete(v) => {
                        AbsValue::Concrete(v.wrapping_add(insn.imm as u64))
                    }
                    AbsValue::RingBufPtr(_) | AbsValue::MapValuePtr(_) => AbsValue::Symbolic,
                    _ => AbsValue::Symbolic,
                };
                state.set(dst, v);
            }
            AluOp::Sub => {
                let v = match state.get(dst) {
                    AbsValue::FramePtr(off) => AbsValue::FramePtr(off - insn.imm as i64),
                    AbsValue::CtxPtr(off) => AbsValue::CtxPtr(off - insn.imm as i64),
                    AbsValue::Concrete(v) => {
                        AbsValue::Concrete(v.wrapping_sub(insn.imm as u64))
                    }
                    _ => AbsValue::Symbolic,
                };
                state.set(dst, v);
            }
            _ => state.set(dst, AbsValue::Symbolic),
        },
        Opcode::Alu32(AluOp::Mov, Source::Imm) => {
            state.set(dst, AbsValue::Concrete(insn.imm as u64));
        }
        Opcode::Alu32(_, _) => state.set(dst, AbsValue::Symbolic),
        Opcode::LdImm64 => {
            let val = insn.imm64.unwrap_or(insn.imm as u32 as u64);
            state.set(dst, AbsValue::Concrete(val));
        }
        Opcode::Ldx(_) => {
            state.set(dst, AbsValue::Symbolic);
        }
        Opcode::Stx(w) => {
            if let AbsValue::RingBufPtr(id) = state.get(dst).clone() {
                let value = match state.get(src) {
                    AbsValue::Concrete(v) => Some(*v),
                    _ => None,
                };
                state.ringbuf_writes.push(RingBufWrite {
                    id,
                    offset: insn.offset as i64,
                    width: w,
                    value,
                });
            }
            state.pc += 1;
            return;
        }
        Opcode::St(w) => {
            if let AbsValue::RingBufPtr(id) = state.get(dst).clone() {
                state.ringbuf_writes.push(RingBufWrite {
                    id,
                    offset: insn.offset as i64,
                    width: w,
                    value: Some(insn.imm as u64),
                });
            }
            state.pc += 1;
            return;
        }
        Opcode::Call => {
            handle_call(state, insn);
            state.pc += 1;
            return;
        }
        _ => {}
    }

    state.pc += 1;
}

fn transfer_with_branches(
    state: &mut PathState,
    insn: &BpfInsn,
    _instructions: &[BpfInsn],
) -> bool {
    let pc = state.pc;

    match insn.opcode {
        Opcode::Jmp64(_, Source::Imm) | Opcode::Jmp64(_, Source::Reg) => {
            let target_pc = (pc as i32 + 1 + insn.offset as i32) as usize;
            let taken = resolve_branch(state, insn);
            match taken {
                Some(true) => {
                    state.pc = target_pc;
                }
                Some(false) => {
                    state.pc = pc + 1;
                }
                None => {
                    state.pc = pc + 1;
                }
            }
            true
        }
        Opcode::Jmp32(_, Source::Imm) | Opcode::Jmp32(_, Source::Reg) => {
            let target_pc = (pc as i32 + 1 + insn.offset as i32) as usize;
            let taken = resolve_branch(state, insn);
            match taken {
                Some(true) => state.pc = target_pc,
                Some(false) => state.pc = pc + 1,
                None => state.pc = pc + 1,
            }
            true
        }
        Opcode::JmpJa => {
            state.pc = (pc as i32 + 1 + insn.offset as i32) as usize;
            true
        }
        Opcode::Call => {
            handle_call(state, insn);
            state.pc = pc + 1;
            true
        }
        Opcode::Exit => true,
        _ => {
            transfer_abstract(state, insn);
            true
        }
    }
}

fn resolve_branch(state: &PathState, insn: &BpfInsn) -> Option<bool> {
    let dst = insn.dst.index();
    let dst_val = state.get(dst);

    let (cmp_op, imm_or_src) = match insn.opcode {
        Opcode::Jmp64(op, Source::Imm) => (op, Some(insn.imm as u64)),
        Opcode::Jmp32(op, Source::Imm) => (op, Some(insn.imm as u64)),
        Opcode::Jmp64(op, Source::Reg) | Opcode::Jmp32(op, Source::Reg) => {
            let src = insn.src.index();
            match state.get(src) {
                AbsValue::Concrete(v) => (op, Some(*v)),
                _ => return None,
            }
        }
        _ => return None,
    };

    match (cmp_op, dst_val) {
        (JmpOp::Jeq, AbsValue::Null) if imm_or_src == Some(0) => {
            Some(true)
        }
        (JmpOp::Jne, AbsValue::Null) if imm_or_src == Some(0) => {
            Some(false)
        }
        (JmpOp::Jeq, AbsValue::MapValuePtr(_))
            if imm_or_src == Some(0) =>
        {
            Some(false)
        }
        (JmpOp::Jne, AbsValue::MapValuePtr(_))
            if imm_or_src == Some(0) =>
        {
            Some(true)
        }
        (JmpOp::Jeq, AbsValue::RingBufPtr(_))
            if imm_or_src == Some(0) =>
        {
            Some(false)
        }
        (JmpOp::Jne, AbsValue::RingBufPtr(_))
            if imm_or_src == Some(0) =>
        {
            Some(true)
        }
        (JmpOp::Jeq, AbsValue::Concrete(v)) => {
            imm_or_src.map(|s| *v == s)
        }
        (JmpOp::Jne, AbsValue::Concrete(v)) => {
            imm_or_src.map(|s| *v != s)
        }
        (JmpOp::Jgt, AbsValue::Concrete(v)) => {
            imm_or_src.map(|s| *v > s)
        }
        (JmpOp::Jge, AbsValue::Concrete(v)) => {
            imm_or_src.map(|s| *v >= s)
        }
        (JmpOp::Jlt, AbsValue::Concrete(v)) => {
            imm_or_src.map(|s| *v < s)
        }
        (JmpOp::Jle, AbsValue::Concrete(v)) => {
            imm_or_src.map(|s| *v <= s)
        }
        _ => None,
    }
}

fn handle_call(state: &mut PathState, insn: &BpfInsn) {
    let helper = get_helper(insn.imm);
    match helper.map(|h| h.ret_type) {
        Some(HelperReturn::MapPtr) => {
            let choice = if state.schedule_cursor < state.schedule.len() {
                let c = state.schedule[state.schedule_cursor];
                state.schedule_cursor += 1;
                c
            } else {
                PathChoice::NonNull
            };
            let id = state.next_ptr_id;
            state.next_ptr_id += 1;
            match choice {
                PathChoice::NonNull => state.set(0, AbsValue::MapValuePtr(id)),
                PathChoice::AsNull => state.set(0, AbsValue::Null),
            }
        }
        Some(HelperReturn::RingBufPtr) => {
            let choice = if state.schedule_cursor < state.schedule.len() {
                let c = state.schedule[state.schedule_cursor];
                state.schedule_cursor += 1;
                c
            } else {
                PathChoice::NonNull
            };
            let id = state.next_ptr_id;
            state.next_ptr_id += 1;
            match choice {
                PathChoice::NonNull => state.set(0, AbsValue::RingBufPtr(id)),
                PathChoice::AsNull => state.set(0, AbsValue::Null),
            }
        }
        Some(HelperReturn::Scalar | HelperReturn::ErrorCode | HelperReturn::KernelPtr) => {
            state.set(0, AbsValue::Symbolic);
        }
        None => {
            state.set(0, AbsValue::Symbolic);
        }
    }
    for r in 1..=5u8 {
        state.set(r, AbsValue::Symbolic);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_nullable_helpers_produces_single_path() {
        let insns = vec![
            BpfInsn::decode(0x0000_0000_0000_10bf).unwrap(), // mov r0, r1
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ];
        let result = analyse(&insns);
        assert!(!result.has_nullable_helpers);
        assert_eq!(result.paths.len(), 1);
    }

    #[test]
    fn enumerate_two_schedules_for_one_nullable() {
        let schedules = enumerate_schedules(1);
        assert_eq!(schedules.len(), 2);
        assert_eq!(schedules[0], vec![PathChoice::NonNull]);
        assert_eq!(schedules[1], vec![PathChoice::AsNull]);
    }

    #[test]
    fn enumerate_four_schedules_for_two_nullable() {
        let schedules = enumerate_schedules(2);
        assert_eq!(schedules.len(), 4);
    }

    #[test]
    fn concrete_mov_tracks_value() {
        let mut state = PathState::init();
        state.set(0, AbsValue::Concrete(42));
        assert_eq!(*state.get(0), AbsValue::Concrete(42));
    }
}
