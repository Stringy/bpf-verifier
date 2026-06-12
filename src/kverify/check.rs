use std::collections::{HashMap, HashSet};

use crate::bpf::helpers::{get_helper, HelperReturn};
use crate::bpf::instruction::{AluOp, BpfInsn, JmpOp, MemWidth, Opcode, Reg, Source};
use crate::elf::parser::{RelocTarget, SourceLoc};

use super::error::{ErrorKind, VerifyError};
use super::state::{RegState, RegType, StackState, Tnum, VerifierState};

/// Maximum number of instructions the verifier will process across all paths
/// before declaring the programme too complex.
const COMPLEXITY_LIMIT: usize = 1_000_000;

/// Maximum BPF stack size in bytes.
const STACK_SIZE: i64 = 512;

/// Default map value size when we don't have BTF info. Set to the kernel's
/// maximum map value size (64 KiB) to avoid false positives on large map values.
const DEFAULT_MAP_VALUE_SIZE: u32 = 65536;

/// Default ring buffer reservation size when we don't know the actual size.
/// Set conservatively large.
const DEFAULT_RINGBUF_SIZE: u32 = 65536;

/// Context size -- we're permissive here since the actual size depends on
/// the programme type. In practice the kernel checks this per-type.
const CTX_SIZE: i64 = 4096;

/// A deferred branch target on the backtrack stack.
#[derive(Clone)]
struct WorkItem {
    pc: usize,
    state: VerifierState,
    stack: StackState,
}

/// Result of verifying a BPF programme.
pub struct CheckResult {
    pub errors: Vec<VerifyError>,
    pub instructions_visited: usize,
}

impl CheckResult {
    pub fn passed(&self) -> bool {
        self.errors.is_empty()
    }
}

struct IdGen(usize);
impl IdGen {
    fn new() -> Self { Self(0) }
    fn next(&mut self) -> usize { let id = self.0; self.0 += 1; id }
}



/// Pre-scan instructions to find PCs that are targets of backward jumps.
fn find_back_edge_targets(
    instructions: &[BpfInsn],
    collapsed_to_raw: &[usize],
    raw_to_collapsed: &HashMap<usize, usize>,
) -> HashSet<usize> {
    let mut targets = HashSet::new();
    for (pc, insn) in instructions.iter().enumerate() {
        let offset = match insn.opcode {
            Opcode::JmpJa => Some(insn.offset),
            Opcode::Jmp64(_, _) | Opcode::Jmp32(_, _) => Some(insn.offset),
            _ => None,
        };
        if let Some(off) = offset {
            if let Some(target) = resolve_branch_target(pc, off, collapsed_to_raw, raw_to_collapsed) {
                if target <= pc {
                    targets.insert(target);
                }
            }
        }
    }
    targets
}

/// Build a mapping from raw BPF PC (counting LdImm64 as 2 slots) to collapsed
/// instruction index (where LdImm64 is 1 entry). Returns a vec where entry `i`
/// is the raw PC of collapsed instruction `i`, and a reverse map from raw PC to
/// collapsed index.
fn build_pc_map(instructions: &[BpfInsn]) -> (Vec<usize>, HashMap<usize, usize>) {
    let mut collapsed_to_raw = Vec::with_capacity(instructions.len());
    let mut raw_to_collapsed = HashMap::new();
    let mut raw_pc: usize = 0;
    for (idx, insn) in instructions.iter().enumerate() {
        collapsed_to_raw.push(raw_pc);
        raw_to_collapsed.insert(raw_pc, idx);
        raw_pc += if matches!(insn.opcode, Opcode::LdImm64) { 2 } else { 1 };
    }
    (collapsed_to_raw, raw_to_collapsed)
}

/// Resolve a branch target: given a branch at collapsed index `pc` with raw
/// offset `offset`, return the collapsed index of the target instruction.
fn resolve_branch_target(
    pc: usize,
    offset: i16,
    collapsed_to_raw: &[usize],
    raw_to_collapsed: &HashMap<usize, usize>,
) -> Option<usize> {
    let raw_pc = collapsed_to_raw[pc];
    let raw_target = raw_pc as i64 + 1 + offset as i64;
    if raw_target < 0 {
        return None;
    }
    raw_to_collapsed.get(&(raw_target as usize)).copied()
}

/// Run the kernel-style verifier on a BPF programme.
///
/// Walks instructions sequentially, processing the fallthrough path first
/// and deferring taken branches to a backtrack stack. At path endpoints
/// (EXIT, errors, pruned states), pops the next deferred branch and
/// continues from there.
pub fn check(
    instructions: &[BpfInsn],
    source_locs: &[Option<SourceLoc>],
) -> CheckResult {
    check_with_relocs(instructions, source_locs, &HashMap::new())
}

/// Run the verifier with relocation info for LD_IMM64 instructions.
pub fn check_with_relocs(
    instructions: &[BpfInsn],
    source_locs: &[Option<SourceLoc>],
    relocations: &HashMap<usize, RelocTarget>,
) -> CheckResult {
    let mut errors = Vec::new();
    let mut total_visited: usize = 0;
    let mut id_gen = IdGen::new();

    if instructions.is_empty() {
        errors.push(VerifyError::new(0, ErrorKind::FallThrough));
        return CheckResult { errors, instructions_visited: 0 };
    }

    let (collapsed_to_raw, raw_to_collapsed) = build_pc_map(instructions);

    let mut reached_exit = false;

    // Backtrack stack: deferred branch targets to explore after the
    // current path ends. The verifier processes the fallthrough path
    // first (like the kernel), deferring the taken branch for later.
    let mut backtrack: Vec<WorkItem> = Vec::new();

    // State pruning: at each PC, store previously-explored states.
    let mut explored: Vec<Vec<(VerifierState, StackState)>> =
        vec![Vec::new(); instructions.len()];
    const MAX_STATES_PER_PC: usize = 32;

    // Back-edge targets: PCs that are jumped to from a later instruction.
    // At these PCs, we widen the explored state rather than storing
    // multiple exact states, ensuring loop convergence.
    let back_edge_targets = find_back_edge_targets(instructions, &collapsed_to_raw, &raw_to_collapsed);

    // Current state: walk instructions sequentially starting at pc=0.
    let mut pc: usize = 0;
    let mut state = VerifierState::entry();
    let mut stack = StackState::new();

    loop {
        // End of path: try to pop a deferred branch from the backtrack stack.
        if pc >= instructions.len() {
            if let Some(item) = backtrack.pop() {
                pc = item.pc;
                state = item.state;
                stack = item.stack;
                continue;
            }
            break;
        }

        total_visited += 1;
        if total_visited > COMPLEXITY_LIMIT {
            errors.push(VerifyError::new(
                pc,
                ErrorKind::ComplexityExceeded {
                    limit: COMPLEXITY_LIMIT,
                    visited: total_visited,
                },
            ));
            break;
        }

        // State pruning: if an already-explored state at this PC subsumes
        // the current state, this path adds nothing new. Backtrack.
        let dominated = explored[pc].iter().any(|(prev_regs, prev_stack)| {
            state.is_substate_of(prev_regs) && stack.is_substate_of(prev_stack)
        });
        if dominated {
            if let Some(item) = backtrack.pop() {
                pc = item.pc;
                state = item.state;
                stack = item.stack;
                continue;
            }
            break;
        }

        if back_edge_targets.contains(&pc) && !explored[pc].is_empty() {
            // At a back-edge target: widen the stored state so the loop
            // converges. Each iteration adds its state to the widened
            // approximation, and eventually the widened state subsumes
            // new iterations.
            let (prev_regs, prev_stack) = &mut explored[pc][0];
            *prev_regs = prev_regs.widen(&state);
            *prev_stack = prev_stack.widen(&stack);
            state = prev_regs.clone();
            stack = prev_stack.clone();
        } else if explored[pc].len() < MAX_STATES_PER_PC {
            explored[pc].push((state.clone(), stack.clone()));
        }

        let insn = &instructions[pc];
        let loc = source_locs.get(pc).and_then(|l| l.as_ref());

        // Process the instruction. For most instructions, advance pc by 1.
        // For branches, defer one path and continue with the other.
        // For EXIT/errors, backtrack to the next deferred branch.
        match insn.opcode {
            Opcode::Unknown(raw) => {
                errors.push(
                    VerifyError::new(pc, ErrorKind::UnknownOpcode { raw })
                        .with_source(loc)
                );
                pc = usize::MAX; // trigger backtrack
            }
            Opcode::Exit => {
                reached_exit = true;
                if let Some(err) = check_exit(&state, pc, loc) {
                    errors.push(err);
                }
                pc = usize::MAX; // trigger backtrack
            }
            Opcode::Call => {
                if let Some(err) = check_call(&mut state, &mut stack, insn, pc, loc, &mut id_gen, source_locs) {
                    errors.push(err);
                    pc = usize::MAX;
                } else {
                    pc += 1;
                }
            }
            Opcode::JmpJa => {
                let target = resolve_branch_target(pc, insn.offset, &collapsed_to_raw, &raw_to_collapsed);
                match target {
                    Some(t) => {
                        pc = t;
                    }
                    None => {
                        errors.push(
                            VerifyError::new(pc, ErrorKind::FallThrough)
                                .with_source(loc)
                        );
                        pc = usize::MAX;
                    }
                }
            }
            Opcode::Jmp64(op, src) | Opcode::Jmp32(op, src) => {
                let is_32 = matches!(insn.opcode, Opcode::Jmp32(..));
                let target = resolve_branch_target(pc, insn.offset, &collapsed_to_raw, &raw_to_collapsed);

                if let Some(err) = check_reg_readable(&state, insn.dst, pc, loc) {
                    errors.push(err);
                    pc = usize::MAX;
                    continue;
                }
                if src == Source::Reg {
                    if let Some(err) = check_reg_readable(&state, insn.src, pc, loc) {
                        errors.push(err);
                        pc = usize::MAX;
                        continue;
                    }
                }

                let target = match target {
                    Some(t) => t,
                    None => {
                        errors.push(
                            VerifyError::new(pc, ErrorKind::FallThrough)
                                .with_source(loc)
                        );
                        pc = usize::MAX;
                        continue;
                    }
                };

                // Refine both branch states.
                let mut taken_state = state.clone();
                let mut taken_stack = stack.clone();
                // state/stack become the fallthrough state after refinement.
                refine_branch(
                    &mut taken_state, &mut taken_stack,
                    &mut state, &mut stack,
                    insn, op, src, is_32,
                );

                // Defer the taken branch for later exploration.
                backtrack.push(WorkItem {
                    pc: target,
                    state: taken_state,
                    stack: taken_stack,
                });

                // Continue with fallthrough.
                pc += 1;
            }
            Opcode::Alu64(op, src) | Opcode::Alu32(op, src) => {
                let is_64 = matches!(insn.opcode, Opcode::Alu64(..));

                if op != AluOp::Mov {
                    if let Some(err) = check_reg_readable(&state, insn.dst, pc, loc) {
                        errors.push(err);
                        pc = usize::MAX;
                        continue;
                    }
                }
                if src == Source::Reg {
                    if let Some(err) = check_reg_readable(&state, insn.src, pc, loc) {
                        errors.push(err);
                        pc = usize::MAX;
                        continue;
                    }
                }

                if let Some(err) = check_alu(&mut state, insn, op, src, is_64, pc, loc) {
                    errors.push(err);
                    pc = usize::MAX;
                } else {
                    pc += 1;
                }
            }
            Opcode::LdImm64 => {
                if let Some(reloc) = relocations.get(&pc) {
                    match reloc {
                        RelocTarget::Map { .. } => {
                            state.set(insn.dst, RegState::scalar_unknown());
                        }
                        RelocTarget::Data { name } => {
                            state.set(insn.dst, RegState {
                                reg_type: RegType::DataPtr { name: name.clone() },
                                tnum: Tnum::unknown(),
                                smin: i64::MIN,
                                smax: i64::MAX,
                                umin: 0,
                                umax: u64::MAX,
                                written_at: None,
                            });
                        }
                        RelocTarget::CoreFieldOffset => {
                            state.set(insn.dst, RegState::kernel_ptr());
                        }
                    }
                } else {
                    let val = insn.imm64.unwrap_or(insn.imm as u32 as u64);
                    state.set(insn.dst, RegState::scalar_value(val));
                }
                pc += 1;
            }
            Opcode::Ldx(w) => {
                if let Some(err) = check_reg_readable(&state, insn.src, pc, loc) {
                    errors.push(err);
                    pc = usize::MAX;
                    continue;
                }
                if let Some(err) = check_load(&mut state, &stack, insn, w, pc, loc, source_locs) {
                    errors.push(err);
                    pc = usize::MAX;
                } else {
                    pc += 1;
                }
            }
            Opcode::Stx(w) => {
                if let Some(err) = check_reg_readable(&state, insn.dst, pc, loc) {
                    errors.push(err);
                    pc = usize::MAX;
                    continue;
                }
                if let Some(err) = check_reg_readable(&state, insn.src, pc, loc) {
                    errors.push(err);
                    pc = usize::MAX;
                    continue;
                }
                if let Some(err) = check_store(&state, &mut stack, insn, w, false, pc, loc, source_locs) {
                    errors.push(err);
                    pc = usize::MAX;
                } else {
                    pc += 1;
                }
            }
            Opcode::St(w) => {
                if let Some(err) = check_reg_readable(&state, insn.dst, pc, loc) {
                    errors.push(err);
                    pc = usize::MAX;
                    continue;
                }
                if let Some(err) = check_store(&state, &mut stack, insn, w, true, pc, loc, source_locs) {
                    errors.push(err);
                    pc = usize::MAX;
                } else {
                    pc += 1;
                }
            }
        }
    }

    if !reached_exit && !errors.iter().any(|e| matches!(e.kind, ErrorKind::ComplexityExceeded { .. })) {
        errors.push(VerifyError::new(0, ErrorKind::FallThrough));
    }

    {
        let mut seen = HashSet::new();
        errors.retain(|e| {
            seen.insert((e.pc, std::mem::discriminant(&e.kind)))
        });
    }

    CheckResult {
        errors,
        instructions_visited: total_visited,
    }
}

fn width_bytes(w: MemWidth) -> u8 {
    match w {
        MemWidth::B => 1,
        MemWidth::H => 2,
        MemWidth::W => 4,
        MemWidth::DW => 8,
    }
}

/// Extract the origin PC from a pointer type, if available.
fn ptr_origin_pc(reg_type: &RegType) -> Option<usize> {
    match reg_type {
        RegType::MapValuePtr { origin_pc, .. } => Some(*origin_pc),
        RegType::RingBufPtr { origin_pc, .. } => Some(*origin_pc),
        RegType::PtrOrNull { origin_pc, .. } => *origin_pc,
        _ => None,
    }
}

/// Resolve an origin PC to a source location.
fn resolve_origin(
    origin_pc: Option<usize>,
    source_locs: &[Option<SourceLoc>],
) -> Option<SourceLoc> {
    origin_pc
        .and_then(|pc| source_locs.get(pc))
        .and_then(|l| l.as_ref())
        .cloned()
}

fn check_reg_readable(
    state: &VerifierState,
    reg: Reg,
    pc: usize,
    loc: Option<&SourceLoc>,
) -> Option<VerifyError> {
    // R10 (frame pointer) is always readable.
    if reg == Reg::R10 {
        return None;
    }
    if !state.get(reg).is_readable() {
        Some(
            VerifyError::new(pc, ErrorKind::UninitRegRead { reg })
                .with_source(loc)
        )
    } else {
        None
    }
}

fn check_exit(
    state: &VerifierState,
    pc: usize,
    loc: Option<&SourceLoc>,
) -> Option<VerifyError> {
    let r0 = state.get(Reg::R0);

    // R0 must be written before exit.
    if r0.reg_type == RegType::Uninit {
        return Some(
            VerifyError::new(pc, ErrorKind::UninitReturn)
                .with_source(loc)
        );
    }

    // R0 must be a scalar at exit (returning a pointer leaks kernel addresses).
    if r0.reg_type.is_ptr() {
        return Some(
            VerifyError::new(
                pc,
                ErrorKind::PtrLeak {
                    reg: Reg::R0,
                    ptr_kind: r0.reg_type.type_name().to_string(),
                },
            )
            .with_source(loc),
        );
    }

    // Null and PtrOrNull are also invalid return values from the kernel's
    // perspective (they indicate the programme didn't handle a null check
    // properly), but they're scalar-like enough that we allow them -- the
    // programme returns 0 in the null case. We only reject actual pointer
    // types leaking.

    None
}

fn check_call(
    state: &mut VerifierState,
    stack: &mut StackState,
    insn: &BpfInsn,
    pc: usize,
    loc: Option<&SourceLoc>,
    id_gen: &mut IdGen,
    _source_locs: &[Option<SourceLoc>],
) -> Option<VerifyError> {
    use crate::bpf::helpers::ArgType;

    let helper = match get_helper(insn.imm) {
        Some(h) => h,
        None => {
            return Some(
                VerifyError::new(pc, ErrorKind::UnknownHelper { id: insn.imm })
                    .with_source(loc)
            );
        }
    };

    // Validate helper arguments.
    let arg_regs = [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5];
    for (i, expected) in helper.args.iter().enumerate() {
        let Some(expected) = expected else { continue };
        let reg = arg_regs[i];
        let actual = &state.get(reg).reg_type;

        // Uninit registers are never valid helper arguments.
        if *actual == RegType::Uninit {
            return Some(
                VerifyError::new(pc, ErrorKind::UninitRegRead { reg })
                    .with_source(loc),
            );
        }

        let ok = match expected {
            ArgType::Any => true,
            ArgType::Scalar | ArgType::Size | ArgType::Flags => {
                matches!(actual, RegType::Scalar | RegType::KernelPtr)
                    || actual == &RegType::Null
            }
            ArgType::PtrToStack => {
                matches!(actual, RegType::FramePtr { .. })
            }
            ArgType::MapPtr => {
                // Map pointers are loaded as 64-bit immediates (scalars)
                // in the compiled BPF. We accept scalars here.
                matches!(actual, RegType::Scalar)
            }
            ArgType::PtrToMapKey | ArgType::PtrToMapValue => {
                matches!(
                    actual,
                    RegType::FramePtr { .. }
                        | RegType::MapValuePtr { .. }
                        | RegType::DataPtr { .. }
                )
            }
            ArgType::PtrToRingBuf => {
                matches!(actual, RegType::RingBufPtr { .. })
            }
            ArgType::PtrToMem => {
                matches!(
                    actual,
                    RegType::FramePtr { .. }
                        | RegType::MapValuePtr { .. }
                        | RegType::RingBufPtr { .. }
                )
            }
            ArgType::PtrToReadonlyMem => {
                matches!(
                    actual,
                    RegType::FramePtr { .. }
                        | RegType::MapValuePtr { .. }
                        | RegType::DataPtr { .. }
                )
            }
        };

        if !ok {
            return Some(
                VerifyError::new(
                    pc,
                    ErrorKind::InvalidHelperArg {
                        helper: helper.name.to_string(),
                        arg_index: i + 1,
                        expected: expected.description().to_string(),
                        actual: format!("{actual}"),
                    },
                )
                .with_source(loc),
            );
        }
    }

    // Set return value based on helper return type.
    match helper.ret_type {
        HelperReturn::Scalar | HelperReturn::ErrorCode => {
            state.set(Reg::R0, RegState::scalar_unknown());
        }
        HelperReturn::KernelPtr => {
            state.set(Reg::R0, RegState::kernel_ptr());
        }
        HelperReturn::MapPtr => {
            let id = id_gen.next();
            let inner = RegType::MapValuePtr {
                id,
                offset: 0,
                size: DEFAULT_MAP_VALUE_SIZE,
                origin_pc: pc,
            };
            state.set(Reg::R0, RegState {
                reg_type: RegType::PtrOrNull { inner: Box::new(inner), origin_pc: Some(pc), id },
                tnum: Tnum::unknown(),
                smin: i64::MIN,
                smax: i64::MAX,
                umin: 0,
                umax: u64::MAX,
                written_at: None,
            });
        }
        HelperReturn::RingBufPtr => {
            let id = id_gen.next();
            // Use the actual reservation size from arg2 if known.
            let reserve_size = state.get(Reg::R2).tnum.known_value()
                .map(|v| v as u32)
                .unwrap_or(DEFAULT_RINGBUF_SIZE);
            let inner = RegType::RingBufPtr {
                id,
                offset: 0,
                size: reserve_size,
                origin_pc: pc,
            };
            state.set(Reg::R0, RegState {
                reg_type: RegType::PtrOrNull { inner: Box::new(inner), origin_pc: Some(pc), id },
                tnum: Tnum::unknown(),
                smin: i64::MIN,
                smax: i64::MAX,
                umin: 0,
                umax: u64::MAX,
                written_at: None,
            });
        }
    }

    // Track helper memory writes. Helpers like bpf_probe_read_kernel write
    // to the pointer in arg1, with the size from arg2. Mark those stack
    // bytes as initialised so subsequent loads don't trigger false positives.
    if let Some(ArgType::PtrToMem | ArgType::PtrToStack) = helper.args[0] {
        if let RegType::FramePtr { offset: dst_off } = &state.get(Reg::R1).reg_type {
            let dst_off = *dst_off;
            let write_size = state.get(Reg::R2).tnum.known_value()
                .unwrap_or(0)
                .min(512) as u8;
            if write_size > 0 {
                stack.mark_written(dst_off, write_size);
            }
            // probe_read_kernel/user read from kernel/user memory.
            // An 8-byte read is typically a pointer-sized struct field,
            // so spill it as KernelPtr for chained field access patterns.
            let is_kernel_read = matches!(
                helper.id,
                4 | 113 | 115  // PROBE_READ, PROBE_READ_KERNEL, PROBE_READ_KERNEL_STR
            );
            if write_size == 8 && is_kernel_read {
                stack.spill(dst_off, &RegState::kernel_ptr());
            }
        }
    }

    // Clobber caller-saved registers r1-r5.
    for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
        state.set(r, RegState::uninit());
    }

    None
}

fn check_alu(
    state: &mut VerifierState,
    insn: &BpfInsn,
    op: AluOp,
    src: Source,
    is_64: bool,
    pc: usize,
    loc: Option<&SourceLoc>,
) -> Option<VerifyError> {
    let dst_reg = insn.dst;
    let dst_state = state.get(dst_reg).clone();

    let src_val: Option<u64> = match src {
        Source::Imm => Some(if is_64 {
            insn.imm as i64 as u64
        } else {
            insn.imm as u32 as u64
        }),
        Source::Reg => state.get(insn.src).tnum.known_value(),
    };

    let src_type = match src {
        Source::Imm => RegType::Scalar,
        Source::Reg => state.get(insn.src).reg_type.clone(),
    };

    match op {
        AluOp::Mov => {
            if src == Source::Imm {
                let val = if is_64 {
                    insn.imm as i64 as u64
                } else {
                    insn.imm as u32 as u64
                };
                state.set(dst_reg, RegState::scalar_value(val));
            } else {
                let mut new_state = state.get(insn.src).clone();
                if !is_64 {
                    // 32-bit mov clears upper bits and demotes pointers to scalars.
                    new_state.reg_type = RegType::Scalar;
                    new_state.tnum = new_state.tnum.trunc32();
                    new_state.umax = new_state.umax.min(0xFFFF_FFFF);
                    new_state.smin = new_state.smin.max(0);
                    new_state.smax = new_state.smax.min(0xFFFF_FFFF);
                }
                state.set(dst_reg, new_state);
            }
            return None;
        }
        AluOp::Neg => {
            // Neg: dst = -dst. Pointers can't be negated.
            if dst_state.reg_type.is_ptr() {
                return Some(
                    VerifyError::new(
                        pc,
                        ErrorKind::InvalidPointerArith {
                            reg: dst_reg,
                            op: "NEG".to_string(),
                        },
                    )
                    .with_source(loc),
                );
            }
            state.set(dst_reg, RegState::scalar_unknown());
            return None;
        }
        _ => {}
    }

    // Check for division/modulo by zero.
    if matches!(op, AluOp::Div | AluOp::Mod) {
        let divisor_could_be_zero = match src {
            Source::Imm => insn.imm == 0,
            Source::Reg => {
                let s = state.get(insn.src);
                s.umin == 0 // could be zero
            }
        };
        if divisor_could_be_zero {
            let divisor_reg = match src {
                Source::Imm => dst_reg, // immediate 0 is always a bug
                Source::Reg => insn.src,
            };
            return Some(
                VerifyError::new(pc, ErrorKind::DivByZero { divisor_reg })
                    .with_source(loc),
            );
        }
    }

    // Check for shift overflow.
    if matches!(op, AluOp::Lsh | AluOp::Rsh | AluOp::Arsh) {
        let max_shift = if is_64 { 63 } else { 31 };
        let shift_amount = match src {
            Source::Imm => Some(insn.imm as u64),
            Source::Reg => {
                let s = state.get(insn.src);
                if s.umax > max_shift { Some(s.umax) } else { None }
            }
        };
        if let Some(amount) = shift_amount {
            if amount > max_shift {
                return Some(
                    VerifyError::new(
                        pc,
                        ErrorKind::ShiftOverflow {
                            width: if is_64 { 64 } else { 32 },
                            amount,
                        },
                    )
                    .with_source(loc),
                );
            }
        }
    }

    // Pointer arithmetic rules.
    if dst_state.reg_type.is_ptr() {
        match op {
            AluOp::Add | AluOp::Sub => {
                if src_type.is_ptr() {
                    if op == AluOp::Sub {
                        // ptr - ptr produces a scalar (offset difference).
                        // The kernel allows this for same-type pointers.
                        state.set(dst_reg, RegState::scalar_unknown());
                        return None;
                    }
                    // ptr + ptr is never valid.
                    return Some(
                        VerifyError::new(
                            pc,
                            ErrorKind::InvalidPointerArith {
                                reg: dst_reg,
                                op: format!("{op} ptr, ptr"),
                            },
                        )
                        .with_source(loc),
                    );
                }

                let delta = match (op, src_val) {
                    (AluOp::Add, Some(v)) => Some(v as i64),
                    (AluOp::Sub, Some(v)) => Some(-(v as i64)),
                    _ => None,
                };

                // When the scalar addend is unknown, we can't track the
                // exact offset. Keep the pointer type (it's still a valid
                // pointer) but reset the offset to 0 since we can't
                // bounds-check precisely. KernelPtr/DataPtr don't track
                // offsets so they're unaffected.
                let Some(delta) = delta else {
                    let new_type = match &dst_state.reg_type {
                        RegType::FramePtr { .. } => RegType::FramePtr { offset: 0 },
                        RegType::CtxPtr { .. } => RegType::CtxPtr { offset: 0 },
                        RegType::MapValuePtr { id, size, origin_pc, .. } => {
                            RegType::MapValuePtr { id: *id, offset: 0, size: *size, origin_pc: *origin_pc }
                        }
                        RegType::RingBufPtr { id, size, origin_pc, .. } => {
                            RegType::RingBufPtr { id: *id, offset: 0, size: *size, origin_pc: *origin_pc }
                        }
                        other => other.clone(),
                    };
                    state.set(dst_reg, RegState {
                        reg_type: new_type,
                        ..RegState::scalar_unknown()
                    });
                    return None;
                };

                let new_type = match &dst_state.reg_type {
                    RegType::FramePtr { offset } => {
                        RegType::FramePtr { offset: offset + delta }
                    }
                    RegType::CtxPtr { offset } => {
                        RegType::CtxPtr { offset: offset + delta }
                    }
                    RegType::MapValuePtr { id, offset, size, origin_pc } => {
                        RegType::MapValuePtr { id: *id, offset: offset + delta, size: *size, origin_pc: *origin_pc }
                    }
                    RegType::RingBufPtr { id, offset, size, origin_pc } => {
                        RegType::RingBufPtr { id: *id, offset: offset + delta, size: *size, origin_pc: *origin_pc }
                    }
                    RegType::KernelPtr => RegType::KernelPtr,
                    RegType::DataPtr { name } => RegType::DataPtr { name: name.clone() },
                    _ => RegType::Scalar,
                };

                state.set(dst_reg, RegState {
                    reg_type: new_type,
                    ..RegState::scalar_unknown()
                });
                return None;
            }
            _ => {
                return Some(
                    VerifyError::new(
                        pc,
                        ErrorKind::InvalidPointerArith {
                            reg: dst_reg,
                            op: format!("{op}"),
                        },
                    )
                    .with_source(loc),
                );
            }
        }
    }

    // Reverse-operand pointer arithmetic: scalar + ptr → ptr.
    // BPF ADD is commutative: if the pointer is in src and the scalar
    // offset is in dst, swap roles and apply pointer arithmetic rules.
    if op == AluOp::Add && src_type.is_ptr() {
        let delta = dst_state.tnum.known_value().map(|v| v as i64);
        let new_type = match (&src_type, delta) {
            (RegType::FramePtr { offset }, Some(d)) => RegType::FramePtr { offset: offset + d },
            (RegType::CtxPtr { offset }, Some(d)) => RegType::CtxPtr { offset: offset + d },
            (RegType::MapValuePtr { id, offset, size, origin_pc }, Some(d)) => {
                RegType::MapValuePtr { id: *id, offset: offset + d, size: *size, origin_pc: *origin_pc }
            }
            (RegType::RingBufPtr { id, offset, size, origin_pc }, Some(d)) => {
                RegType::RingBufPtr { id: *id, offset: offset + d, size: *size, origin_pc: *origin_pc }
            }
            (RegType::KernelPtr, _) => RegType::KernelPtr,
            (RegType::DataPtr { name }, _) => RegType::DataPtr { name: name.clone() },
            // Unknown offset: keep the pointer type, reset offset.
            (RegType::FramePtr { .. }, None) => RegType::FramePtr { offset: 0 },
            (RegType::CtxPtr { .. }, None) => RegType::CtxPtr { offset: 0 },
            (RegType::MapValuePtr { id, size, origin_pc, .. }, None) => {
                RegType::MapValuePtr { id: *id, offset: 0, size: *size, origin_pc: *origin_pc }
            }
            (RegType::RingBufPtr { id, size, origin_pc, .. }, None) => {
                RegType::RingBufPtr { id: *id, offset: 0, size: *size, origin_pc: *origin_pc }
            }
            _ => RegType::Scalar,
        };
        state.set(dst_reg, RegState {
            reg_type: new_type,
            ..RegState::scalar_unknown()
        });
        return None;
    }

    // Scalar ALU: compute result using tnum.
    let dst_tnum = dst_state.tnum;
    let src_tnum = match src {
        Source::Imm => Tnum::constant(if is_64 {
            insn.imm as i64 as u64
        } else {
            insn.imm as u32 as u64
        }),
        Source::Reg => state.get(insn.src).tnum,
    };

    let result_tnum = match op {
        AluOp::Add => dst_tnum.add(src_tnum),
        AluOp::Sub => dst_tnum.sub(src_tnum),
        AluOp::And => dst_tnum.and(src_tnum),
        AluOp::Or => dst_tnum.or(src_tnum),
        AluOp::Xor => dst_tnum.xor(src_tnum),
        AluOp::Lsh => {
            if let Some(s) = src_tnum.known_value() {
                dst_tnum.lsh(s as u32)
            } else {
                Tnum::unknown()
            }
        }
        AluOp::Rsh => {
            if let Some(s) = src_tnum.known_value() {
                dst_tnum.rsh(s as u32)
            } else {
                Tnum::unknown()
            }
        }
        AluOp::Arsh => {
            // Arithmetic right shift -- conservative
            if let (Some(a), Some(s)) = (dst_tnum.known_value(), src_tnum.known_value()) {
                Tnum::constant((a as i64 >> s) as u64)
            } else {
                Tnum::unknown()
            }
        }
        AluOp::Mul => {
            if let (Some(a), Some(b)) = (dst_tnum.known_value(), src_tnum.known_value()) {
                Tnum::constant(a.wrapping_mul(b))
            } else {
                Tnum::unknown()
            }
        }
        AluOp::Div => {
            if let (Some(a), Some(b)) = (dst_tnum.known_value(), src_tnum.known_value()) {
                if b != 0 { Tnum::constant(a / b) } else { Tnum::unknown() }
            } else {
                Tnum::unknown()
            }
        }
        AluOp::Mod => {
            if let (Some(a), Some(b)) = (dst_tnum.known_value(), src_tnum.known_value()) {
                if b != 0 { Tnum::constant(a % b) } else { Tnum::unknown() }
            } else {
                Tnum::unknown()
            }
        }
        AluOp::Mov | AluOp::Neg => unreachable!("handled above"),
    };

    let mut result = if !is_64 {
        let t = result_tnum.trunc32();
        RegState {
            reg_type: RegType::Scalar,
            tnum: t,
            smin: t.min_value() as i64,
            smax: t.max_value() as i64,
            umin: t.min_value(),
            umax: t.max_value(),
            written_at: None,
        }
    } else {
        RegState {
            reg_type: RegType::Scalar,
            tnum: result_tnum,
            smin: result_tnum.min_value() as i64,
            smax: result_tnum.max_value() as i64,
            umin: result_tnum.min_value(),
            umax: result_tnum.max_value(),
            written_at: None,
        }
    };
    result.refine_bounds();

    state.set(dst_reg, result);
    None
}

fn check_load(
    state: &mut VerifierState,
    stack: &StackState,
    insn: &BpfInsn,
    w: MemWidth,
    pc: usize,
    loc: Option<&SourceLoc>,
    source_locs: &[Option<SourceLoc>],
) -> Option<VerifyError> {
    let base = state.get(insn.src);
    let width = width_bytes(w);
    let offset = insn.offset as i64;
    let origin = resolve_origin(ptr_origin_pc(&base.reg_type), source_locs);

    match &base.reg_type {
        RegType::FramePtr { offset: ptr_off } => {
            let eff_off = ptr_off + offset;
            if !StackState::check_bounds(eff_off, width) {
                return Some(
                    VerifyError::new(
                        pc,
                        ErrorKind::OutOfBoundsAccess {
                            reg: insn.src,
                            ptr_kind: "stack",
                            offset: eff_off,
                            width,
                            region_size: STACK_SIZE,
                        },
                    )
                    .with_source(loc),
                );
            }
            if !stack.check_readable(eff_off, width) {
                return Some(
                    VerifyError::new(
                        pc,
                        ErrorKind::UninitStackRead {
                            offset: eff_off,
                            width,
                        },
                    )
                    .with_source(loc),
                );
            }
            // Check for spilled register reload.
            if width == 8 {
                if let Some(spilled) = stack.get_spill(eff_off) {
                    state.set(insn.dst, spilled.clone());
                    return None;
                }
            }
            state.set(insn.dst, RegState::scalar_unknown());
        }
        RegType::MapValuePtr { offset: ptr_off, size, .. } => {
            let eff_off = ptr_off + offset;
            if eff_off < 0 || eff_off + width as i64 > *size as i64 {
                return Some(
                    VerifyError::new(
                        pc,
                        ErrorKind::OutOfBoundsAccess {
                            reg: insn.src,
                            ptr_kind: "map value",
                            offset: eff_off,
                            width,
                            region_size: *size as i64,
                        },
                    )
                    .with_source(loc)
                    .with_origin(origin.as_ref()),
                );
            }
            state.set(insn.dst, RegState::scalar_unknown());
        }
        RegType::CtxPtr { offset: ptr_off } => {
            let eff_off = ptr_off + offset;
            if eff_off < 0 || eff_off + width as i64 > CTX_SIZE {
                return Some(
                    VerifyError::new(
                        pc,
                        ErrorKind::OutOfBoundsAccess {
                            reg: insn.src,
                            ptr_kind: "context",
                            offset: eff_off,
                            width,
                            region_size: CTX_SIZE,
                        },
                    )
                    .with_source(loc),
                );
            }
            // For LSM/tracing hooks, ctx fields are pointers to kernel
            // structures. 64-bit loads from ctx yield kernel pointers;
            // smaller loads yield scalars (e.g. flags, mode fields).
            if width == 8 {
                state.set(insn.dst, RegState::kernel_ptr());
            } else {
                state.set(insn.dst, RegState::scalar_unknown());
            }
        }
        RegType::RingBufPtr { offset: ptr_off, size, .. } => {
            let eff_off = ptr_off + offset;
            if eff_off < 0 || eff_off + width as i64 > *size as i64 {
                return Some(
                    VerifyError::new(
                        pc,
                        ErrorKind::OutOfBoundsAccess {
                            reg: insn.src,
                            ptr_kind: "ring buffer",
                            offset: eff_off,
                            width,
                            region_size: *size as i64,
                        },
                    )
                    .with_source(loc)
                    .with_origin(origin.as_ref()),
                );
            }
            state.set(insn.dst, RegState::scalar_unknown());
        }
        RegType::KernelPtr => {
            // Kernel pointers are valid for dereferencing (field access
            // via CO-RE or direct BTF access). 64-bit loads produce
            // another kernel pointer (pointer-to-struct fields); smaller
            // loads produce scalars (integer fields).
            if width == 8 {
                state.set(insn.dst, RegState::kernel_ptr());
            } else {
                state.set(insn.dst, RegState::scalar_unknown());
            }
        }
        RegType::DataPtr { .. } => {
            // Data section pointers (rodata, global variables) are
            // patched by the loader and always valid. We can't bounds-check
            // because we don't know the data section layout, but the
            // kernel verifier accepts these.
            state.set(insn.dst, RegState::scalar_unknown());
        }
        RegType::PtrOrNull { origin_pc: opc, .. } => {
            let origin_loc = opc
                .and_then(|p| source_locs.get(p))
                .and_then(|l| l.as_ref())
                .cloned();
            return Some(
                VerifyError::new(
                    pc,
                    ErrorKind::NullPointerDeref {
                        reg: insn.src,
                        origin_pc: *opc,
                        origin_loc,
                    },
                )
                .with_source(loc),
            );
        }
        RegType::Null => {
            return Some(
                VerifyError::new(
                    pc,
                    ErrorKind::NullPointerDeref {
                        reg: insn.src,
                        origin_pc: None,
                        origin_loc: None,
                    },
                )
                .with_source(loc),
            );
        }
        RegType::Scalar => {
            return Some(
                VerifyError::new(
                    pc,
                    ErrorKind::InvalidPointerDeref {
                        reg: insn.src,
                        actual: format!("{}", base.reg_type),
                    },
                )
                .with_source(loc)
                .with_reg_provenance(base.written_at),
            );
        }
        RegType::Uninit => {
            return Some(
                VerifyError::new(pc, ErrorKind::UninitRegRead { reg: insn.src })
                    .with_source(loc),
            );
        }
    }

    None
}

fn check_store(
    state: &VerifierState,
    stack: &mut StackState,
    insn: &BpfInsn,
    w: MemWidth,
    is_st: bool,
    pc: usize,
    loc: Option<&SourceLoc>,
    source_locs: &[Option<SourceLoc>],
) -> Option<VerifyError> {
    let base = state.get(insn.dst);
    let width = width_bytes(w);
    let offset = insn.offset as i64;
    let origin = resolve_origin(ptr_origin_pc(&base.reg_type), source_locs);

    // Check that the value being stored doesn't leak a BPF-managed pointer
    // to an untracked destination. Stores to stack (spills) and map values
    // are fine -- the pointer stays within the BPF programme's address space.
    // Kernel pointers and data pointers are opaque values that can be stored
    // anywhere. The real pointer leak check is at exit (r0 must be scalar).
    if !is_st {
        let val_type = &state.get(insn.src).reg_type;
        let is_bpf_ptr = matches!(
            val_type,
            RegType::FramePtr { .. } | RegType::CtxPtr { .. }
        );
        let dst_is_tracked = matches!(
            base.reg_type,
            RegType::FramePtr { .. } | RegType::MapValuePtr { .. } | RegType::RingBufPtr { .. }
        );
        if is_bpf_ptr && !dst_is_tracked {
            return Some(
                VerifyError::new(
                    pc,
                    ErrorKind::PtrLeak {
                        reg: insn.src,
                        ptr_kind: val_type.type_name().to_string(),
                    },
                )
                .with_source(loc),
            );
        }
    }

    match &base.reg_type {
        RegType::FramePtr { offset: ptr_off } => {
            let eff_off = ptr_off + offset;
            if !StackState::check_bounds(eff_off, width) {
                return Some(
                    VerifyError::new(
                        pc,
                        ErrorKind::OutOfBoundsAccess {
                            reg: insn.dst,
                            ptr_kind: "stack",
                            offset: eff_off,
                            width,
                            region_size: STACK_SIZE,
                        },
                    )
                    .with_source(loc),
                );
            }
            // For 8-byte stores from a register, track as a spill.
            // Includes PtrOrNull so that null-check refinement can
            // propagate through stack spills.
            if !is_st && width == 8 {
                let val = state.get(insn.src);
                if val.reg_type.is_ptr() || matches!(val.reg_type, RegType::PtrOrNull { .. }) {
                    stack.spill(eff_off, val);
                } else {
                    stack.clear_spill(eff_off);
                    stack.mark_written(eff_off, width);
                }
            } else {
                stack.clear_spill(eff_off);
                stack.mark_written(eff_off, width);
            }
        }
        RegType::MapValuePtr { offset: ptr_off, size, .. } => {
            let eff_off = ptr_off + offset;
            if eff_off < 0 || eff_off + width as i64 > *size as i64 {
                return Some(
                    VerifyError::new(
                        pc,
                        ErrorKind::OutOfBoundsAccess {
                            reg: insn.dst,
                            ptr_kind: "map value",
                            offset: eff_off,
                            width,
                            region_size: *size as i64,
                        },
                    )
                    .with_source(loc)
                    .with_origin(origin.as_ref()),
                );
            }
        }
        RegType::CtxPtr { offset: ptr_off } => {
            let eff_off = ptr_off + offset;
            if eff_off < 0 || eff_off + width as i64 > CTX_SIZE {
                return Some(
                    VerifyError::new(
                        pc,
                        ErrorKind::OutOfBoundsAccess {
                            reg: insn.dst,
                            ptr_kind: "context",
                            offset: eff_off,
                            width,
                            region_size: CTX_SIZE,
                        },
                    )
                    .with_source(loc),
                );
            }
        }
        RegType::RingBufPtr { offset: ptr_off, size, .. } => {
            let eff_off = ptr_off + offset;
            if eff_off < 0 || eff_off + width as i64 > *size as i64 {
                return Some(
                    VerifyError::new(
                        pc,
                         ErrorKind::OutOfBoundsAccess {
                            reg: insn.dst,
                            ptr_kind: "ring buffer",
                            offset: eff_off,
                            width,
                            region_size: *size as i64,
                        },
                    )
                    .with_source(loc)
                    .with_origin(origin.as_ref()),
                );
            }
        }
        RegType::KernelPtr => {
            // Stores to kernel memory -- the kernel verifier would check
            // write permissions, but we allow it (the programme may be
            // writing to BTF-typed kernel fields).
        }
        RegType::DataPtr { .. } => {
            // Stores to data section pointers are allowed (e.g. global variables).
        }
        RegType::PtrOrNull { origin_pc: opc, .. } => {
            let origin_loc = opc
                .and_then(|p| source_locs.get(p))
                .and_then(|l| l.as_ref())
                .cloned();
            return Some(
                VerifyError::new(
                    pc,
                    ErrorKind::NullPointerDeref {
                        reg: insn.dst,
                        origin_pc: *opc,
                        origin_loc,
                    },
                )
                .with_source(loc),
            );
        }
        RegType::Null => {
            return Some(
                VerifyError::new(
                    pc,
                    ErrorKind::NullPointerDeref {
                        reg: insn.dst,
                        origin_pc: None,
                        origin_loc: None,
                    },
                )
                .with_source(loc),
            );
        }
        RegType::Scalar => {
            return Some(
                VerifyError::new(
                    pc,
                    ErrorKind::InvalidPointerDeref {
                        reg: insn.dst,
                        actual: "scalar".to_string(),
                    },
                )
                .with_source(loc)
                .with_reg_provenance(base.written_at),
            );
        }
        RegType::Uninit => {
            return Some(
                VerifyError::new(pc, ErrorKind::UninitRegRead { reg: insn.dst })
                    .with_source(loc),
            );
        }
    }

    None
}

/// Refine register types on branch taken/fallthrough paths.
///
/// The key insight: when a programme branches on `if (ptr == 0)`,
/// we know that on the taken branch the register is null, and on
/// the fallthrough branch the register is a valid (non-null) pointer.
/// This is how the kernel verifier tracks null checks.
fn refine_branch(
    taken: &mut VerifierState,
    taken_stack: &mut StackState,
    fall: &mut VerifierState,
    fall_stack: &mut StackState,
    insn: &BpfInsn,
    op: JmpOp,
    src: Source,
    is_32: bool,
) {
    let dst = insn.dst;

    // Get the comparison value (either immediate or source register).
    let cmp_val = match src {
        Source::Imm => Some(if is_32 {
            insn.imm as u32 as u64
        } else {
            insn.imm as i64 as u64
        }),
        Source::Reg => {
            // For reg-reg comparisons, we can refine when comparing against a
            // known constant or zero.
            fall.get(insn.src).tnum.known_value()
        }
    };

    // Null check refinement: `if (ptr == 0)` or `if (ptr != 0)`.
    // When a register is null-checked, all registers sharing the same
    // PtrOrNull id are refined on both branches (they alias the same
    // allocation).
    if let Some(0) = cmp_val {
        let dst_type = &fall.get(dst).reg_type;
        if let RegType::PtrOrNull { inner, id: ptr_id, .. } = dst_type {
            let inner = inner.as_ref().clone();
            let ptr_id = *ptr_id;
            match op {
                JmpOp::Jeq => {
                    // taken: ptr == 0 -> null
                    // fall: ptr != 0 -> valid pointer
                    refine_all_with_id(taken, ptr_id, &RegType::Null);
                    refine_spills_with_id(taken_stack, ptr_id, &RegType::Null);
                    refine_all_with_id(fall, ptr_id, &inner);
                    refine_spills_with_id(fall_stack, ptr_id, &inner);
                }
                JmpOp::Jne => {
                    // taken: ptr != 0 -> valid pointer
                    // fall: ptr == 0 -> null
                    refine_all_with_id(taken, ptr_id, &inner);
                    refine_spills_with_id(taken_stack, ptr_id, &inner);
                    refine_all_with_id(fall, ptr_id, &RegType::Null);
                    refine_spills_with_id(fall_stack, ptr_id, &RegType::Null);
                }
                _ => {}
            }
            return;
        }
    }

    // Scalar range refinement.
    if let Some(val) = cmp_val {
        let dst_state = fall.get(dst).clone();
        if dst_state.reg_type == RegType::Scalar {
            if is_32 {
                refine_scalar_32(taken, fall, dst, op, val);
            } else {
                refine_scalar_64(taken, fall, dst, op, val);
            }
        }
    }
}

/// Refine all stack spills that hold a PtrOrNull with the given id.
fn refine_spills_with_id(stack: &mut StackState, ptr_id: usize, new_type: &RegType) {
    for spill in stack.spills_mut() {
        if let RegType::PtrOrNull { id, .. } = &spill.reg_type {
            if *id == ptr_id {
                if *new_type == RegType::Null {
                    *spill = RegState::null();
                } else {
                    spill.reg_type = new_type.clone();
                }
            }
        }
    }
}

/// Refine all registers that hold a PtrOrNull with the given id.
/// On the null branch, set them to Null. On the non-null branch,
/// set them to the inner pointer type.
fn refine_all_with_id(state: &mut VerifierState, ptr_id: usize, new_type: &RegType) {
    for i in 0..11u8 {
        let reg = Reg::from_u8(i).unwrap();
        let reg_state = state.get(reg);
        if let RegType::PtrOrNull { id, .. } = &reg_state.reg_type {
            if *id == ptr_id {
                if *new_type == RegType::Null {
                    state.set(reg, RegState::null());
                } else {
                    let mut refined = state.get(reg).clone();
                    refined.reg_type = new_type.clone();
                    state.set(reg, refined);
                }
            }
        }
    }
}

/// Apply scalar refinement for a 64-bit branch comparison.
fn refine_scalar_64(
    taken: &mut VerifierState,
    fall: &mut VerifierState,
    dst: Reg,
    op: JmpOp,
    val: u64,
) {
    match op {
        JmpOp::Jeq => {
            taken.set(dst, RegState::scalar_value(val));
        }
        JmpOp::Jne => {
            fall.set(dst, RegState::scalar_value(val));
        }
        JmpOp::Jgt => {
            let mut ts = taken.get(dst).clone();
            ts.umin = ts.umin.max(val.saturating_add(1));
            ts.refine_bounds();
            taken.set(dst, ts);
            let mut fs = fall.get(dst).clone();
            fs.umax = fs.umax.min(val);
            fs.refine_bounds();
            fall.set(dst, fs);
        }
        JmpOp::Jge => {
            let mut ts = taken.get(dst).clone();
            ts.umin = ts.umin.max(val);
            ts.refine_bounds();
            taken.set(dst, ts);
            let mut fs = fall.get(dst).clone();
            fs.umax = fs.umax.min(val.saturating_sub(1));
            fs.refine_bounds();
            fall.set(dst, fs);
        }
        JmpOp::Jlt => {
            let mut ts = taken.get(dst).clone();
            ts.umax = ts.umax.min(val.saturating_sub(1));
            ts.refine_bounds();
            taken.set(dst, ts);
            let mut fs = fall.get(dst).clone();
            fs.umin = fs.umin.max(val);
            fs.refine_bounds();
            fall.set(dst, fs);
        }
        JmpOp::Jle => {
            let mut ts = taken.get(dst).clone();
            ts.umax = ts.umax.min(val);
            ts.refine_bounds();
            taken.set(dst, ts);
            let mut fs = fall.get(dst).clone();
            fs.umin = fs.umin.max(val.saturating_add(1));
            fs.refine_bounds();
            fall.set(dst, fs);
        }
        JmpOp::Jsgt => {
            let sval = val as i64;
            let mut ts = taken.get(dst).clone();
            ts.smin = ts.smin.max(sval.saturating_add(1));
            ts.refine_bounds();
            taken.set(dst, ts);
            let mut fs = fall.get(dst).clone();
            fs.smax = fs.smax.min(sval);
            fs.refine_bounds();
            fall.set(dst, fs);
        }
        JmpOp::Jsge => {
            let sval = val as i64;
            let mut ts = taken.get(dst).clone();
            ts.smin = ts.smin.max(sval);
            ts.refine_bounds();
            taken.set(dst, ts);
            let mut fs = fall.get(dst).clone();
            fs.smax = fs.smax.min(sval.saturating_sub(1));
            fs.refine_bounds();
            fall.set(dst, fs);
        }
        JmpOp::Jslt => {
            let sval = val as i64;
            let mut ts = taken.get(dst).clone();
            ts.smax = ts.smax.min(sval.saturating_sub(1));
            ts.refine_bounds();
            taken.set(dst, ts);
            let mut fs = fall.get(dst).clone();
            fs.smin = fs.smin.max(sval);
            fs.refine_bounds();
            fall.set(dst, fs);
        }
        JmpOp::Jsle => {
            let sval = val as i64;
            let mut ts = taken.get(dst).clone();
            ts.smax = ts.smax.min(sval);
            ts.refine_bounds();
            taken.set(dst, ts);
            let mut fs = fall.get(dst).clone();
            fs.smin = fs.smin.max(sval.saturating_add(1));
            fs.refine_bounds();
            fall.set(dst, fs);
        }
        JmpOp::Jset | JmpOp::Ja => {}
    }
}

/// Apply scalar refinement for a 32-bit branch comparison.
///
/// JMP32 compares only the lower 32 bits of the registers, so we must
/// not refine the full 64-bit range. Instead we:
/// 1. Truncate the destination register's bounds to 32 bits.
/// 2. Apply the comparison constraint within the 32-bit domain.
/// 3. Leave the upper 32 bits untouched (they weren't compared).
///
/// For JEQ/JNE we can set the low 32 bits to the known value while
/// preserving the upper bits. For range comparisons we clamp only
/// within [0, 0xFFFF_FFFF].
fn refine_scalar_32(
    taken: &mut VerifierState,
    fall: &mut VerifierState,
    dst: Reg,
    op: JmpOp,
    val: u64,
) {
    let val32 = val & 0xFFFF_FFFF;

    match op {
        JmpOp::Jeq => {
            // taken: low32(dst) == val32
            let mut ts = taken.get(dst).clone();
            // Mask off the low 32 bits of tnum and set them to val32.
            ts.tnum.value = (ts.tnum.value & !0xFFFF_FFFF) | val32;
            ts.tnum.mask &= !0xFFFF_FFFF;
            clamp_u32_bounds(&mut ts, val32, val32);
            ts.refine_bounds();
            taken.set(dst, ts);
            // fall: low32(dst) != val32 -- can't narrow much
        }
        JmpOp::Jne => {
            // fall: low32(dst) == val32
            let mut fs = fall.get(dst).clone();
            fs.tnum.value = (fs.tnum.value & !0xFFFF_FFFF) | val32;
            fs.tnum.mask &= !0xFFFF_FFFF;
            clamp_u32_bounds(&mut fs, val32, val32);
            fs.refine_bounds();
            fall.set(dst, fs);
        }
        JmpOp::Jgt => {
            // taken: low32(dst) > val32
            let mut ts = taken.get(dst).clone();
            clamp_u32_bounds_min(&mut ts, val32.saturating_add(1));
            ts.refine_bounds();
            taken.set(dst, ts);
            // fall: low32(dst) <= val32
            let mut fs = fall.get(dst).clone();
            clamp_u32_bounds_max(&mut fs, val32);
            fs.refine_bounds();
            fall.set(dst, fs);
        }
        JmpOp::Jge => {
            let mut ts = taken.get(dst).clone();
            clamp_u32_bounds_min(&mut ts, val32);
            ts.refine_bounds();
            taken.set(dst, ts);
            let mut fs = fall.get(dst).clone();
            clamp_u32_bounds_max(&mut fs, val32.saturating_sub(1));
            fs.refine_bounds();
            fall.set(dst, fs);
        }
        JmpOp::Jlt => {
            let mut ts = taken.get(dst).clone();
            clamp_u32_bounds_max(&mut ts, val32.saturating_sub(1));
            ts.refine_bounds();
            taken.set(dst, ts);
            let mut fs = fall.get(dst).clone();
            clamp_u32_bounds_min(&mut fs, val32);
            fs.refine_bounds();
            fall.set(dst, fs);
        }
        JmpOp::Jle => {
            let mut ts = taken.get(dst).clone();
            clamp_u32_bounds_max(&mut ts, val32);
            ts.refine_bounds();
            taken.set(dst, ts);
            let mut fs = fall.get(dst).clone();
            clamp_u32_bounds_min(&mut fs, val32.saturating_add(1));
            fs.refine_bounds();
            fall.set(dst, fs);
        }
        JmpOp::Jsgt => {
            // Only refine 64-bit signed bounds when the value is in the
            // 32-bit domain, matching the unsigned case.
            let sval = val32 as i32 as i64;
            if taken.get(dst).umax <= 0xFFFF_FFFF {
                let mut ts = taken.get(dst).clone();
                ts.smin = ts.smin.max(sval.saturating_add(1));
                ts.refine_bounds();
                taken.set(dst, ts);
            }
            if fall.get(dst).umax <= 0xFFFF_FFFF {
                let mut fs = fall.get(dst).clone();
                fs.smax = fs.smax.min(sval);
                fs.refine_bounds();
                fall.set(dst, fs);
            }
        }
        JmpOp::Jsge => {
            let sval = val32 as i32 as i64;
            if taken.get(dst).umax <= 0xFFFF_FFFF {
                let mut ts = taken.get(dst).clone();
                ts.smin = ts.smin.max(sval);
                ts.refine_bounds();
                taken.set(dst, ts);
            }
            if fall.get(dst).umax <= 0xFFFF_FFFF {
                let mut fs = fall.get(dst).clone();
                fs.smax = fs.smax.min(sval.saturating_sub(1));
                fs.refine_bounds();
                fall.set(dst, fs);
            }
        }
        JmpOp::Jslt => {
            let sval = val32 as i32 as i64;
            if taken.get(dst).umax <= 0xFFFF_FFFF {
                let mut ts = taken.get(dst).clone();
                ts.smax = ts.smax.min(sval.saturating_sub(1));
                ts.refine_bounds();
                taken.set(dst, ts);
            }
            if fall.get(dst).umax <= 0xFFFF_FFFF {
                let mut fs = fall.get(dst).clone();
                fs.smin = fs.smin.max(sval);
                fs.refine_bounds();
                fall.set(dst, fs);
            }
        }
        JmpOp::Jsle => {
            let sval = val32 as i32 as i64;
            if taken.get(dst).umax <= 0xFFFF_FFFF {
                let mut ts = taken.get(dst).clone();
                ts.smax = ts.smax.min(sval);
                ts.refine_bounds();
                taken.set(dst, ts);
            }
            if fall.get(dst).umax <= 0xFFFF_FFFF {
                let mut fs = fall.get(dst).clone();
                fs.smin = fs.smin.max(sval.saturating_add(1));
                fs.refine_bounds();
                fall.set(dst, fs);
            }
        }
        JmpOp::Jset | JmpOp::Ja => {}
    }
}

/// Clamp 64-bit unsigned bounds so the low 32 bits fall within [lo, hi].
/// Does not touch the upper 32 bits.
fn clamp_u32_bounds(state: &mut RegState, lo: u64, hi: u64) {
    // If the current 64-bit range is entirely within the 32-bit domain,
    // we can tighten directly.
    if state.umax <= 0xFFFF_FFFF {
        state.umin = state.umin.max(lo);
        state.umax = state.umax.min(hi);
    }
    // Otherwise the upper bits are unknown -- we can't tighten the 64-bit
    // range from a 32-bit comparison without risking unsoundness.
}

fn clamp_u32_bounds_min(state: &mut RegState, lo: u64) {
    if state.umax <= 0xFFFF_FFFF {
        state.umin = state.umin.max(lo);
    }
}

fn clamp_u32_bounds_max(state: &mut RegState, hi: u64) {
    if state.umax <= 0xFFFF_FFFF {
        state.umax = state.umax.min(hi);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::instruction::BpfInsn;

    fn empty_locs(n: usize) -> Vec<Option<SourceLoc>> {
        vec![None; n]
    }

    #[test]
    fn simple_return_passes() {
        // mov r0, 0; exit
        let insns = vec![
            BpfInsn::decode(0x0000_0000_0000_00b7).unwrap(), // mov64 r0, 0
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ];
        let result = check(&insns, &empty_locs(2));
        assert!(result.passed(), "errors: {:?}", result.errors);
    }

    #[test]
    fn uninit_r0_at_exit() {
        // exit without setting r0
        let insns = vec![
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ];
        let result = check(&insns, &empty_locs(1));
        assert!(!result.passed());
        assert!(matches!(result.errors[0].kind, ErrorKind::UninitReturn));
    }

    #[test]
    fn stack_write_then_read_passes() {
        // mov64 r0, 42
        // stx w32 [r10-4], r0
        // ldx w32 r0, [r10-4]
        // exit
        let insns = vec![
            {
                let i = BpfInsn::decode(0x0000_002a_0000_00b7).unwrap(); // mov64 r0, 42
                i
            },
            BpfInsn {
                opcode: Opcode::Stx(MemWidth::W),
                dst: Reg::R10,
                src: Reg::R0,
                offset: -4,
                imm: 0,
                imm64: None,
            },
            BpfInsn {
                opcode: Opcode::Ldx(MemWidth::W),
                dst: Reg::R0,
                src: Reg::R10,
                offset: -4,
                imm: 0,
                imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ];
        let result = check(&insns, &empty_locs(4));
        assert!(result.passed(), "errors: {:?}", result.errors);
    }

    #[test]
    fn uninit_stack_read_fails() {
        // ldx w32 r0, [r10-4]  -- reading uninitialised stack
        // exit
        let insns = vec![
            BpfInsn {
                opcode: Opcode::Ldx(MemWidth::W),
                dst: Reg::R0,
                src: Reg::R10,
                offset: -4,
                imm: 0,
                imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ];
        let result = check(&insns, &empty_locs(2));
        assert!(!result.passed());
        assert!(matches!(result.errors[0].kind, ErrorKind::UninitStackRead { .. }));
    }

    #[test]
    fn stack_oob_fails() {
        // mov64 r0, 42; stx w32 [r10+0], r0; exit  -- writing above stack
        let insns = vec![
            BpfInsn::decode(0x0000_002a_0000_00b7).unwrap(),
            BpfInsn {
                opcode: Opcode::Stx(MemWidth::W),
                dst: Reg::R10,
                src: Reg::R0,
                offset: 0,
                imm: 0,
                imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(),
        ];
        let result = check(&insns, &empty_locs(3));
        assert!(!result.passed());
        assert!(matches!(result.errors[0].kind, ErrorKind::OutOfBoundsAccess { .. }));
    }

    /// Build the standard prologue for map_lookup_elem tests:
    /// sets r1 = scalar (map fd) and r2 = frame pointer (key on stack).
    fn map_lookup_prologue() -> Vec<BpfInsn> {
        vec![
            // r1 = 0 (map fd placeholder -- scalar)
            BpfInsn {
                opcode: Opcode::Alu64(AluOp::Mov, Source::Imm),
                dst: Reg::R1, src: Reg::R0, offset: 0, imm: 0, imm64: None,
            },
            // r2 = r10 (frame pointer for key on stack)
            BpfInsn {
                opcode: Opcode::Alu64(AluOp::Mov, Source::Reg),
                dst: Reg::R2, src: Reg::R10, offset: 0, imm: 0, imm64: None,
            },
            // r2 += -4 (point to stack slot for key)
            BpfInsn {
                opcode: Opcode::Alu64(AluOp::Add, Source::Imm),
                dst: Reg::R2, src: Reg::R0, offset: 0, imm: -4, imm64: None,
            },
            // st [r10-4] = 0 (initialise key slot)
            BpfInsn {
                opcode: Opcode::St(MemWidth::W),
                dst: Reg::R10, src: Reg::R0, offset: -4, imm: 0, imm64: None,
            },
        ]
    }

    #[test]
    fn null_deref_fails() {
        // prologue: set up r1 (map fd), r2 (key ptr)
        // call map_lookup_elem  (helper 1)
        // ldx w64 r1, [r0+0]   -- deref without null check
        // mov64 r0, 0
        // exit
        let mut insns = map_lookup_prologue();
        insns.extend([
            BpfInsn {
                opcode: Opcode::Call,
                dst: Reg::R0, src: Reg::R0, offset: 0, imm: 1, imm64: None,
            },
            BpfInsn {
                opcode: Opcode::Ldx(MemWidth::DW),
                dst: Reg::R1, src: Reg::R0, offset: 0, imm: 0, imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_00b7).unwrap(), // mov64 r0, 0
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ]);
        let result = check(&insns, &empty_locs(insns.len()));
        assert!(!result.passed());
        assert!(
            result.errors.iter().any(|e| matches!(e.kind, ErrorKind::NullPointerDeref { .. })),
            "expected null deref error, got: {:?}", result.errors
        );
    }

    #[test]
    fn null_check_then_deref_passes() {
        // prologue: set up r1 (map fd), r2 (key ptr)
        // call map_lookup_elem (helper 1)  -- r0 = ptr_or_null
        // jeq r0, 0, +2                    -- if null, skip to exit
        // ldx w64 r1, [r0+0]               -- deref (safe: null check passed)
        // mov64 r0, 0
        // exit
        let mut insns = map_lookup_prologue();
        insns.extend([
            BpfInsn {
                opcode: Opcode::Call,
                dst: Reg::R0, src: Reg::R0, offset: 0, imm: 1, imm64: None,
            },
            BpfInsn {
                opcode: Opcode::Jmp64(JmpOp::Jeq, Source::Imm),
                dst: Reg::R0, src: Reg::R0, offset: 2, imm: 0, imm64: None,
            },
            BpfInsn {
                opcode: Opcode::Ldx(MemWidth::DW),
                dst: Reg::R1, src: Reg::R0, offset: 0, imm: 0, imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_00b7).unwrap(), // mov64 r0, 0
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ]);
        let result = check(&insns, &empty_locs(insns.len()));
        assert!(result.passed(), "errors: {:?}", result.errors);
    }

    #[test]
    fn div_by_zero_fails() {
        // mov64 r0, 10; mov64 r1, 0; div64 r0, r1; exit
        let insns = vec![
            BpfInsn::decode(0x0000_000a_0000_00b7).unwrap(), // mov64 r0, 10
            BpfInsn::decode(0x0000_0000_0000_01b7).unwrap(), // mov64 r1, 0
            BpfInsn {
                opcode: Opcode::Alu64(AluOp::Div, Source::Reg),
                dst: Reg::R0,
                src: Reg::R1,
                offset: 0,
                imm: 0,
                imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ];
        let result = check(&insns, &empty_locs(4));
        assert!(!result.passed());
        assert!(
            result.errors.iter().any(|e| matches!(e.kind, ErrorKind::DivByZero { .. })),
            "expected div-by-zero error, got: {:?}", result.errors
        );
    }

    #[test]
    fn unknown_helper_fails() {
        let insns = vec![
            BpfInsn {
                opcode: Opcode::Call,
                dst: Reg::R0,
                src: Reg::R0,
                offset: 0,
                imm: 9999, // unknown helper
                imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(),
        ];
        let result = check(&insns, &empty_locs(2));
        assert!(!result.passed());
        assert!(matches!(result.errors[0].kind, ErrorKind::UnknownHelper { id: 9999 }));
    }

    #[test]
    fn bounded_loop_passes() {
        // Simulate: for (i = 0; i < 3; i++) {}
        // 0: mov32 r1, 0          // i = 0
        // 1: mov32 r0, 0          // return value
        // 2: add32 r1, 1          // i++       <-- loop head
        // 3: jeq32 r1, 3, +1      // if i == 3, exit loop
        // 4: ja -3                 // back to insn 2
        // 5: exit
        let insns = vec![
            BpfInsn {
                opcode: Opcode::Alu32(AluOp::Mov, Source::Imm),
                dst: Reg::R1, src: Reg::R0, offset: 0, imm: 0, imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_00b7).unwrap(), // mov64 r0, 0
            BpfInsn {
                opcode: Opcode::Alu32(AluOp::Add, Source::Imm),
                dst: Reg::R1, src: Reg::R0, offset: 0, imm: 1, imm64: None,
            },
            BpfInsn {
                opcode: Opcode::Jmp32(JmpOp::Jeq, Source::Imm),
                dst: Reg::R1, src: Reg::R0, offset: 1, imm: 3, imm64: None,
            },
            BpfInsn {
                opcode: Opcode::JmpJa,
                dst: Reg::R0, src: Reg::R0, offset: -3, imm: 0, imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ];
        let result = check(&insns, &empty_locs(6));
        assert!(result.passed(), "errors: {:?}", result.errors);
    }

    #[test]
    fn ptr_leak_at_exit_fails() {
        // mov64 r0, r1  (r1 = ctx_ptr at entry)
        // exit           (returning a pointer)
        let insns = vec![
            BpfInsn {
                opcode: Opcode::Alu64(AluOp::Mov, Source::Reg),
                dst: Reg::R0,
                src: Reg::R1,
                offset: 0,
                imm: 0,
                imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ];
        let result = check(&insns, &empty_locs(2));
        assert!(!result.passed());
        assert!(
            result.errors.iter().any(|e| matches!(e.kind, ErrorKind::PtrLeak { .. })),
            "expected ptr leak error, got: {:?}", result.errors
        );
    }

    #[test]
    fn scalar_range_refinement() {
        // mov64 r0, ???  (unknown scalar from ctx load)
        // jge r0, 10, +1  -- taken: r0 >= 10, fall: r0 < 10
        // mov64 r0, 0
        // exit
        // This tests that the branch refinement narrows bounds.
        let insns = vec![
            BpfInsn {
                opcode: Opcode::Ldx(MemWidth::W),
                dst: Reg::R0,
                src: Reg::R1, // ctx ptr
                offset: 0,
                imm: 0,
                imm64: None,
            },
            BpfInsn {
                opcode: Opcode::Jmp64(JmpOp::Jge, Source::Imm),
                dst: Reg::R0,
                src: Reg::R0,
                offset: 1,
                imm: 10,
                imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_00b7).unwrap(), // mov64 r0, 0
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ];
        let result = check(&insns, &empty_locs(4));
        assert!(result.passed(), "errors: {:?}", result.errors);
    }

    #[test]
    fn pointer_add_scalar_passes() {
        // r2 = r10; r2 += -8; stx [r2+0], r0; -- frame ptr arithmetic
        let insns = vec![
            BpfInsn::decode(0x0000_0000_0000_00b7).unwrap(), // mov64 r0, 0
            BpfInsn {
                opcode: Opcode::Alu64(AluOp::Mov, Source::Reg),
                dst: Reg::R2,
                src: Reg::R10,
                offset: 0,
                imm: 0,
                imm64: None,
            },
            BpfInsn {
                opcode: Opcode::Alu64(AluOp::Add, Source::Imm),
                dst: Reg::R2,
                src: Reg::R0,
                offset: 0,
                imm: -8,
                imm64: None,
            },
            BpfInsn {
                opcode: Opcode::Stx(MemWidth::DW),
                dst: Reg::R2,
                src: Reg::R0,
                offset: 0,
                imm: 0,
                imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit
        ];
        let result = check(&insns, &empty_locs(5));
        assert!(result.passed(), "errors: {:?}", result.errors);
    }

    #[test]
    fn pointer_mul_fails() {
        // r0 = r10; r0 *= 2 -- can't multiply a pointer
        let insns = vec![
            BpfInsn {
                opcode: Opcode::Alu64(AluOp::Mov, Source::Reg),
                dst: Reg::R0,
                src: Reg::R10,
                offset: 0,
                imm: 0,
                imm64: None,
            },
            BpfInsn {
                opcode: Opcode::Alu64(AluOp::Mul, Source::Imm),
                dst: Reg::R0,
                src: Reg::R0,
                offset: 0,
                imm: 2,
                imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(),
        ];
        let result = check(&insns, &empty_locs(3));
        assert!(!result.passed());
        assert!(
            result.errors.iter().any(|e| matches!(e.kind, ErrorKind::InvalidPointerArith { .. })),
            "expected invalid ptr arith, got: {:?}", result.errors
        );
    }

    #[test]
    fn helper_clobbers_caller_saved() {
        // r6 = r1 (save ctx); call ktime_get_ns; ldx r0, [r6+0]; exit
        // r6 is callee-saved so it survives the call.
        // r1 is caller-saved and should be clobbered.
        let insns = vec![
            BpfInsn {
                opcode: Opcode::Alu64(AluOp::Mov, Source::Reg),
                dst: Reg::R6,
                src: Reg::R1,
                offset: 0,
                imm: 0,
                imm64: None,
            },
            BpfInsn {
                opcode: Opcode::Call,
                dst: Reg::R0,
                src: Reg::R0,
                offset: 0,
                imm: 5, // ktime_get_ns
                imm64: None,
            },
            BpfInsn {
                opcode: Opcode::Ldx(MemWidth::W),
                dst: Reg::R0,
                src: Reg::R6, // still ctx_ptr
                offset: 0,
                imm: 0,
                imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(),
        ];
        let result = check(&insns, &empty_locs(4));
        assert!(result.passed(), "errors: {:?}", result.errors);
    }

    #[test]
    fn read_clobbered_reg_after_call_fails() {
        // call ktime_get_ns; ldx r0, [r1+0]; exit
        // r1 was clobbered by the call.
        let insns = vec![
            BpfInsn::decode(0x0000_0000_0000_00b7).unwrap(), // mov64 r0, 0
            BpfInsn {
                opcode: Opcode::Call,
                dst: Reg::R0,
                src: Reg::R0,
                offset: 0,
                imm: 5,
                imm64: None,
            },
            BpfInsn {
                opcode: Opcode::Ldx(MemWidth::W),
                dst: Reg::R0,
                src: Reg::R1, // clobbered
                offset: 0,
                imm: 0,
                imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(),
        ];
        let result = check(&insns, &empty_locs(4));
        assert!(!result.passed());
        assert!(
            result.errors.iter().any(|e| matches!(e.kind, ErrorKind::UninitRegRead { reg: Reg::R1 })),
            "expected uninit R1 read, got: {:?}", result.errors
        );
    }

    #[test]
    fn jmp32_does_not_refine_64bit_range() {
        // If r0 holds a large 64-bit value (e.g. 0x1_0000_0003), a JMP32
        // comparison against 5 should only refine the low 32 bits, not
        // clamp the full 64-bit umax.
        //
        // ld_imm64 r0, 0x1_0000_0003
        // jlt32 r0, 5, +1           -- low32(r0) = 3 < 5, branch taken
        // exit                       -- fallthrough (low32(r0) >= 5)
        // exit                       -- taken (low32(r0) < 5)
        //
        // On the fallthrough path, r0 should still have umax >= 0x1_0000_0003
        // because JMP32 can't constrain the upper bits.
        let insns = vec![
            BpfInsn {
                opcode: Opcode::LdImm64,
                dst: Reg::R0, src: Reg::R0, offset: 0, imm: 0,
                imm64: Some(0x1_0000_0003),
            },
            BpfInsn {
                opcode: Opcode::Jmp32(JmpOp::Jlt, Source::Imm),
                dst: Reg::R0, src: Reg::R0, offset: 1, imm: 5, imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit (fall)
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit (taken)
        ];
        // This should pass -- both paths exit with a scalar r0.
        let result = check(&insns, &empty_locs(4));
        assert!(result.passed(), "errors: {:?}", result.errors);
    }

    #[test]
    fn jmp32_refines_when_upper_bits_zero() {
        // When the 64-bit value is within the 32-bit domain (umax <= 0xFFFF_FFFF),
        // JMP32 refinement should tighten normally.
        //
        // mov64 r0, 10
        // jge32 r0, 5, +1           -- taken: low32(r0) >= 5
        // exit                       -- fall: low32(r0) < 5
        // exit                       -- taken
        let insns = vec![
            BpfInsn {
                opcode: Opcode::Alu64(AluOp::Mov, Source::Imm),
                dst: Reg::R0, src: Reg::R0, offset: 0, imm: 10, imm64: None,
            },
            BpfInsn {
                opcode: Opcode::Jmp32(JmpOp::Jge, Source::Imm),
                dst: Reg::R0, src: Reg::R0, offset: 1, imm: 5, imm64: None,
            },
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit (fall)
            BpfInsn::decode(0x0000_0000_0000_0095).unwrap(), // exit (taken)
        ];
        let result = check(&insns, &empty_locs(4));
        assert!(result.passed(), "errors: {:?}", result.errors);
    }
}
