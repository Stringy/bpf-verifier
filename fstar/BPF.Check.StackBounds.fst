(* BPF.Check.StackBounds -- static stack bounds checker via abstract interpretation.

   This is the first safety layer in our CertiKOS-style layered verification.
   It performs a forward abstract interpretation over a BPF programme, tracking
   which registers hold a derived frame pointer (and at what offset from r10)
   and which hold something else (scalars, map pointers, etc.).

   At every memory access instruction (BPF_LDX, BPF_STX, BPF_ST), if the base
   register is a known frame pointer, we check that the effective offset falls
   within the 512-byte stack. If any access is provably out-of-bounds, the
   check fails. If the base register is not a known frame pointer, we
   conservatively skip the stack bounds check for that instruction (other
   layers handle map pointer and null checks).

   The analysis is branch-aware: at conditional jumps, we record the current
   abstract state for the jump target. When execution reaches a branch target,
   we merge (join) the saved state with the fall-through state. This prevents
   false positives from stale FramePtr tracking after control flow merges.

   The abstract domain is:
     AbsFramePtr off -- register is r10 (or derived from r10) with known offset
     AbsOther        -- register holds something we don't track here

   F* notes for BPF developers:
   - `option abs_state` is either `Some new_state` (check passed) or `None`
     (definite out-of-bounds detected)
   - `Tot` means the function always terminates -- F* proves this
   - `decreases prog` tells F* the recursive function terminates because
     the list gets shorter on each call *)
module BPF.Check.StackBounds

open FStar.Mul
open FStar.Int32
open BPF.State
open BPF.Semantics

(* --- Abstract register domain ---
   AbsFramePtr off : register is known to be FramePtr with this offset
   AbsOther        : register holds a scalar, map pointer, null, or
                     a frame pointer whose offset we lost track of *)
type abs_reg =
  | AbsFramePtr : int -> abs_reg
  | AbsOther : abs_reg

(* Abstract state is a function from register index to abstract value.
   Using a function (like reg_file in BPF.State) lets F*'s normaliser
   reduce abs_get/abs_set via beta-reduction -- no sequences needed. *)
type abs_state = reg_idx -> abs_reg

let abs_get (abs: abs_state) (r: reg_idx) : abs_reg = abs r

let abs_set (abs: abs_state) (r: reg_idx) (v: abs_reg) : abs_state =
  fun i -> if i = r then v else abs i

(* Initial abstract state at programme entry.
   r10 is the frame pointer with offset 0 (top of stack).
   All other registers are unknown. *)
let abs_init : abs_state =
  fun r -> if r = r10 then AbsFramePtr 0 else AbsOther

(* --- Branch target tracking ---
   At conditional jumps, we save the current abstract state for the
   jump target pc. When the linear scan reaches that pc, we merge
   the saved state with the fall-through state. This handles control
   flow joins correctly -- if a register is FramePtr(-4) on one path
   and AbsOther on another, the merged result is AbsOther.

   We use int for pc because branch offsets can be negative. *)
type branch_targets = list (int & abs_state)

(* --- Join function for merging abstract register values ---
   At a branch join point, if both paths agree on a FramePtr offset,
   keep it. Otherwise, fall back to AbsOther. *)
let join_reg (a b: abs_reg) : abs_reg =
  match a, b with
  | AbsFramePtr x, AbsFramePtr y -> if x = y then AbsFramePtr x else AbsOther
  | _, _ -> AbsOther

(* Join two full abstract states register-by-register. *)
let join_states (a b: abs_state) : abs_state =
  fun r -> join_reg (a r) (b r)

(* Merge all saved branch states targeting this pc into the current state. *)
let rec merge_targets_at (pc: int) (targets: branch_targets) (acc: abs_state)
  : Tot abs_state (decreases targets) =
  match targets with
  | [] -> acc
  | (tpc, tstate) :: rest ->
    if tpc = pc
    then merge_targets_at pc rest (join_states acc tstate)
    else merge_targets_at pc rest acc

(* Remove all branch target entries for a given pc. *)
let rec remove_targets_at (pc: int) (targets: branch_targets)
  : Tot branch_targets (decreases targets) =
  match targets with
  | [] -> []
  | (tpc, tstate) :: rest ->
    if tpc = pc
    then remove_targets_at pc rest
    else (tpc, tstate) :: remove_targets_at pc rest

(* Merge and clean up in one step. *)
let apply_targets (abs: abs_state) (pc: int) (targets: branch_targets)
  : abs_state & branch_targets =
  let merged = merge_targets_at pc targets abs in
  let cleaned = remove_targets_at pc targets in
  (merged, cleaned)

(* --- Stack bounds check for memory accesses ---
   Given a base register's abstract value and the instruction's offset,
   check whether the effective stack offset is within [0, 512).
   Returns true if safe or if the base isn't a known frame pointer. *)
let check_mem_access (base: abs_reg) (insn_off: Int32.t) (w: mem_width) : bool =
  match base with
  | AbsFramePtr ptr_off ->
    let eff_off = ptr_off + sign_extend_to_int insn_off in
    stack_offset_valid eff_off w
  | AbsOther ->
    true

(* --- Per-instruction abstract transfer function ---
   Takes the current abstract state, one instruction, current pc, and
   branch targets. Returns the new abstract state and updated targets,
   or None if a stack bounds violation is detected.

   At each instruction:
   1. Merge any branch targets at the current pc
   2. Apply the instruction's transfer rules
   3. For conditional branches, record the jump target *)
let check_insn_sb (abs: abs_state) (insn: bpf_insn) (pc: int) (targets: branch_targets)
  : option (abs_state & branch_targets) =

  (* Step 1: merge any saved branch states targeting this pc *)
  let (abs, targets) = apply_targets abs pc targets in

  match insn with

  (* --- 64-bit ALU, register operands --- *)
  | BPF_ALU64_REG op dst src ->
    (match op with
     | MOV -> Some (abs_set abs dst (abs_get abs src), targets)
     | _ -> Some (abs_set abs dst AbsOther, targets))

  (* --- 64-bit ALU, immediate operand --- *)
  | BPF_ALU64_IMM op dst imm ->
    (match op with
     | MOV -> Some (abs_set abs dst AbsOther, targets)
     | ADD ->
       (match abs_get abs dst with
        | AbsFramePtr off ->
          Some (abs_set abs dst (AbsFramePtr (off + sign_extend_to_int imm)), targets)
        | AbsOther -> Some (abs_set abs dst AbsOther, targets))
     | SUB ->
       (match abs_get abs dst with
        | AbsFramePtr off ->
          Some (abs_set abs dst (AbsFramePtr (off - sign_extend_to_int imm)), targets)
        | AbsOther -> Some (abs_set abs dst AbsOther, targets))
     | _ -> Some (abs_set abs dst AbsOther, targets))

  (* --- 32-bit ALU ops always destroy frame pointer tracking --- *)
  | BPF_ALU32_REG _ dst _ -> Some (abs_set abs dst AbsOther, targets)
  | BPF_ALU32_IMM _ dst _ -> Some (abs_set abs dst AbsOther, targets)

  (* --- Load 64-bit immediate: always a scalar --- *)
  | BPF_LD_IMM64 dst _ -> Some (abs_set abs dst AbsOther, targets)

  (* --- Memory load (LDX): check bounds, then set dst to AbsOther --- *)
  | BPF_LDX w dst src off ->
    if check_mem_access (abs_get abs src) off w
    then Some (abs_set abs dst AbsOther, targets)
    else None

  (* --- Memory store from register (STX): check bounds, state unchanged --- *)
  | BPF_STX w dst _src off ->
    if check_mem_access (abs_get abs dst) off w
    then Some (abs, targets)
    else None

  (* --- Memory store immediate (ST): check bounds, state unchanged --- *)
  | BPF_ST w dst off _imm ->
    if check_mem_access (abs_get abs dst) off w
    then Some (abs, targets)
    else None

  (* --- Conditional jumps: record branch target for merging --- *)
  | BPF_JMP64_IMM _ _ _ offset ->
    let target_pc = pc + 1 + offset in
    Some (abs, (target_pc, abs) :: targets)
  | BPF_JMP64_REG _ _ _ offset ->
    let target_pc = pc + 1 + offset in
    Some (abs, (target_pc, abs) :: targets)
  | BPF_JMP32_IMM _ _ _ offset ->
    let target_pc = pc + 1 + offset in
    Some (abs, (target_pc, abs) :: targets)
  | BPF_JMP32_REG _ _ _ offset ->
    let target_pc = pc + 1 + offset in
    Some (abs, (target_pc, abs) :: targets)

  (* --- Unconditional jump: no fork, pass through --- *)
  | BPF_JMP_JA _ -> Some (abs, targets)

  (* --- BPF_CALL: clobber caller-saved registers r0-r5 ---
     r6-r9 are callee-saved and preserve their abstract values.
     r10 (frame pointer) is always preserved. *)
  | BPF_CALL _ ->
    let abs1 = abs_set abs 0 AbsOther in
    let abs2 = abs_set abs1 1 AbsOther in
    let abs3 = abs_set abs2 2 AbsOther in
    let abs4 = abs_set abs3 3 AbsOther in
    let abs5 = abs_set abs4 4 AbsOther in
    let abs6 = abs_set abs5 5 AbsOther in
    Some (abs6, targets)

  (* --- EXIT: pass through --- *)
  | BPF_EXIT -> Some (abs, targets)

(* --- Whole-programme check ---
   Walk the instruction list front-to-back, threading the abstract
   state, pc, and branch targets through each instruction. *)
let rec check_program_loop (abs: abs_state) (prog: list bpf_insn) (pc: int) (targets: branch_targets)
  : Tot bool (decreases prog) =
  match prog with
  | [] -> true
  | insn :: rest ->
    match check_insn_sb abs insn pc targets with
    | None -> false
    | Some (abs', targets') -> check_program_loop abs' rest (pc + 1) targets'

(* Top-level entry point. *)
let stack_bounds_check (prog: bpf_program) : bool =
  check_program_loop abs_init prog 0 []
