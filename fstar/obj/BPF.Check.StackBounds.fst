(* BPF.Check.StackBounds -- static stack bounds checker via abstract interpretation.

   Tracks which registers hold derived frame pointers (offsets from r10)
   and verifies that every memory access through a frame pointer falls
   within the 512-byte stack.

   Branch-aware: at conditional jumps, we record the abstract state for
   the jump target. When execution reaches that pc, we merge (join) the
   saved state with the fall-through state. This prevents false positives
   from stale FramePtr tracking after control flow merges.

   Branch targets use a function-based map (int -> option abs_state)
   rather than a list. This matches the pattern used for register files
   and abstract states -- F*'s normaliser reduces function application
   via beta-reduction instantly, avoiding the O(n) list scans that
   cause performance problems on large programmes. *)
module BPF.Check.StackBounds

open FStar.Mul
open FStar.Int32
open BPF.State
open BPF.Semantics

(* --- Abstract register domain --- *)
type abs_reg =
  | AbsFramePtr : int -> abs_reg
  | AbsCtxPtr : int -> abs_reg
  | AbsRingBufPtr : nat -> abs_reg
  | AbsOther : abs_reg

(* Function-based abstract state, same pattern as reg_file. *)
type abs_state = reg_idx -> abs_reg

let abs_get (abs: abs_state) (r: reg_idx) : abs_reg = abs r

let abs_set (abs: abs_state) (r: reg_idx) (v: abs_reg) : abs_state =
  fun i -> if i = r then v else abs i

let abs_init : abs_state =
  fun r -> if r = r10 then AbsFramePtr 0
           else if r = r1 then AbsCtxPtr 0
           else AbsOther

(* --- Branch target map ---
   Function-based map from pc to saved abstract state. Lookup is a
   single beta-reduction step -- the normaliser handles this instantly
   regardless of how many branches have been recorded.

   Adding a target joins with any existing entry at that pc, so
   multiple branches targeting the same pc are handled correctly. *)
type target_map = int -> option abs_state

(* Empty target map -- no branches recorded yet. *)
let empty_targets : target_map = fun _ -> None

(* --- Join --- *)
let join_reg (a b: abs_reg) : abs_reg =
  match a, b with
  | AbsFramePtr x, AbsFramePtr y -> if x = y then AbsFramePtr x else AbsOther
  | AbsCtxPtr x, AbsCtxPtr y -> if x = y then AbsCtxPtr x else AbsOther
  | AbsRingBufPtr x, AbsRingBufPtr y -> if x = y then AbsRingBufPtr x else AbsOther
  | _, _ -> AbsOther

let join_states (a b: abs_state) : abs_state =
  fun r -> join_reg (a r) (b r)

(* Record a branch target. If there's already a saved state at this pc,
   join it with the new state (handles multiple branches to same target). *)
let add_target (targets: target_map) (pc: int) (state: abs_state) : target_map =
  fun i -> if i = pc then
    (match targets i with
     | Some existing -> Some (join_states existing state)
     | None -> Some state)
  else targets i

(* Merge any saved branch state at this pc into the current state,
   and clear the entry. Returns the merged state and updated map. *)
let apply_targets (abs: abs_state) (pc: int) (targets: target_map)
  : abs_state & target_map =
  match targets pc with
  | Some saved ->
    let merged = join_states abs saved in
    let cleared = fun i -> if i = pc then None else targets i in
    (merged, cleared)
  | None -> (abs, targets)

(* --- Stack bounds check for memory accesses --- *)
let check_mem_access (base: abs_reg) (insn_off: Int32.t) (w: mem_width) : bool =
  match base with
  | AbsFramePtr ptr_off ->
    let eff_off = ptr_off + sign_extend_to_int insn_off in
    stack_offset_valid eff_off w
  | AbsCtxPtr _ -> true
  | AbsRingBufPtr _ -> true
  | AbsOther -> true

(* --- Per-instruction transfer function --- *)
let check_insn_sb (abs: abs_state) (insn: bpf_insn) (pc: int) (targets: target_map)
  : option (abs_state & target_map) =

  let (abs, targets) = apply_targets abs pc targets in

  match insn with
  | BPF_ALU64_REG op dst src ->
    (match op with
     | MOV -> Some (abs_set abs dst (abs_get abs src), targets)
     | _ -> Some (abs_set abs dst AbsOther, targets))

  | BPF_ALU64_IMM op dst imm ->
    (match op with
     | MOV -> Some (abs_set abs dst AbsOther, targets)
     | ADD ->
       (match abs_get abs dst with
        | AbsFramePtr off ->
          Some (abs_set abs dst (AbsFramePtr (off + sign_extend_to_int imm)), targets)
        | AbsCtxPtr off ->
          Some (abs_set abs dst (AbsCtxPtr (off + sign_extend_to_int imm)), targets)
        | AbsRingBufPtr _ -> Some (abs_set abs dst AbsOther, targets)
        | AbsOther -> Some (abs_set abs dst AbsOther, targets))
     | SUB ->
       (match abs_get abs dst with
        | AbsFramePtr off ->
          Some (abs_set abs dst (AbsFramePtr (off - sign_extend_to_int imm)), targets)
        | AbsCtxPtr off ->
          Some (abs_set abs dst (AbsCtxPtr (off - sign_extend_to_int imm)), targets)
        | AbsRingBufPtr _ -> Some (abs_set abs dst AbsOther, targets)
        | AbsOther -> Some (abs_set abs dst AbsOther, targets))
     | _ -> Some (abs_set abs dst AbsOther, targets))

  | BPF_ALU32_REG _ dst _ -> Some (abs_set abs dst AbsOther, targets)
  | BPF_ALU32_IMM _ dst _ -> Some (abs_set abs dst AbsOther, targets)
  | BPF_LD_IMM64 dst _ -> Some (abs_set abs dst AbsOther, targets)

  | BPF_LDX w dst src off ->
    if check_mem_access (abs_get abs src) off w
    then Some (abs_set abs dst AbsOther, targets)
    else None

  | BPF_STX w dst _src off ->
    if check_mem_access (abs_get abs dst) off w
    then Some (abs, targets)
    else None

  | BPF_ST w dst off _imm ->
    if check_mem_access (abs_get abs dst) off w
    then Some (abs, targets)
    else None

  | BPF_JMP64_IMM _ _ _ offset ->
    Some (abs, add_target targets (pc + 1 + offset) abs)
  | BPF_JMP64_REG _ _ _ offset ->
    Some (abs, add_target targets (pc + 1 + offset) abs)
  | BPF_JMP32_IMM _ _ _ offset ->
    Some (abs, add_target targets (pc + 1 + offset) abs)
  | BPF_JMP32_REG _ _ _ offset ->
    Some (abs, add_target targets (pc + 1 + offset) abs)
  | BPF_JMP_JA _ -> Some (abs, targets)

  | BPF_CALL _ ->
    let abs1 = abs_set abs 0 AbsOther in
    let abs2 = abs_set abs1 1 AbsOther in
    let abs3 = abs_set abs2 2 AbsOther in
    let abs4 = abs_set abs3 3 AbsOther in
    let abs5 = abs_set abs4 4 AbsOther in
    let abs6 = abs_set abs5 5 AbsOther in
    Some (abs6, targets)

  | BPF_EXIT -> Some (abs, targets)

(* --- Whole-programme check --- *)
let rec check_program_loop (abs: abs_state) (prog: list bpf_insn) (pc: int) (targets: target_map)
  : Tot bool (decreases prog) =
  match prog with
  | [] -> true
  | insn :: rest ->
    match check_insn_sb abs insn pc targets with
    | None -> false
    | Some (abs', targets') -> check_program_loop abs' rest (pc + 1) targets'

(* --- Backward branch (loop) support ---
   Pre-populate the target map with widened states at loop heads.
   r0-r5 become AbsOther (caller-saved), r6-r9 and r10 preserved. *)

let branch_offset_sb (insn: bpf_insn) : option int =
  match insn with
  | BPF_JMP64_IMM _ _ _ off -> Some off
  | BPF_JMP64_REG _ _ _ off -> Some off
  | BPF_JMP32_IMM _ _ _ off -> Some off
  | BPF_JMP32_REG _ _ _ off -> Some off
  | BPF_JMP_JA off -> Some off
  | _ -> None

let widen_sb (abs: abs_state) : abs_state =
  let abs = abs_set abs 0 AbsOther in
  let abs = abs_set abs 1 AbsOther in
  let abs = abs_set abs 2 AbsOther in
  let abs = abs_set abs 3 AbsOther in
  let abs = abs_set abs 4 AbsOther in
  let abs = abs_set abs 5 AbsOther in
  abs

let rec init_loop_targets_sb (prog: list bpf_insn) (pc: int) (targets: target_map)
  : Tot target_map (decreases prog) =
  match prog with
  | [] -> targets
  | insn :: rest ->
    let targets = match branch_offset_sb insn with
      | Some off ->
        let target_pc = pc + 1 + off in
        if target_pc <= pc
        then add_target targets target_pc (widen_sb abs_init)
        else targets
      | None -> targets
    in
    init_loop_targets_sb rest (pc + 1) targets

let stack_bounds_check (prog: bpf_program) : bool =
  let targets = init_loop_targets_sb prog 0 empty_targets in
  check_program_loop abs_init prog 0 targets
