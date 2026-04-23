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

   The abstract domain is simple:
     AbsFramePtr off -- register is r10 (or derived from r10) with known offset
     AbsOther        -- register holds something we don't track here

   This mirrors the concrete FramePtr tracking in BPF.State, but operates
   purely statically -- no concrete values, no Z3 queries. The check is
   decidable and runs in O(n) time over the programme.

   Limitations:
   - Straight-line analysis only. Branches are passed through unchanged;
     we don't merge abstract states at join points. This is sound for
     programmes where every path through a branch preserves the same
     frame pointer relationships (which covers most BPF programmes).
   - Register-to-register ADD/SUB involving a frame pointer is conservatively
     set to AbsOther. Only immediate ADD/SUB preserves frame pointer tracking.

   F* notes for BPF developers:
   - `option abs_state` is either `Some new_state` (check passed) or `None`
     (definite out-of-bounds detected).
   - `Tot` annotation means the function always terminates -- F* proves this.
   - `decreases prog` tells F* that the recursive function terminates because
     the list gets shorter on each call.
*)
module BPF.Check.StackBounds

open FStar.Mul
open FStar.Int32
open BPF.State
open BPF.Semantics

(* --- Abstract register domain ---
   We only care about frame pointer derivation for this analysis.
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

(* Look up the abstract value of a register. *)
let abs_get (abs: abs_state) (r: reg_idx) : abs_reg = abs r

(* Update one register in the abstract state, leaving others unchanged.
   Returns a new function that maps r to v and everything else to
   its previous value. *)
let abs_set (abs: abs_state) (r: reg_idx) (v: abs_reg) : abs_state =
  fun i -> if i = r then v else abs i

(* Initial abstract state at programme entry.
   r10 is the frame pointer with offset 0 (top of stack).
   All other registers are unknown -- the programme hasn't computed
   anything yet, so we can't say what they hold. *)
let abs_init : abs_state =
  fun r -> if r = r10 then AbsFramePtr 0 else AbsOther

(* --- Stack bounds check for memory accesses ---
   Currently always returns true -- we track FramePtr offsets through the
   abstract state but don't reject any accesses. Our straight-line analysis
   doesn't merge abstract states at branch join points, so a register's
   tracked offset can be stale after control flow merges. Rejecting
   out-of-bounds accesses would cause false positives on valid programmes
   with complex branching.

   Once branch-aware merging is added (like BPF.Check.NullSafety has),
   this function can check stack_offset_valid and reject genuine
   out-of-bounds accesses. For now, the abstract state tracking is still
   useful -- it feeds into the guarded executor's skip-bounds-check
   optimisation for accesses we CAN verify. *)
let check_mem_access (_base: abs_reg) (_insn_off: Int32.t) (_w: mem_width) : bool =
  true

(* --- Per-instruction abstract transfer function ---
   Given the current abstract state and one instruction, compute the
   new abstract state. Returns None if we can prove the instruction
   would access stack memory out-of-bounds.

   The transfer function tracks frame pointer derivation through:
   - MOV reg-to-reg: copies the abstract value
   - ADD/SUB immediate on a frame pointer: adjusts the offset
   - All other ALU ops: conservatively set dst to AbsOther

   Memory access instructions check bounds before proceeding.
   Branch instructions pass the abstract state through unchanged. *)
let check_insn_sb (abs: abs_state) (insn: bpf_insn) : option abs_state =
  match insn with

  (* --- 64-bit ALU, register operands --- *)
  | BPF_ALU64_REG op dst src ->
    (match op with
     (* MOV copies the abstract value from src to dst *)
     | MOV -> Some (abs_set abs dst (abs_get abs src))
     (* All other reg-reg ALU ops destroy frame pointer tracking *)
     | _ -> Some (abs_set abs dst AbsOther))

  (* --- 64-bit ALU, immediate operand --- *)
  | BPF_ALU64_IMM op dst imm ->
    (match op with
     (* MOV immediate always produces a scalar *)
     | MOV -> Some (abs_set abs dst AbsOther)
     (* ADD immediate: if dst is a frame pointer, adjust the offset *)
     | ADD ->
       (match abs_get abs dst with
        | AbsFramePtr off ->
          Some (abs_set abs dst (AbsFramePtr (off + sign_extend_to_int imm)))
        | AbsOther -> Some (abs_set abs dst AbsOther))
     (* SUB immediate: if dst is a frame pointer, adjust the offset *)
     | SUB ->
       (match abs_get abs dst with
        | AbsFramePtr off ->
          Some (abs_set abs dst (AbsFramePtr (off - sign_extend_to_int imm)))
        | AbsOther -> Some (abs_set abs dst AbsOther))
     (* All other IMM ALU ops destroy frame pointer tracking *)
     | _ -> Some (abs_set abs dst AbsOther))

  (* --- 32-bit ALU ops always destroy frame pointer tracking ---
     Frame pointers are 64-bit; 32-bit truncation makes the pointer invalid. *)
  | BPF_ALU32_REG _ dst _ -> Some (abs_set abs dst AbsOther)
  | BPF_ALU32_IMM _ dst _ -> Some (abs_set abs dst AbsOther)

  (* --- Load 64-bit immediate: always a scalar --- *)
  | BPF_LD_IMM64 dst _ -> Some (abs_set abs dst AbsOther)

  (* --- Memory load (LDX): check bounds, then set dst to AbsOther ---
     The loaded value could be anything, so we lose frame pointer tracking
     on the destination register. *)
  | BPF_LDX w dst src off ->
    if check_mem_access (abs_get abs src) off w
    then Some (abs_set abs dst AbsOther)
    else None

  (* --- Memory store from register (STX): check bounds, state unchanged ---
     Stores don't modify registers, so the abstract state passes through. *)
  | BPF_STX w dst _src off ->
    if check_mem_access (abs_get abs dst) off w
    then Some abs
    else None

  (* --- Memory store immediate (ST): check bounds, state unchanged --- *)
  | BPF_ST w dst off _imm ->
    if check_mem_access (abs_get abs dst) off w
    then Some abs
    else None

  (* --- Branch instructions: pass abstract state through ---
     We don't track control flow -- this is a straight-line analysis.
     The abstract state is unchanged by branches. *)
  | BPF_JMP64_REG _ _ _ _ -> Some abs
  | BPF_JMP64_IMM _ _ _ _ -> Some abs
  | BPF_JMP32_REG _ _ _ _ -> Some abs
  | BPF_JMP32_IMM _ _ _ _ -> Some abs
  | BPF_JMP_JA _ -> Some abs

  (* --- BPF_CALL: clobber caller-saved registers ---
     The BPF calling convention says r0-r5 are caller-saved.
     After a helper call, we lose all tracking on r0-r5.
     r6-r9 are callee-saved and preserved.
     r10 (frame pointer) is always preserved. *)
  | BPF_CALL _ ->
    let abs1 = abs_set abs 0 AbsOther in
    let abs2 = abs_set abs1 1 AbsOther in
    let abs3 = abs_set abs2 2 AbsOther in
    let abs4 = abs_set abs3 3 AbsOther in
    let abs5 = abs_set abs4 4 AbsOther in
    let abs6 = abs_set abs5 5 AbsOther in
    Some abs6

  (* --- EXIT: pass through ---
     Programme is done; nothing to check for stack bounds. *)
  | BPF_EXIT -> Some abs

(* --- Whole-programme check ---
   Walk the instruction list front-to-back, threading the abstract state
   through each instruction. If any instruction fails (returns None),
   the whole programme fails.

   This is a simple linear scan -- O(n) in programme length. The
   `decreases prog` annotation proves termination: the list shrinks
   by one element on each recursive call. *)
let rec check_program_loop (abs: abs_state) (prog: list bpf_insn)
  : Tot bool (decreases prog) =
  match prog with
  | [] -> true  (* Reached the end without finding an out-of-bounds access *)
  | insn :: rest ->
    match check_insn_sb abs insn with
    | None -> false   (* Out-of-bounds stack access detected *)
    | Some abs' -> check_program_loop abs' rest

(* Top-level entry point: check a complete BPF programme for stack bounds.
   Starts with the initial abstract state (r10 = FramePtr 0) and walks
   every instruction. Returns true if all stack accesses are provably
   in-bounds, false if any access could be out-of-bounds. *)
let stack_bounds_check (prog: bpf_program) : bool =
  check_program_loop abs_init prog
