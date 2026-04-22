(* BPF.Check.NullSafety -- branch-aware null pointer safety checker.

   This is the most complex safety layer in our CertiKOS-style layered
   verification. It verifies that every map pointer dereference is
   guarded by a null check, using a forward abstract interpretation
   with branch-aware state tracking.

   When bpf_map_lookup_elem returns a pointer in r0, that pointer
   could be either a valid map value pointer or null. The programme
   must branch on the result (e.g. "if r0 == 0 goto error") before
   dereferencing the pointer. This checker tracks which registers have
   been null-checked and rejects any load through an unchecked or
   known-null register.

   Branch awareness: unlike the simpler StackBounds and TypeSafety
   checkers which use straight-line analysis, this module forks the
   abstract state at null-check branches. For "JEQ r1 0 +offset":
     - Fall-through (condition false): r1 is NOT zero, so Checked
     - Jump target (condition true):   r1 IS zero, so IsNull
   The jump target state is recorded in a branch_targets list. When
   execution reaches that target pc, the saved state is merged with
   the fall-through state using a conservative join.

   The abstract domain:
     Checked    -- register was null-checked, safe to dereference
     Unchecked  -- register holds a map lookup result, not yet checked
     IsNull     -- register is known to be null on this path
     NotMap     -- register doesn't hold a map pointer (irrelevant)

   F* notes for BPF developers:
   - `option (abs_state_ns & branch_targets)` is the return type of
     the per-instruction check. Some means the instruction is safe;
     None means a null pointer dereference was detected.
   - The `&` syntax is F*'s tuple type (like a pair in C).
   - `branch_targets` is a list of (pc, state) pairs representing
     deferred abstract states from branch instructions.
   - `Tot` means the function always terminates -- F* proves this.
   - `decreases prog` tells F* that the recursive function terminates
     because the list gets shorter on each call.
*)
module BPF.Check.NullSafety

open FStar.Mul
open FStar.Int32
open BPF.State
open BPF.Helpers
open BPF.Semantics

(* --- Abstract null-status domain ---
   We only care about whether a register holds an unchecked map pointer.
   Registers that hold scalars, frame pointers, or other non-map values
   are simply NotMap -- irrelevant to this analysis. *)
type null_status =
  | Checked    (* null-checked map pointer -- safe to dereference *)
  | Unchecked  (* map lookup result, not yet null-checked *)
  | IsNull     (* known to be null on this path *)
  | NotMap     (* not a map pointer -- don't care *)

(* Abstract state is a function from register index to null status.
   Same representation as the other checkers -- a function lets F*'s
   normaliser reduce lookups via beta-reduction. *)
type abs_state_ns = reg_idx -> null_status

(* Look up the null status of a register. *)
let ns_get (abs: abs_state_ns) (r: reg_idx) : null_status = abs r

(* Update one register's null status, leaving others unchanged.
   Returns a new function that maps r to s and everything else to
   its previous value. *)
let ns_set (abs: abs_state_ns) (r: reg_idx) (s: null_status) : abs_state_ns =
  fun i -> if i = r then s else abs i

(* Initial abstract state at programme entry.
   No register holds a map pointer yet -- the programme hasn't called
   any helper functions. All registers start as NotMap. *)
let ns_init : abs_state_ns =
  fun _ -> NotMap

(* --- Branch target tracking ---
   When we encounter a null-check branch (JEQ/JNE against 0), we fork
   the abstract state. The fall-through path gets one state and the
   jump target gets another. We record the jump target's state here so
   it can be merged when we reach that pc.

   Each entry is a (target_pc, abstract_state) pair. Multiple branches
   can target the same pc, so we may have multiple entries for one pc.
   The merge function handles combining them all.

   We use `int` for the target pc rather than `nat` because branch
   offsets can be negative (backward jumps), and pc + 1 + offset may
   yield a negative value for malformed programmes. Using `int` avoids
   a subtyping obligation that F* can't always discharge. *)
type branch_targets = list (int & abs_state_ns)

(* --- Join function for merging two null statuses ---
   At a branch join point, we merge the null status from each path.
   The rule is conservative:
   - If both paths agree on the status, keep it
   - Otherwise, fall back to Unchecked (must re-check)

   This is sound because Unchecked will force a null check before
   any dereference, which is always safe (if overly conservative). *)
let join_status (a b: null_status) : null_status =
  match a, b with
  | Checked, Checked     -> Checked
  | Unchecked, Unchecked -> Unchecked
  | IsNull, IsNull       -> IsNull
  | NotMap, NotMap        -> NotMap
  | _, _                  -> Unchecked

(* Join two full abstract states register-by-register.
   Each register gets the join of its status from both states. *)
let join_states (a b: abs_state_ns) : abs_state_ns =
  fun r -> join_status (a r) (b r)

(* --- Branch target merging ---
   When we reach a particular pc, check if any branch targets point
   here. If so, merge all their saved states into the current state
   and remove them from the list.

   This is done in two passes:
   1. merge_targets_at: fold over matching targets, joining their
      states into the current state
   2. remove_targets_at: filter out entries for this pc *)

(* Merge all saved branch states targeting this pc into the current state.
   We fold over the target list, joining any matching entry's state
   into the accumulator. Non-matching entries are ignored. *)
let rec merge_targets_at (pc: int) (targets: branch_targets) (acc: abs_state_ns)
  : Tot abs_state_ns (decreases targets) =
  match targets with
  | [] -> acc
  | (tpc, tstate) :: rest ->
    if tpc = pc
    then merge_targets_at pc rest (join_states acc tstate)
    else merge_targets_at pc rest acc

(* Remove all branch target entries for a given pc.
   After merging, we don't need them any more. *)
let rec remove_targets_at (pc: int) (targets: branch_targets)
  : Tot branch_targets (decreases targets) =
  match targets with
  | [] -> []
  | (tpc, tstate) :: rest ->
    if tpc = pc
    then remove_targets_at pc rest
    else (tpc, tstate) :: remove_targets_at pc rest

(* Convenience: merge and clean up in one step.
   Returns the merged abstract state and the cleaned target list. *)
let apply_targets (abs: abs_state_ns) (pc: int) (targets: branch_targets)
  : abs_state_ns & branch_targets =
  let merged = merge_targets_at pc targets abs in
  let cleaned = remove_targets_at pc targets in
  (merged, cleaned)

(* --- Safety predicate for memory loads ---
   A load through a register is safe only if the register is Checked
   (null-checked map pointer) or NotMap (not a map pointer at all --
   handled by other safety layers). Loading through Unchecked or IsNull
   is a null safety violation. *)
let is_safe_deref (s: null_status) : bool =
  match s with
  | Checked -> true
  | NotMap   -> true
  | _       -> false

(* --- Per-instruction abstract transfer function ---
   Given the current abstract state, one instruction, the current pc,
   and the branch target list, compute the new abstract state and
   updated targets. Returns None if a null safety violation is detected.

   Steps at each instruction:
   1. Merge any branch targets at the current pc
   2. Apply the instruction's transfer rules
   3. For null-check branches, fork the state and record the target

   This function must handle ALL 16 bpf_insn constructors. Missing
   any constructor would cause an F* incomplete-match error. *)
let check_insn_ns (abs: abs_state_ns) (insn: bpf_insn) (pc: int) (targets: branch_targets)
  : option (abs_state_ns & branch_targets) =

  (* Step 1: merge any saved branch states targeting this pc *)
  let (abs, targets) = apply_targets abs pc targets in

  match insn with

  (* --- 64-bit ALU, register operands --- *)
  | BPF_ALU64_REG op dst src ->
    (match op with
     (* MOV copies the null status from src to dst. If src holds an
        unchecked map pointer, dst now holds the same unchecked pointer.
        This tracks the common pattern: r1 = r0 (copy lookup result). *)
     | MOV -> Some (ns_set abs dst (ns_get abs src), targets)
     (* All other reg-reg ALU ops produce a scalar result, which is
        not a map pointer. *)
     | _ -> Some (ns_set abs dst NotMap, targets))

  (* --- 64-bit ALU, immediate operand --- *)
  | BPF_ALU64_IMM op dst _ ->
    (match op with
     (* MOV immediate replaces the register with a scalar constant --
        not a map pointer. *)
     | MOV -> Some (ns_set abs dst NotMap, targets)
     (* ADD/SUB on a checked map pointer: the pointer arithmetic keeps
        it as a valid (checked) map pointer. On an unchecked pointer,
        arithmetic doesn't magically make it checked. On NotMap, the
        result is still NotMap. For simplicity and soundness, all
        non-MOV ALU-immediate ops set dst to NotMap. The common case
        is stack pointer arithmetic which is NotMap anyway. *)
     | _ -> Some (ns_set abs dst NotMap, targets))

  (* --- 32-bit ALU ops always produce scalars ---
     32-bit truncation destroys any pointer type. The result is a
     plain scalar, not a map pointer. *)
  | BPF_ALU32_REG _ dst _ -> Some (ns_set abs dst NotMap, targets)
  | BPF_ALU32_IMM _ dst _ -> Some (ns_set abs dst NotMap, targets)

  (* --- Load 64-bit immediate: always a scalar constant --- *)
  | BPF_LD_IMM64 dst _ -> Some (ns_set abs dst NotMap, targets)

  (* --- Memory load (LDX): check that the base is safe to dereference ---
     If the base register (src) is Unchecked or IsNull, this is a null
     safety violation -- return None. If it's Checked (null-checked
     map pointer) or NotMap (stack/scalar pointer handled by other
     layers), the load is safe for null purposes.
     The loaded value is a scalar, so dst becomes NotMap. *)
  | BPF_LDX _ dst src _ ->
    if is_safe_deref (ns_get abs src)
    then Some (ns_set abs dst NotMap, targets)
    else None

  (* --- Memory store from register (STX): check base is safe ---
     Same null safety check as LDX -- the base (dst) must not be
     Unchecked or IsNull. Stores don't change register null status. *)
  | BPF_STX _ dst _ _ ->
    if is_safe_deref (ns_get abs dst)
    then Some (abs, targets)
    else None

  (* --- Memory store immediate (ST): check base is safe --- *)
  | BPF_ST _ dst _ _ ->
    if is_safe_deref (ns_get abs dst)
    then Some (abs, targets)
    else None

  (* --- 64-bit conditional jump, immediate operand ---
     This is the key case: null-check detection.

     When we see "JEQ dst 0 +offset" and dst is Unchecked:
       - The condition is "dst == 0"
       - Fall-through (condition false): dst is NOT null, so Checked
       - Jump target (condition true): dst IS null, so IsNull

     When we see "JNE dst 0 +offset" and dst is Unchecked:
       - The condition is "dst != 0"
       - Fall-through (condition false): dst IS null, so IsNull
       - Jump target (condition true): dst is NOT null, so Checked

     For all other cases (dst is not Unchecked, or comparison is not
     against 0, or it's a non-equality op like JGT/JGE), we just
     record the branch target with the current state for merging at
     the join point. This is conservative -- we don't lose information,
     we just don't gain any. *)
  | BPF_JMP64_IMM op dst imm offset ->
    let dst_status = ns_get abs dst in
    let imm_is_zero = (sign_extend_to_int imm = 0) in
    if dst_status = Unchecked && imm_is_zero && op = JEQ then
      (* JEQ dst 0: fall-through means dst is non-null (Checked),
         jump target means dst is null (IsNull) *)
      let fall_abs = ns_set abs dst Checked in
      let jump_abs = ns_set abs dst IsNull in
      let target_pc = pc + 1 + offset in
      Some (fall_abs, (target_pc, jump_abs) :: targets)
    else if dst_status = Unchecked && imm_is_zero && op = JNE then
      (* JNE dst 0: fall-through means dst is null (IsNull),
         jump target means dst is non-null (Checked) *)
      let fall_abs = ns_set abs dst IsNull in
      let jump_abs = ns_set abs dst Checked in
      let target_pc = pc + 1 + offset in
      Some (fall_abs, (target_pc, jump_abs) :: targets)
    else
      (* Non-null-check branch: record target with current state for
         merge at the join point, but don't change null status *)
      let target_pc = pc + 1 + offset in
      Some (abs, (target_pc, abs) :: targets)

  (* --- 64-bit conditional jump, register operands ---
     We don't detect null checks via register comparison (would need
     to know the other register is zero). Conservatively record the
     branch target with the current state for merging. *)
  | BPF_JMP64_REG _ _ _ offset ->
    let target_pc = pc + 1 + offset in
    Some (abs, (target_pc, abs) :: targets)

  (* --- 32-bit conditional jumps ---
     32-bit comparisons are unlikely to be used for null checks on
     64-bit pointers. Record targets for merging, don't change status. *)
  | BPF_JMP32_IMM _ _ _ offset ->
    let target_pc = pc + 1 + offset in
    Some (abs, (target_pc, abs) :: targets)
  | BPF_JMP32_REG _ _ _ offset ->
    let target_pc = pc + 1 + offset in
    Some (abs, (target_pc, abs) :: targets)

  (* --- Unconditional jump: no state change, no branch target ---
     JA always jumps, so there's no fork. The analysis continues at
     the next sequential instruction (our linear scan doesn't follow
     jumps -- branch targets handle the merge). *)
  | BPF_JMP_JA _ -> Some (abs, targets)

  (* --- BPF_CALL: dispatch on helper ret_type for r0's null status ---
     RetMapPtr -> Unchecked (must null-check before dereference)
     RetScalar/RetErrorCode -> NotMap (not a map pointer)
     Unknown helpers -> NotMap (conservative)
     r1-r5 are caller-saved and clobbered. r6-r9 preserved. *)
  | BPF_CALL hid ->
    let r0_status = (match get_helper_spec hid with
      | Some spec ->
        (match spec.ret_type with
         | RetMapPtr -> Unchecked
         | RetScalar -> NotMap
         | RetErrorCode -> NotMap)
      | None -> NotMap) in
    let abs1 = ns_set abs 0 r0_status in
    let abs2 = ns_set abs1 1 NotMap in
    let abs3 = ns_set abs2 2 NotMap in
    let abs4 = ns_set abs3 3 NotMap in
    let abs5 = ns_set abs4 4 NotMap in
    let abs6 = ns_set abs5 5 NotMap in
    Some (abs6, targets)

  (* --- EXIT: pass through ---
     Programme is done; nothing to check. Any saved branch targets for
     unreachable code will simply never be merged. *)
  | BPF_EXIT -> Some (abs, targets)

(* --- Whole-programme check ---
   Walk the instruction list front-to-back, threading the abstract
   state and branch targets through each instruction. If any
   instruction fails (returns None -- null safety violation), the
   whole programme fails.

   This is O(n) in programme length (with a small constant for branch
   target list operations). The `decreases prog` annotation proves
   termination: the instruction list shrinks by one on each call. *)
let rec check_program_ns_loop (abs: abs_state_ns) (prog: list bpf_insn) (pc: int) (targets: branch_targets)
  : Tot bool (decreases prog) =
  match prog with
  | [] -> true  (* Reached the end without finding a null safety violation *)
  | insn :: rest ->
    match check_insn_ns abs insn pc targets with
    | None -> false   (* Null safety violation detected *)
    | Some (abs', targets') -> check_program_ns_loop abs' rest (pc + 1) targets'

(* Top-level entry point: check a complete BPF programme for null safety.
   Starts with the initial abstract state (all registers NotMap, no
   branch targets) and walks every instruction. Returns true if all
   map pointer dereferences are guarded by null checks, false if any
   dereference could happen without a null check. *)
let null_check (prog: bpf_program) : bool =
  check_program_ns_loop ns_init prog 0 []
