(* BPF.Check.TypeSafety -- static type safety checker via abstract interpretation.

   This is another safety layer in our CertiKOS-style layered verification.
   It performs a forward abstract interpretation over a BPF programme, tracking
   the abstract type of each register (scalar, frame pointer, map pointer,
   null, or unknown) and checking that each instruction receives operands of
   the correct type.

   The rules mirror the kernel's BPF verifier type system:
   - ALU ops (except MOV) require scalar operands
   - Memory loads must go through a pointer (FramePtr or MapValuePtr), never
     through a Scalar or Null
   - Memory stores must go through a FramePtr (stack-only stores in our model)
   - FramePtr arithmetic is restricted to ADD/SUB with immediates, which
     preserves the pointer type
   - MOV copies any type without restriction

   The abstract domain:
     TScalar    -- plain integer value (arithmetic result, immediate, etc.)
     TFramePtr  -- stack frame pointer (derived from r10)
     TMapPtr    -- pointer to a map value (from bpf_map_lookup_elem)
     TNull      -- null pointer
     TUnknown   -- unknown type (conservative top element)

   This analysis complements BPF.Check.StackBounds: StackBounds checks that
   frame pointer offsets fall within the 512-byte stack; this module checks
   that the right types of values are used in the right places.

   Limitations:
   - Straight-line analysis only. Branches pass the abstract state through
     unchanged; we don't merge abstract states at join points.
   - After a helper call, r0-r5 are conservatively set to TUnknown since
     we don't model individual helper return types beyond map_lookup_elem.

   F* notes for BPF developers:
   - `option abs_state_ts` is either `Some new_state` (check passed) or
     `None` (type error detected).
   - `Tot` annotation means the function always terminates -- F* proves this.
   - `decreases prog` tells F* that the recursive function terminates because
     the list gets shorter on each call.
*)
module BPF.Check.TypeSafety

open FStar.Mul
open FStar.Int32
open BPF.State
open BPF.Helpers
open BPF.Semantics

(* --- Abstract type domain ---
   Each register is assigned one of these abstract types. This mirrors the
   concrete reg_val constructors in BPF.State, but we don't track actual
   values -- only the "shape" of what a register holds.

   TUnknown is the conservative top element: it could be anything. We use
   it for registers whose type we've lost track of (e.g. after a helper
   call). Most predicates treat TUnknown permissively to avoid false
   positives -- if we don't know the type, we let other layers catch
   concrete errors. *)
type abs_type =
  | TScalar    (* plain integer value *)
  | TFramePtr  (* stack frame pointer *)
  | TMapPtr    (* map value pointer *)
  | TNull      (* null pointer *)
  | TUnknown   (* unknown type -- conservative *)

(* Abstract state is a function from register index to abstract type.
   Same representation as abs_state in BPF.Check.StackBounds -- a function
   lets F*'s normaliser reduce lookups via beta-reduction. *)
type abs_state_ts = reg_idx -> abs_type

(* Look up the abstract type of a register. *)
let ts_get (abs: abs_state_ts) (r: reg_idx) : abs_type = abs r

(* Update one register's abstract type, leaving others unchanged.
   Returns a new function that maps r to t and everything else to
   its previous value. *)
let ts_set (abs: abs_state_ts) (r: reg_idx) (t: abs_type) : abs_state_ts =
  fun i -> if i = r then t else abs i

(* Initial abstract state at programme entry.
   r10 is the frame pointer. All other registers start as TUnknown --
   the programme hasn't computed anything yet, so we can't say what
   type they hold. *)
let ts_init : abs_state_ts =
  fun r -> if r = r10 then TFramePtr else TUnknown

(* --- Helper predicates ---
   These encode the type constraints for different instruction classes.
   They return true if the given abstract type is acceptable in that
   position, false if using that type would be a type error. *)

(* Can this type be used as an ALU operand (for ops other than MOV)?
   Scalars are the normal case. TUnknown is allowed because we don't
   want to reject programmes where we merely lost track of the type. *)
let is_scalar_type (t: abs_type) : bool =
  match t with | TScalar -> true | TUnknown -> true | _ -> false

(* Can this type be used as a base register for a memory load?
   Loads through FramePtr access the stack; loads through MapPtr access
   map values. TUnknown is allowed conservatively. Scalar and Null are
   never valid load bases -- dereferencing them is UB. *)
let is_load_base (t: abs_type) : bool =
  match t with | TFramePtr -> true | TMapPtr -> true | TUnknown -> true | _ -> false

(* Can this type be used as a base register for a memory store?
   In our model, only stack stores (through FramePtr) are supported.
   Map value stores aren't modelled yet. TUnknown is allowed
   conservatively. *)
let is_store_base (t: abs_type) : bool =
  match t with | TFramePtr -> true | TUnknown -> true | _ -> false

(* --- Per-instruction abstract transfer function ---
   Given the current abstract type state and one instruction, compute the
   new abstract state. Returns None if we can prove the instruction would
   receive operands of the wrong type.

   The transfer function tracks types through:
   - MOV reg-to-reg: copies the abstract type from src to dst
   - ADD/SUB immediate on a pointer: preserves the pointer type
   - All other ALU ops: require scalar operands, produce TScalar
   - Memory ops: check base register type, loaded values become TScalar
   - Helper calls: clobber caller-saved registers to TUnknown *)
let check_insn_ts (abs: abs_state_ts) (insn: bpf_insn) : option abs_state_ts =
  match insn with

  (* --- 64-bit ALU, register operands --- *)
  | BPF_ALU64_REG op dst src ->
    (match op with
     (* MOV copies the type from src to dst -- any type is allowed *)
     | MOV -> Some (ts_set abs dst (ts_get abs src))
     (* All other reg-reg ALU ops require scalar operands on both sides *)
     | _ ->
       if is_scalar_type (ts_get abs dst) && is_scalar_type (ts_get abs src)
       then Some (ts_set abs dst TScalar)
       else None)

  (* --- 64-bit ALU, immediate operand --- *)
  | BPF_ALU64_IMM op dst imm ->
    (match op with
     (* MOV immediate always produces a scalar *)
     | MOV -> Some (ts_set abs dst TScalar)
     (* ADD immediate: frame pointer arithmetic preserves TFramePtr,
        scalar arithmetic produces TScalar, unknown stays unknown *)
     | ADD ->
       (match ts_get abs dst with
        | TFramePtr -> Some (ts_set abs dst TFramePtr)
        | TScalar   -> Some (ts_set abs dst TScalar)
        | TUnknown  -> Some (ts_set abs dst TUnknown)
        | _         -> None)
     (* SUB immediate: same rules as ADD *)
     | SUB ->
       (match ts_get abs dst with
        | TFramePtr -> Some (ts_set abs dst TFramePtr)
        | TScalar   -> Some (ts_set abs dst TScalar)
        | TUnknown  -> Some (ts_set abs dst TUnknown)
        | _         -> None)
     (* All other ALU ops with immediates require a scalar dst *)
     | _ ->
       if is_scalar_type (ts_get abs dst)
       then Some (ts_set abs dst TScalar)
       else None)

  (* --- 32-bit ALU, register operands ---
     32-bit ops truncate to 32 bits and zero-extend, which destroys any
     pointer type. MOV is no exception in 32-bit mode -- the truncation
     makes a pointer invalid, so both operands must be scalar. *)
  | BPF_ALU32_REG op dst src ->
    (match op with
     | MOV ->
       if is_scalar_type (ts_get abs src)
       then Some (ts_set abs dst TScalar)
       else None
     | _ ->
       if is_scalar_type (ts_get abs dst) && is_scalar_type (ts_get abs src)
       then Some (ts_set abs dst TScalar)
       else None)

  (* --- 32-bit ALU, immediate operand --- *)
  | BPF_ALU32_IMM op dst _ ->
    (match op with
     (* MOV immediate always produces a scalar *)
     | MOV -> Some (ts_set abs dst TScalar)
     (* All other 32-bit ALU ops require scalar dst *)
     | _ ->
       if is_scalar_type (ts_get abs dst)
       then Some (ts_set abs dst TScalar)
       else None)

  (* --- Load 64-bit immediate: always a scalar --- *)
  | BPF_LD_IMM64 dst _ -> Some (ts_set abs dst TScalar)

  (* --- Memory load (LDX): base must be a valid load target ---
     The loaded value could be anything, but we conservatively assign
     TScalar to the destination -- loaded data is treated as a plain
     integer until proven otherwise. *)
  | BPF_LDX _ dst src _ ->
    if is_load_base (ts_get abs src)
    then Some (ts_set abs dst TScalar)
    else None

  (* --- Memory store from register (STX): base must be a valid store target,
     and the value being stored must be a scalar --- *)
  | BPF_STX _ dst src _ ->
    if is_store_base (ts_get abs dst) && is_scalar_type (ts_get abs src)
    then Some abs
    else None

  (* --- Memory store immediate (ST): base must be a valid store target ---
     The immediate value is always a scalar, so no src type check needed. *)
  | BPF_ST _ dst _ _ ->
    if is_store_base (ts_get abs dst)
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

  (* --- BPF_CALL: dispatch on helper ret_type for r0's abstract type ---
     RetMapPtr -> TUnknown (could be map pointer or null)
     RetScalar/RetErrorCode -> TScalar (plain integer)
     Unknown helpers -> TUnknown (conservative)
     r1-r5 are caller-saved and clobbered. r6-r9 preserved. *)
  | BPF_CALL hid ->
    let r0_type = (match get_helper_spec hid with
      | Some spec ->
        (match spec.ret_type with
         | RetMapPtr -> TUnknown
         | RetScalar -> TScalar
         | RetErrorCode -> TScalar)
      | None -> TUnknown) in
    let abs1 = ts_set abs 0 r0_type in
    let abs2 = ts_set abs1 1 TUnknown in
    let abs3 = ts_set abs2 2 TUnknown in
    let abs4 = ts_set abs3 3 TUnknown in
    let abs5 = ts_set abs4 4 TUnknown in
    let abs6 = ts_set abs5 5 TUnknown in
    Some abs6

  (* --- EXIT: pass through ---
     Programme is done; nothing to check for types. *)
  | BPF_EXIT -> Some abs

(* --- Whole-programme check ---
   Walk the instruction list front-to-back, threading the abstract state
   through each instruction. If any instruction fails (returns None),
   the whole programme fails.

   This is a simple linear scan -- O(n) in programme length. The
   `decreases prog` annotation proves termination: the list shrinks
   by one element on each recursive call. *)
let rec check_program_ts_loop (abs: abs_state_ts) (prog: list bpf_insn)
  : Tot bool (decreases prog) =
  match prog with
  | [] -> true  (* Reached the end without finding a type error *)
  | insn :: rest ->
    match check_insn_ts abs insn with
    | None -> false   (* Type error detected *)
    | Some abs' -> check_program_ts_loop abs' rest

(* Top-level entry point: check a complete BPF programme for type safety.
   Starts with the initial abstract state (r10 = TFramePtr, all others
   TUnknown) and walks every instruction. Returns true if all type
   constraints are satisfied, false if any instruction would receive
   operands of the wrong type. *)
let type_check (prog: bpf_program) : bool =
  check_program_ts_loop ts_init prog
