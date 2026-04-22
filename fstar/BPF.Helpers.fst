(* BPF.Helpers -- declarative specifications for BPF helper functions.

   Each helper is described by a helper_spec: which registers it reads,
   what it returns in r0, and what side effects it has. The semantics
   engine and safety checkers dispatch through this spec generically,
   so adding a new helper only requires a new constructor in helper_id
   and a new entry in get_helper_spec.

   F* notes for BPF developers:
   - `noeq` means the record type doesn't need decidable equality
   - `option helper_spec` is either Some spec (known helper) or None (unknown)
   - The registry is a total function -- it always returns a value for any helper_id *)
module BPF.Helpers

open FStar.UInt64
open BPF.State
open BPF.Semantics

(* What kind of value the helper returns in r0.
   This determines how the safety checkers treat the return value:
   - RetScalar: ordinary integer, no pointer safety concerns
   - RetMapPtr: could be a valid map pointer or null, must null-check
   - RetErrorCode: integer error code (0 = success), no pointer concerns *)
type helper_ret =
  | RetScalar
  | RetMapPtr
  | RetErrorCode

(* What side effects the helper has beyond setting r0.
   - NoEffect: pure computation, no state changes
   - WriteMapValue: modifies map contents (map_update_elem, map_delete_elem)
   - ReadIntoPtr: writes data through a pointer argument (bpf_probe_read) *)
type helper_effect =
  | NoEffect
  | WriteMapValue
  | ReadIntoPtr

(* Complete specification of a BPF helper function.
   This is the single source of truth for how a helper behaves --
   the semantics engine and all safety checkers read from this. *)
noeq
type helper_spec = {
  args_used: list reg_idx;
  ret_type: helper_ret;
  side_effect: helper_effect;
}

(* Look up the specification for a helper function.
   Returns None for UNKNOWN_HELPER -- the semantics will treat
   unknown helpers as undefined behaviour (programme rejected). *)
let get_helper_spec (hid: helper_id) : option helper_spec =
  match hid with
  | MAP_LOOKUP_ELEM ->
    Some { args_used = [r1; r2]; ret_type = RetMapPtr; side_effect = NoEffect }
  | MAP_UPDATE_ELEM ->
    Some { args_used = [r1; r2; r3; r4]; ret_type = RetErrorCode; side_effect = WriteMapValue }
  | MAP_DELETE_ELEM ->
    Some { args_used = [r1; r2]; ret_type = RetErrorCode; side_effect = WriteMapValue }
  | PROBE_READ ->
    Some { args_used = [r1; r2; r3]; ret_type = RetErrorCode; side_effect = ReadIntoPtr }
  | KTIME_GET_NS ->
    Some { args_used = []; ret_type = RetScalar; side_effect = NoEffect }
  | GET_PRANDOM_U32 ->
    Some { args_used = []; ret_type = RetScalar; side_effect = NoEffect }
  | UNKNOWN_HELPER _ -> None

(* Execute a BPF helper call given its specification.
   Dispatches on ret_type to determine what goes in r0:
   - RetMapPtr: allocates a fresh map value ID and returns MapValuePtr
   - RetScalar/RetErrorCode: returns Scalar 0uL as a placeholder
     (the forall in program_satisfies covers all possible return values)

   Note: we only set r0 and advance pc. We do NOT clobber r1-r5 here
   because the original exec_insn didn't -- the safety checkers handle
   caller-saved clobbering in their abstract state independently. *)
let exec_helper (st: bpf_state) (spec: helper_spec) : option bpf_state =
  match spec.ret_type with
  | RetMapPtr ->
    let id = st.next_map_id in
    Some { st with
      regs = set_reg st.regs r0 (MapValuePtr id);
      pc = st.pc + 1;
      next_map_id = id + 1 }
  | RetScalar ->
    Some { st with
      regs = set_reg st.regs r0 (Scalar 0uL);
      pc = st.pc + 1 }
  | RetErrorCode ->
    Some { st with
      regs = set_reg st.regs r0 (Scalar 0uL);
      pc = st.pc + 1 }

(* Execute a helper with null safety evidence.
   When null_safe is true and the helper returns RetMapPtr,
   populate map_values with a deterministic value so subsequent
   map_value_read calls succeed without symbolic option terms.
   This enables full delta normalisation for map programmes.

   Takes a bool rather than safety_evidence to avoid a circular
   dependency -- BPF.Exec.Safe imports us, so we can't import it. *)
let exec_helper_safe (st: bpf_state) (spec: helper_spec) (null_safe: bool) : option bpf_state =
  match spec.ret_type with
  | RetMapPtr ->
    let id = st.next_map_id in
    if null_safe
    then
      Some { st with
        regs = set_reg st.regs r0 (MapValuePtr id);
        map_values = (id, 0uL) :: st.map_values;
        pc = st.pc + 1;
        next_map_id = id + 1 }
    else
      Some { st with
        regs = set_reg st.regs r0 (MapValuePtr id);
        pc = st.pc + 1;
        next_map_id = id + 1 }
  | RetScalar ->
    Some { st with
      regs = set_reg st.regs r0 (Scalar 0uL);
      pc = st.pc + 1 }
  | RetErrorCode ->
    Some { st with
      regs = set_reg st.regs r0 (Scalar 0uL);
      pc = st.pc + 1 }
