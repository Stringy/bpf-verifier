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

(* What kind of value the helper returns in r0.
   This determines how the safety checkers treat the return value:
   - RetScalar: ordinary integer, no pointer safety concerns
   - RetMapPtr: could be a valid map pointer or null, must null-check
   - RetErrorCode: integer error code (0 = success), no pointer concerns *)
type helper_ret =
  | RetScalar
  | RetMapPtr
  | RetRingBufPtr
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
  (* Map operations *)
  | MAP_LOOKUP_ELEM ->
    Some { args_used = [r1; r2]; ret_type = RetMapPtr; side_effect = NoEffect }
  | MAP_UPDATE_ELEM ->
    Some { args_used = [r1; r2; r3; r4]; ret_type = RetErrorCode; side_effect = WriteMapValue }
  | MAP_DELETE_ELEM ->
    Some { args_used = [r1; r2]; ret_type = RetErrorCode; side_effect = WriteMapValue }
  (* Memory read helpers *)
  | PROBE_READ ->
    Some { args_used = [r1; r2; r3]; ret_type = RetErrorCode; side_effect = ReadIntoPtr }
  | PROBE_READ_STR ->
    Some { args_used = [r1; r2; r3]; ret_type = RetErrorCode; side_effect = ReadIntoPtr }
  | PROBE_READ_USER ->
    Some { args_used = [r1; r2; r3]; ret_type = RetErrorCode; side_effect = ReadIntoPtr }
  | PROBE_READ_KERNEL ->
    Some { args_used = [r1; r2; r3]; ret_type = RetErrorCode; side_effect = ReadIntoPtr }
  | PROBE_READ_KERNEL_STR ->
    Some { args_used = [r1; r2; r3]; ret_type = RetErrorCode; side_effect = ReadIntoPtr }
  | D_PATH ->
    Some { args_used = [r1; r2; r3]; ret_type = RetErrorCode; side_effect = ReadIntoPtr }
  | GET_CURRENT_COMM ->
    Some { args_used = [r1; r2]; ret_type = RetErrorCode; side_effect = ReadIntoPtr }
  (* Simple scalar returns *)
  | KTIME_GET_NS ->
    Some { args_used = []; ret_type = RetScalar; side_effect = NoEffect }
  | KTIME_GET_BOOT_NS ->
    Some { args_used = []; ret_type = RetScalar; side_effect = NoEffect }
  | GET_PRANDOM_U32 ->
    Some { args_used = []; ret_type = RetScalar; side_effect = NoEffect }
  | GET_CURRENT_PID_TGID ->
    Some { args_used = []; ret_type = RetScalar; side_effect = NoEffect }
  | GET_CURRENT_UID_GID ->
    Some { args_used = []; ret_type = RetScalar; side_effect = NoEffect }
  | GET_CURRENT_TASK ->
    Some { args_used = []; ret_type = RetScalar; side_effect = NoEffect }
  | GET_CURRENT_TASK_BTF ->
    Some { args_used = []; ret_type = RetScalar; side_effect = NoEffect }
  | TRACE_PRINTK ->
    Some { args_used = [r1; r2]; ret_type = RetErrorCode; side_effect = NoEffect }
  (* Ring buffer operations *)
  | RINGBUF_RESERVE ->
    Some { args_used = [r1; r2; r3]; ret_type = RetRingBufPtr; side_effect = NoEffect }
  | RINGBUF_SUBMIT ->
    Some { args_used = [r1; r2]; ret_type = RetErrorCode; side_effect = NoEffect }
  | RINGBUF_DISCARD ->
    Some { args_used = [r1; r2]; ret_type = RetErrorCode; side_effect = NoEffect }
  | UNKNOWN_HELPER _ -> None

(* Apply side effects before setting the return value.
   ReadIntoPtr helpers (probe_read_kernel, get_current_comm, d_path)
   write data through the r1 pointer. We model this by writing a
   placeholder 0uL at the destination so subsequent reads succeed.
   Without this, stack_read returns None and the programme appears
   to crash at the next load from that address. *)
let apply_helper_effect (st0: bpf_state) (eff: helper_effect) : bpf_state =
  match eff with
  | ReadIntoPtr ->
    (match state_get_reg st0 r1 with
     | FramePtr off -> { st0 with stack = stack_write st0.stack off W64 0uL }
     | _ -> st0)
  | _ -> st0

(* Execute a BPF helper call given its specification.
   First applies side effects (ReadIntoPtr writes through r1),
   then dispatches on ret_type to determine what goes in r0. *)
let exec_helper (st0: bpf_state) (spec: helper_spec) : option bpf_state =
  let st = apply_helper_effect st0 spec.side_effect in
  let origin = if st.pc >= 0 then st.pc else 0 in
  let origins' = fun i -> if i = r0 then origin else st.reg_origins i in
  match spec.ret_type with
  | RetMapPtr ->
    let id = st.next_map_id in
    Some { st with
      regs = set_reg st.regs r0 (MapValuePtr id);
      pc = st.pc + 1;
      next_map_id = id + 1;
      reg_origins = origins' }
  | RetRingBufPtr ->
    let id = st.next_map_id in
    Some { st with
      regs = set_reg st.regs r0 (RingBufPtr id);
      pc = st.pc + 1;
      next_map_id = id + 1;
      reg_origins = origins' }
  | RetScalar ->
    Some { st with
      regs = set_reg st.regs r0 (Scalar 0uL);
      pc = st.pc + 1;
      reg_origins = origins' }
  | RetErrorCode ->
    Some { st with
      regs = set_reg st.regs r0 (Scalar 0uL);
      pc = st.pc + 1;
      reg_origins = origins' }

(* Execute a helper with null safety evidence.
   When null_safe is true and the helper returns RetMapPtr,
   populate map_values with a deterministic value so subsequent
   map_value_read calls succeed without symbolic option terms.
   This enables full delta normalisation for map programmes.

   Takes a bool rather than safety_evidence to avoid a circular
   dependency -- BPF.Exec.Safe imports us, so we can't import it. *)
let exec_helper_safe (st0: bpf_state) (spec: helper_spec) (null_safe: bool) : option bpf_state =
  let st = apply_helper_effect st0 spec.side_effect in
  let origin = if st.pc >= 0 then st.pc else 0 in
  let origins' = fun i -> if i = r0 then origin else st.reg_origins i in
  match spec.ret_type with
  | RetMapPtr ->
    let id = st.next_map_id in
    if null_safe
    then
      Some { st with
        regs = set_reg st.regs r0 (MapValuePtr id);
        map_values = (id, 0uL) :: st.map_values;
        pc = st.pc + 1;
        next_map_id = id + 1;
        reg_origins = origins' }
    else
      Some { st with
        regs = set_reg st.regs r0 (MapValuePtr id);
        pc = st.pc + 1;
        next_map_id = id + 1;
        reg_origins = origins' }
  | RetRingBufPtr ->
    let id = st.next_map_id in
    Some { st with
      regs = set_reg st.regs r0 (RingBufPtr id);
      pc = st.pc + 1;
      next_map_id = id + 1;
      reg_origins = origins' }
  | RetScalar ->
    Some { st with
      regs = set_reg st.regs r0 (Scalar 0uL);
      pc = st.pc + 1;
      reg_origins = origins' }
  | RetErrorCode ->
    Some { st with
      regs = set_reg st.regs r0 (Scalar 0uL);
      pc = st.pc + 1;
      reg_origins = origins' }
