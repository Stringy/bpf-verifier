(* BPF.Exec.Path — deterministic path-based executor.

   The standard executor (`exec_program`) is non-deterministic at helper
   calls that return nullable pointers: map_lookup_elem and ringbuf_reserve
   can return either a valid pointer or null. This creates exponential
   branching during F* normalisation — k nullable helpers means 2^k paths.

   This module provides a deterministic executor parameterised by a
   "path schedule" — a list of choices (NonNull or AsNull) consumed
   left-to-right at each nullable helper call. Each schedule defines
   one specific execution path through the programme.

   The Rust-side abstract interpreter enumerates all feasible schedules,
   and the generated F* code proves the postcondition for each schedule
   independently. Each per-schedule proof is deterministic (no branching),
   so full delta normalisation works efficiently.

   F* notes:
   - The schedule is threaded through the execution as a list that gets
     consumed. This avoids needing mutable state or indices.
   - `path_choice` is a simple two-constructor type, not an option —
     clarity over reuse. *)
module BPF.Exec.Path

open FStar.Mul
open FStar.UInt64
open FStar.UInt32
open FStar.Int32
open FStar.Int.Cast
open BPF.State
open BPF.Helpers
open BPF.Semantics
open BPF.Spec
open BPF.Verify

(* At each nullable helper call, the schedule dictates what happens. *)
type path_choice =
  | NonNull
  | AsNull

type path_schedule = list path_choice

(* Execute a helper with a deterministic choice from the schedule.
   Returns the updated state AND the remaining schedule (tail).
   Non-nullable helpers (RetScalar, RetErrorCode) don't consume
   a choice — the schedule passes through unchanged. *)
let exec_helper_path (st0: bpf_state) (spec: helper_spec) (sched: path_schedule)
  : option bpf_state & path_schedule =
  let st = apply_helper_effect st0 spec.side_effect in
  let origin = if st.pc >= 0 then st.pc else 0 in
  let origins' = fun i -> if i = r0 then origin else st.reg_origins i in
  match spec.ret_type with
  | RetMapPtr ->
    (match sched with
     | NonNull :: rest ->
       let id = st.next_map_id in
       (Some { st with
          regs = set_reg st.regs r0 (MapValuePtr id);
          map_values = (id, 0uL) :: st.map_values;
          pc = st.pc + 1;
          next_map_id = id + 1;
          reg_origins = origins' }, rest)
     | AsNull :: rest ->
       (Some { st with
          regs = set_reg st.regs r0 Null;
          pc = st.pc + 1;
          reg_origins = origins' }, rest)
     | [] ->
       let id = st.next_map_id in
       (Some { st with
          regs = set_reg st.regs r0 (MapValuePtr id);
          map_values = (id, 0uL) :: st.map_values;
          pc = st.pc + 1;
          next_map_id = id + 1;
          reg_origins = origins' }, []))
  | RetRingBufPtr ->
    (match sched with
     | NonNull :: rest ->
       let id = st.next_map_id in
       (Some { st with
          regs = set_reg st.regs r0 (RingBufPtr id);
          pc = st.pc + 1;
          next_map_id = id + 1;
          reg_origins = origins' }, rest)
     | AsNull :: rest ->
       (Some { st with
          regs = set_reg st.regs r0 Null;
          pc = st.pc + 1;
          reg_origins = origins' }, rest)
     | [] ->
       let id = st.next_map_id in
       (Some { st with
          regs = set_reg st.regs r0 (RingBufPtr id);
          pc = st.pc + 1;
          next_map_id = id + 1;
          reg_origins = origins' }, []))
  | RetScalar ->
    (Some { st with
       regs = set_reg st.regs r0 (Scalar 0uL);
       pc = st.pc + 1;
       reg_origins = origins' }, sched)
  | RetErrorCode ->
    (Some { st with
       regs = set_reg st.regs r0 (Scalar 0uL);
       pc = st.pc + 1;
       reg_origins = origins' }, sched)

(* Execute one instruction, threading the path schedule through
   helper calls. Non-call instructions behave identically to
   BPF.Semantics.exec_insn. *)
let exec_insn_path (st: bpf_state) (insn: bpf_insn) (sched: path_schedule)
  : option bpf_state & path_schedule =
  match insn with
  | BPF_CALL hid ->
    (match get_helper_spec hid with
     | Some spec -> exec_helper_path st spec sched
     | None -> (None, sched))
  | _ ->
    (exec_insn st insn, sched)

(* Execute a full programme with a path schedule.
   Same structure as exec_program but threads the schedule through
   each instruction via exec_insn_path. *)
let rec exec_program_path (st: bpf_state) (prog: bpf_program) (fuel: nat) (sched: path_schedule)
  : Tot (option bpf_state) (decreases fuel) =
  if fuel = 0 then None
  else
    let tail = list_drop prog (if st.pc >= 0 then st.pc else 0) in
    match tail with
    | [] -> None
    | insn :: _ ->
      if BPF_EXIT? insn then Some st
      else
        let (result, sched') = exec_insn_path st insn sched in
        match result with
        | None -> None
        | Some st' -> exec_program_path st' prog (fuel - 1) sched'

(* Verification proposition for a specific path schedule.
   Identical to program_satisfies but uses exec_program_path with
   the given schedule, making execution deterministic. *)
let program_satisfies_path (prog: bpf_program) (spec: bpf_spec)
  (sched: path_schedule) : prop =
  forall (init: bpf_state).
    spec_pre spec init ==>
    (let init_st = { init with pc = 0;
         regs = set_reg (set_reg init.regs r10 (FramePtr 0)) r1 (CtxPtr 0) } in
     match exec_program_path init_st prog (List.Tot.length prog) sched with
     | Some final_st -> spec_post spec final_st
     | None -> True)
