(* BPF.Exec.Safe -- guarded executor with safety evidence.

   This module provides an alternative instruction executor that can skip
   redundant bounds checks when static verification has already proved
   them safe. The key idea: the BPF verifier (BPF.Verify) analyses a
   programme and produces "safety evidence" -- a record of which safety
   properties have been verified. The guarded executor checks this
   evidence at each stack access point:

   - If stack_safe is true, the bounds check has already been proved
     statically, so we call stack_read/stack_write directly (skipping
     the stack_offset_valid check that stack_load/stack_store perform).
   - If stack_safe is false, we fall back to the original checked path
     (stack_load/stack_store), which is identical to BPF.Semantics.exec_insn.

   This separation lets us prove two things independently:
   1. The programme's functional behaviour (what it computes)
   2. The programme's safety properties (no out-of-bounds access)

   The type_safe and null_safe fields are reserved for future phases --
   they have no guards yet, but their presence in the evidence type
   means we can extend the system without changing the core signature.

   F* notes:
   - `noeq` means F* won't try to derive decidable equality for the type
     (needed because record types with bool fields sometimes confuse it)
   - `Tot` means total -- the function always terminates and returns a value
   - `decreases fuel` tells F* which argument shrinks on each recursive call,
     proving termination
*)
module BPF.Exec.Safe

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

(* --- Safety evidence ---
   A record of which safety properties have been statically verified
   for a particular programme. Each field gates a class of runtime
   checks in the guarded executor.

   - stack_safe: all stack accesses are within bounds (skip stack_offset_valid)
   - type_safe: all ALU operands have correct types (future use)
   - null_safe: all pointer dereferences are non-null (future use) *)
noeq
type safety_evidence = {
  stack_safe: bool;
  type_safe: bool;
  null_safe: bool;
}

(* No properties verified -- all runtime checks are enabled.
   This is the conservative default; the executor behaves identically
   to BPF.Semantics.exec_insn with this evidence. *)
let evidence_none : safety_evidence = { stack_safe = false; type_safe = false; null_safe = false }

(* Stack bounds have been verified -- skip stack_offset_valid checks.
   Used when the verifier has proved that every stack access in the
   programme falls within the 512-byte frame. *)
let evidence_stack : safety_evidence = { stack_safe = true; type_safe = false; null_safe = false }

(* Execute one instruction with safety evidence.

   This is identical to BPF.Semantics.exec_insn except at three stack
   access points (BPF_LDX/BPF_STX/BPF_ST through FramePtr), where the
   stack_safe flag controls whether we check bounds:

   - stack_safe = true:  call stack_read/stack_write directly (no bounds check)
   - stack_safe = false: call stack_load/stack_store (includes bounds check)

   All other instruction cases are copied verbatim from BPF.Semantics. *)
let exec_insn_safe (st: bpf_state) (insn: bpf_insn) (ev: safety_evidence) : option bpf_state =
  match insn with
  | BPF_ALU64_REG op dst src ->
    let dv = state_get_reg st dst in
    let sv = state_get_reg st src in
    (match op with
     | MOV -> Some (state_set_reg st dst sv)
     | _ ->
       (match scalar_val dv, scalar_val sv with
        | Some d, Some s ->
          (match alu64 op d s with
           | None -> None
           | Some result -> Some (state_set_reg st dst (Scalar result)))
        | _, _ -> None))
  | BPF_ALU64_IMM op dst imm ->
    let dv = state_get_reg st dst in
    let iv = sign_extend_to_int imm in
    (match op with
     | MOV -> Some (state_set_reg st dst (Scalar (sign_extend_imm imm)))
     | ADD ->
       (match dv with
        | Scalar d ->
          (match alu64 ADD d (sign_extend_imm imm) with
           | None -> None
           | Some result -> Some (state_set_reg st dst (Scalar result)))
        | FramePtr off -> Some (state_set_reg st dst (FramePtr (off + iv)))
        | CtxPtr off -> Some (state_set_reg st dst (CtxPtr (off + iv)))
        | _ -> None)
     | SUB ->
       (match dv with
        | Scalar d ->
          (match alu64 SUB d (sign_extend_imm imm) with
           | None -> None
           | Some result -> Some (state_set_reg st dst (Scalar result)))
        | FramePtr off -> Some (state_set_reg st dst (FramePtr (off - iv)))
        | CtxPtr off -> Some (state_set_reg st dst (CtxPtr (off - iv)))
        | _ -> None)
     | _ ->
       (match scalar_val dv with
        | Some d ->
          (match alu64 op d (sign_extend_imm imm) with
           | None -> None
           | Some result -> Some (state_set_reg st dst (Scalar result)))
        | None -> None))
  | BPF_ALU32_REG op dst src ->
    let dv = state_get_reg st dst in
    let sv = state_get_reg st src in
    (match op with
     | MOV ->
       (match scalar_val sv with
        | Some s ->
          (match alu32 MOV s s with
           | Some result -> Some (state_set_reg st dst (Scalar result))
           | None -> None)
        | None -> None)
     | _ ->
       (match scalar_val dv, scalar_val sv with
        | Some d, Some s ->
          (match alu32 op d s with
           | None -> None
           | Some result -> Some (state_set_reg st dst (Scalar result)))
        | _, _ -> None))
  | BPF_ALU32_IMM op dst imm ->
    let dv = state_get_reg st dst in
    (match op with
     | MOV -> Some (state_set_reg st dst (Scalar (sign_extend_imm imm)))
     | _ ->
       (match scalar_val dv with
        | Some d ->
          let iv = sign_extend_imm imm in
          (match alu32 op d iv with
           | None -> None
           | Some result -> Some (state_set_reg st dst (Scalar result)))
        | None -> None))
  | BPF_LD_IMM64 dst imm ->
    Some (state_set_reg st dst (Scalar imm))
  (* Memory load: dispatch on the base register type.
     For FramePtr, the stack_safe guard controls whether we check bounds. *)
  | BPF_LDX w dst src off ->
    let base = state_get_reg st src in
    let insn_off = sign_extend_to_int off in
    (match base with
     | FramePtr ptr_off ->
       if ev.stack_safe
       then
         (* Bounds already verified statically -- skip stack_offset_valid,
            read directly from the stack memory list. *)
         (match stack_read st.stack (ptr_off + insn_off) w with
          | None -> None
          | Some v -> Some (state_set_reg st dst (Scalar v)))
       else
         (* No static evidence -- fall back to checked stack_load which
            validates offset is within the 512-byte frame. *)
         (match stack_load st (ptr_off + insn_off) w with
          | None -> None
          | Some v -> Some (state_set_reg st dst (Scalar v)))
     | MapValuePtr id ->
       (match map_value_read st.map_values id with
        | None -> None
        | Some v -> Some (state_set_reg st dst (Scalar v)))
     | RingBufPtr id ->
       (match ringbuf_read st.ringbuf id insn_off w with
        | None -> Some (state_set_reg st dst (Scalar 0uL))
        | Some v -> Some (state_set_reg st dst (Scalar v)))
     | CtxPtr _ -> Some (state_set_reg st dst (Scalar 0uL))
     | Null -> None
     | Scalar _ -> None)
  | BPF_STX w dst src off ->
    let base = state_get_reg st dst in
    let insn_off = sign_extend_to_int off in
    (match base with
     | FramePtr ptr_off ->
       (match scalar_val (state_get_reg st src) with
        | Some v ->
          if ev.stack_safe
          then
            Some { st with stack = stack_write st.stack (ptr_off + insn_off) w v; pc = st.pc + 1 }
          else
            stack_store st (ptr_off + insn_off) w v
        | None -> None)
     | RingBufPtr id ->
       (match scalar_val (state_get_reg st src) with
        | Some v ->
          Some { st with ringbuf = ringbuf_write st.ringbuf id insn_off w v;
                         pc = st.pc + 1 }
        | None -> None)
     | _ -> None)
  | BPF_ST w dst off imm ->
    let base = state_get_reg st dst in
    let insn_off = sign_extend_to_int off in
    (match base with
     | FramePtr ptr_off ->
       let v = sign_extend_imm imm in
       if ev.stack_safe
       then
         Some { st with stack = stack_write st.stack (ptr_off + insn_off) w v; pc = st.pc + 1 }
       else
         stack_store st (ptr_off + insn_off) w v
     | RingBufPtr id ->
       let v = sign_extend_imm imm in
       Some { st with ringbuf = ringbuf_write st.ringbuf id insn_off w v;
                      pc = st.pc + 1 }
     | _ -> None)
  | BPF_JMP64_REG op dst src offset ->
    (match reg_val_for_jmp (state_get_reg st dst), reg_val_for_jmp (state_get_reg st src) with
     | Some d, Some s ->
       let next_pc = if eval_jmp64 op d s then st.pc + 1 + offset else st.pc + 1 in
       Some { st with pc = next_pc }
     | _, _ -> None)
  | BPF_JMP64_IMM op dst imm offset ->
    if op = JEQ || op = JNE then
      (match reg_val_is_zero (state_get_reg st dst) with
       | Some is_zero ->
         let imm_val = sign_extend_imm imm in
         let cond = (match op with
           | JEQ -> if UInt64.v imm_val = 0 then is_zero else not is_zero
           | JNE -> if UInt64.v imm_val = 0 then not is_zero else is_zero
           | _ -> false) in
         let next_pc = if cond then st.pc + 1 + offset else st.pc + 1 in
         Some { st with pc = next_pc }
       | None -> None)
    else
      (match scalar_val (state_get_reg st dst) with
       | Some d ->
         let s = sign_extend_imm imm in
         let next_pc = if eval_jmp64 op d s then st.pc + 1 + offset else st.pc + 1 in
         Some { st with pc = next_pc }
       | None -> None)
  | BPF_JMP32_REG op dst src offset ->
    (match scalar_val (state_get_reg st dst), scalar_val (state_get_reg st src) with
     | Some d, Some s ->
       let next_pc = if eval_jmp32 op d s then st.pc + 1 + offset else st.pc + 1 in
       Some { st with pc = next_pc }
     | _, _ -> None)
  | BPF_JMP32_IMM op dst imm offset ->
    (match scalar_val (state_get_reg st dst) with
     | Some d ->
       let s = sign_extend_imm imm in
       let next_pc = if eval_jmp32 op d s then st.pc + 1 + offset else st.pc + 1 in
       Some { st with pc = next_pc }
     | None -> None)
  | BPF_JMP_JA offset ->
    Some { st with pc = st.pc + 1 + offset }
  (* BPF_CALL: dispatch through helper registry with safety evidence.
     exec_helper_safe uses the null_safe flag to determine whether to
     populate map_values for RetMapPtr helpers. *)
  | BPF_CALL hid ->
    (match get_helper_spec hid with
     | Some spec -> exec_helper_safe st spec ev.null_safe
     | None -> None)
  | BPF_EXIT -> Some st

(* Execute a full programme with safety evidence.

   Same fuel-based loop as BPF.Semantics.exec_program, but delegates
   each instruction to exec_insn_safe so that the evidence gates can
   skip redundant checks.

   `fuel` bounds the number of steps to prevent infinite loops. For
   loop-free programmes, fuel = programme length is sufficient. *)
let rec exec_program_safe (st: bpf_state) (prog: bpf_program) (fuel: nat) (ev: safety_evidence)
  : Tot (option bpf_state) (decreases fuel) =
  if fuel = 0 then None
  else
    let tail = list_drop prog (if st.pc >= 0 then st.pc else 0) in
    match tail with
    | [] -> None
    | insn :: _ ->
      if BPF_EXIT? insn then Some st
      else
        match exec_insn_safe st insn ev with
        | None -> None
        | Some st' -> exec_program_safe st' prog (fuel - 1) ev

(* The core verification proposition for guarded execution.

   Same contract as BPF.Verify.program_satisfies: for all initial states
   satisfying the precondition, if the programme terminates, the final
   state satisfies the postcondition. The difference is that execution
   uses exec_program_safe with the provided safety evidence, so verified
   bounds checks are skipped.

   When ev = evidence_none, this is equivalent to program_satisfies. *)
let program_satisfies_safe (prog: bpf_program) (spec: bpf_spec) (ev: safety_evidence) : prop =
  forall (init: bpf_state).
    spec_pre spec init ==>
    (let init_st = { init with pc = 0;
         regs = set_reg (set_reg init.regs r10 (FramePtr 0)) r1 (CtxPtr 0) } in
     match exec_program_safe init_st prog (List.Tot.length prog) ev with
     | Some final_st -> spec_post spec final_st
     | None -> True)

(* --- Phase 1 reconnection strategy ---

   In Phase 1 we do NOT yet have a formal lemma proving that
   exec_program_safe refines exec_program. Instead the generated
   template emits two independent proofs:

   1. stack_bounds_check programme = true   (via stack_bounds_tac)
   2. program_satisfies programme spec      (via bpf_auto_pure/map)

   The stack bounds proof is an additive safety guarantee -- it
   certifies a property independently of the functional spec. The
   functional proof still uses the original program_satisfies (not
   program_satisfies_safe) so correctness is unchanged.

   A formal reconnection lemma (layered_sound) will be added in
   Phase 3 when all three safety layers are in place:

     val layered_sound : prog:bpf_program -> spec:bpf_spec ->
       ev:safety_evidence ->
       Lemma (requires
                (ev.stack_safe ==> stack_bounds_check prog) /\
                (ev.type_safe  ==> type_check prog) /\
                (ev.null_safe  ==> null_check prog) /\
                program_satisfies_safe prog spec ev)
             (ensures program_satisfies prog spec)

   At that point the generated template will switch to proving
   program_satisfies_safe with evidence_all, then applying
   layered_sound to recover program_satisfies. *)
