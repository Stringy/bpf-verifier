(* BPF.Tactic — proof tactic for BPF programme verification.

   Instead of asking Z3 to reason about the full programme execution,
   this tactic uses F*'s normaliser to evaluate the execution step by
   step. The normaliser can reduce exec_insn on concrete instructions
   even when the state is symbolic, because it resolves match arms
   based on the instruction constructors.

   After normalisation, Z3 only sees the final simplified state and
   the spec — a much smaller proof obligation than the full execution
   trace. This scales linearly with programme size. *)
module BPF.Tactic

open FStar.Tactics.V2
open BPF.State
open BPF.Semantics
open BPF.Spec
open BPF.Verify

(* The list of functions to unfold during normalisation.
   These are the definitions that make up the BPF execution
   semantics — everything from exec_program down to register
   access and stack operations. *)
let bpf_norm_steps : list norm_step = [
  delta_only [
    `%program_satisfies; `%exec_program; `%exec_chunk; `%exec_insn;
    `%list_drop;
    `%alu64; `%alu32; `%sign_extend_imm; `%sign_extend_to_int;
    `%scalar_val; `%state_get_reg; `%state_set_reg;
    `%get_reg; `%set_reg;
    `%stack_load; `%stack_store;
    `%stack_read; `%stack_write; `%stack_offset_valid;
    `%map_value_read;
    `%reg_val_for_jmp; `%reg_val_is_zero;
    `%eval_jmp64; `%eval_jmp32;
    `%width_bytes;
    `%BPF_EXIT?;
    `%List.Tot.Base.length;
    `%Mkbpf_state?.regs; `%Mkbpf_state?.pc;
    `%Mkbpf_state?.stack; `%Mkbpf_state?.map_values;
    `%Mkbpf_state?.next_map_id;
    `%FStar.UInt32.uint_to_t; `%FStar.UInt32.v;
    `%FStar.UInt32.logand; `%FStar.UInt32.logor; `%FStar.UInt32.logxor;
    `%FStar.UInt.logand; `%FStar.UInt.logor; `%FStar.UInt.logxor;
    `%FStar.UInt.to_vec; `%FStar.UInt.from_vec;
    `%FStar.UInt32.add_mod; `%FStar.UInt32.sub_mod; `%FStar.UInt32.mul_mod;
    `%FStar.UInt64.uint_to_t; `%FStar.UInt64.v;
    `%FStar.Int32.v; `%FStar.Int.Cast.int32_to_int64;
    `%FStar.Int.Cast.Full.int64_to_uint64
  ];
  iota; zeta; primops
]

(* The main proof tactic: normalise the programme execution, then
   hand the simplified goal to Z3.

   `extra_deltas` should include the generated `program` and `spec`
   definitions so the normaliser can inline them. *)
let bpf_auto (extra_deltas: list string) : Tac unit =
  norm [delta; iota; zeta; primops];
  smt ()
