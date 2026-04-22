module Test.ReturnZero

open FStar.UInt64
open FStar.Int32
open BPF.State
open BPF.Semantics
open BPF.Spec
open BPF.Verify

let return_zero_program : bpf_program = [
  BPF_ALU32_IMM MOV r0 0l;
  BPF_EXIT
]

let return_zero_spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 0uL
  )

let return_zero_proof : squash (program_satisfies return_zero_program return_zero_spec) =
  ()
