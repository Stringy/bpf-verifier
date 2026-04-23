(* Test chunked verification tactic. *)
module Test.ChunkedProof

open FStar.UInt64
open FStar.Int32
open FStar.Tactics.V2
open BPF.State
open BPF.Semantics
open BPF.Spec
open BPF.Verify
open BPF.Tactic.Layered

(* Simple programme: mov r0, 42; exit — one block of 2 instructions *)
let test_program : bpf_program = [
  BPF_ALU32_IMM MOV r0 42l;
  BPF_EXIT
]

let test_spec : bpf_spec =
  post_only (fun st -> state_get_reg st r0 == Scalar 42uL)

(* Chunked proof with one block *)
#push-options "--z3rlimit 60"
let chunked_proof : squash (program_satisfies test_program test_spec) =
  _ by (bpf_auto_chunked [2])
#pop-options

(* Multi-block programme: branch creates two blocks *)
let branch_program : bpf_program = [
  BPF_ALU32_IMM MOV r0 10l;       (* block 0: 2 insns *)
  BPF_JMP64_IMM JGT r0 100l 1;
  BPF_ALU32_IMM ADD r0 5l;        (* block 1: 1 insn *)
  BPF_EXIT                         (* block 2: 1 insn *)
]

let branch_spec : bpf_spec =
  post_only (fun st -> state_get_reg st r0 == Scalar 15uL)

#push-options "--z3rlimit 60"
let chunked_branch : squash (program_satisfies branch_program branch_spec) =
  _ by (bpf_auto_chunked [2; 1; 1])
#pop-options
