(* BPF.Verify — the proof harness.

   This is where specification meets execution. `program_satisfies`
   is the core proposition: "for all possible initial states where the
   precondition holds, if the programme terminates normally, the final
   state satisfies the postcondition."

   The None case (undefined behaviour / fuel exhaustion) is mapped to
   True — meaning UB doesn't violate the functional spec. This is correct
   because UB is caught separately by safety checks (the kernel verifier
   rejects programmes that can divide by zero, access out-of-bounds
   memory, etc.). We verify safety and functional correctness independently.

   Fuel is set to the programme length — sufficient for loop-free
   programmes where each instruction is visited at most once. Programmes
   with bounded loops would need higher fuel.
*)
module BPF.Verify

open BPF.State
open BPF.Semantics
open BPF.Spec

(* The core verification proposition.
   `forall (init: bpf_state)` means this must hold for ANY initial
   state — any register values, any stack contents. The user narrows
   this with preconditions (e.g. "r1 is non-null").

   The initial pc is set to 0 (programme entry point). Fuel is the
   programme length — one step per instruction, enough for straight-line
   code and forward-only branches. *)
let program_satisfies (prog: bpf_program) (spec: bpf_spec) : prop =
  forall (init: bpf_state).
    spec_pre spec init ==>
    (let init_st = { init with pc = 0;
         regs = set_reg (set_reg init.regs r10 (FramePtr 0)) r1 (CtxPtr 0) } in
     match exec_program init_st prog (List.Tot.length prog) with
     | Some final_st -> spec_post spec final_st
     | None -> True)

(* Chunked verification: the exec function is provided by the generated
   code (which chains exec_chunk calls). Same contract as program_satisfies
   but the execution strategy is delegated to the caller. *)
let program_satisfies_chunked (exec_fn: bpf_state -> option bpf_state) (spec: bpf_spec) : prop =
  forall (init: bpf_state).
    spec_pre spec init ==>
    (match exec_fn init with
     | Some final_st -> spec_post spec final_st
     | None -> True)
