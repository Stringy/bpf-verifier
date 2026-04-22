(* BPF.Verify — the proof harness.

   This is where specification meets execution. `program_satisfies`
   is the core proposition: "for all possible initial states where the
   precondition holds, if the programme terminates normally, the final
   state satisfies the postcondition."

   The None case (undefined behaviour) is mapped to True — meaning UB
   doesn't violate the functional spec. This is correct because UB is
   caught separately by safety checks (the kernel verifier rejects
   programmes that can divide by zero, access out-of-bounds memory,
   etc.). We verify safety and functional correctness independently.

   The CO-RE / relocation scaffolding (layout_constraints, relocate,
   for_all_layouts) is trivial stubs for now. In Milestone E, these
   will quantify over all valid BTF layouts to prove that the programme
   is correct regardless of which kernel it runs on.
*)
module BPF.Verify

open BPF.State
open BPF.Semantics
open BPF.Spec

(* The core verification proposition.
   `forall (init: bpf_state)` means this must hold for ANY initial
   state — any register values, any stack contents. The user narrows
   this with preconditions (e.g. "r1 is non-null"). *)
let program_satisfies (prog: bpf_program) (spec: bpf_spec) : prop =
  forall (init: bpf_state).
    spec_pre spec init ==>
    (match exec_program init prog with
     | Some final_st -> spec_post spec final_st
     | None -> True)

(* --- CO-RE relocation stubs ---
   Placeholder types for Milestone E. Currently trivial (no relocations). *)
type layout_constraints = unit

let trivial_constraints : layout_constraints = ()

let relocate (prog: bpf_program) (_lc: layout_constraints) : bpf_program = prog

let for_all_layouts
  (constraints: layout_constraints)
  (prop_fn: bpf_program -> prop)
  (prog: bpf_program) : prop =
  prop_fn (relocate prog constraints)
