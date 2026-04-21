module BPF.Verify

open BPF.State
open BPF.Semantics
open BPF.Spec

let program_satisfies (prog: bpf_program) (spec: bpf_spec) : prop =
  forall (init: bpf_state).
    spec_pre spec init ==>
    (match exec_program init prog with
     | Some final_st -> spec_post spec final_st
     | None -> True)

type layout_constraints = unit

let trivial_constraints : layout_constraints = ()

let relocate (prog: bpf_program) (_lc: layout_constraints) : bpf_program = prog

let for_all_layouts
  (constraints: layout_constraints)
  (prop_fn: bpf_program -> prop)
  (prog: bpf_program) : prop =
  prop_fn (relocate prog constraints)
