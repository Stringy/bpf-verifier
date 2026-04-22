module NestedBranch

open BPF.State
open BPF.Spec

(* Crash safety with nested control flow: null check guards a map
   dereference, then a value comparison creates a second branch.
   Tests that null safety analysis correctly tracks Checked status
   through nested branches. *)
let spec : bpf_spec =
  post_only (fun _ -> True)
