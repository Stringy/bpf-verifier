module BranchResult

open FStar.UInt64
open BPF.State
open BPF.Spec

(* The map lookup can succeed or fail, so there are two possible
   return values. The spec captures both branches as a disjunction. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 0uL \/
    state_get_reg final_st r0 == Scalar 1uL
  )
