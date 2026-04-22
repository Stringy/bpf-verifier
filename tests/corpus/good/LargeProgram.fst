module LargeProgram

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Sum of 1..26 = 351 *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 351uL
  )
