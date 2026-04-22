module WrongReturn

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Claims the program returns 1, but it actually returns 0. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 1uL
  )
