module WrongOp

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Claims the program returns 10, but it returns 5. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 10uL
  )
