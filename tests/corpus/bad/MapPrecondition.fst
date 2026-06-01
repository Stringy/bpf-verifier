module MapPrecondition

open FStar.UInt64
open BPF.State
open BPF.Spec

(* A more complex spec: claims the programme returns 0 when input > 100,
   but it actually returns 1. Also claims r0 is never 1, which is wrong. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 0uL /\
    (state_get_reg final_st r0 == Scalar 0uL \/
     state_get_reg final_st r0 == Scalar 2uL)
  )
