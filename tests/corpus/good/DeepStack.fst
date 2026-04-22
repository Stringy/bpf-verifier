module DeepStack

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Uses ~80 bytes of the 512-byte stack with ten 8-byte variables.
   Tests stack bounds checking with many slots at increasing offsets
   from the frame pointer. Sum = 1+2+...+10 = 55. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 55uL
  )
