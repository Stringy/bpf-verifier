module StackArith

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Multiple derived frame pointers: stores and loads through several
   different stack offsets. Tests that stack bounds abstract interpretation
   correctly tracks multiple AbsFramePtr values simultaneously. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 60uL
  )
