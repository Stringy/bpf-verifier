module WideStack

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Store and load at all four BPF memory widths (W8/W16/W32/W64).
   Tests that stack bounds checking handles different access sizes
   correctly at various offsets. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 10uL
  )
