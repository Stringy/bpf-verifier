module WrongWidth

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Claims the program returns 100, but it actually returns 3.
   Programme uses mixed-width stack accesses (W8, W16). *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 100uL
  )
