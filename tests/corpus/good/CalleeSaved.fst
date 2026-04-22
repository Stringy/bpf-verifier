module CalleeSaved

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Programme stores and loads multiple values at different stack offsets,
   exercising stack bounds checking across several frame pointer derivations. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 60uL
  )
