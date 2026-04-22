module AddRegs

open FStar.UInt64
open BPF.State
open BPF.Spec

let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 0uL
  )
