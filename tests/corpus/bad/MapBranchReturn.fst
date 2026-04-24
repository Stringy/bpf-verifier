module MapBranchReturn

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Claims it always returns 0, but it returns *val or 99 *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 0uL
  )
