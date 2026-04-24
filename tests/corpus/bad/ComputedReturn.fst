module ComputedReturn

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Claims x + y = 10, but 3 + 4 = 7 *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 10uL
  )
