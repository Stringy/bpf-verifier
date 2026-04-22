module OffByOne

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Claims a + b = 43, but 10 + 32 = 42. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 43uL
  )
