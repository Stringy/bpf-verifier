module EarlyReturn

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Multiple early return paths with different conditions.
   Tests stack bounds and type safety across complex control flow.
   x=42, y=10: none of the early return conditions are met,
   so the programme returns x + y = 52. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 52uL
  )
