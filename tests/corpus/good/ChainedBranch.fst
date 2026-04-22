module ChainedBranch

open FStar.UInt64
open BPF.State
open BPF.Spec

(* If/else-if/else-if/else chain with four possible return values.
   Tests multiple forward branches and branch target merging.
   x=42 falls into the third case (x > 25), returning 2. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 2uL
  )
