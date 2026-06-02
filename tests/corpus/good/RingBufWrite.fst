module RingBufWrite

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Ring buffer reserve can fail (returns null), so the programme
   returns either 0 (success — wrote to ringbuf) or 1 (reserve failed).
   We verify both paths are safe and return the expected value. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 0uL \/
    state_get_reg final_st r0 == Scalar 1uL
  )
