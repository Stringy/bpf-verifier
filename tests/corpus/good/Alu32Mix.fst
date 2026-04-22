module Alu32Mix

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Mix of 32-bit and 64-bit ALU operations on the same registers.
   Tests type safety: 32-bit ops require scalar operands and produce
   scalars. sum = 150, diff = 50, result = 150 - 50 = 100. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 100uL
  )
