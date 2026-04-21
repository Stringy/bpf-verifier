module Wrong_return

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Spec claims the program returns 1, but it actually returns 0.
   Verification should FAIL. *)
let spec : bpf_spec =
  ensures (fun final_st ->
    state_get_reg final_st r0 == 1uL
  )
