module AddRegs

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Spec: the program computes r0 = r1 + r2 *)
let spec : bpf_spec =
  ensures (fun final_st ->
    forall (r1_init r2_init: UInt64.t).
      state_get_reg final_st r0 == UInt64.add_mod r1_init r2_init
  )
