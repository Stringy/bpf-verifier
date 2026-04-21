module Add_regs

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Spec: the program returns 0 *)
let spec : bpf_spec =
  ensures (fun final_st ->
    state_get_reg final_st r0 == 0uL
  )
