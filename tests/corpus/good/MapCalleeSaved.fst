module MapCalleeSaved

open BPF.State
open BPF.Spec

(* Tests that null-checked map pointer status survives across a second
   BPF_CALL via callee-saved registers. The first map lookup result is
   dereferenced and saved before a second map lookup clobbers r0-r5
   but preserves r6-r9. *)
let spec : bpf_spec =
  post_only (fun _ -> True)
