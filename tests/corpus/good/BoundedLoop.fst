module BoundedLoop

open BPF.State
open BPF.Spec

(* Bounded loop: sum of 0..4 = 10. Tests backward branch support
   in the safety checkers — the loop generates a backward jump that
   the checkers must handle via widened states at the loop head. *)
let spec : bpf_spec =
  post_only (fun _ -> True)
