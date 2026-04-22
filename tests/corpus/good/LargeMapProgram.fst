module LargeMapProgram

open BPF.State
open BPF.Spec

(* Larger programme with three map lookups, null checks on each,
   value accumulation, and a final bounds check. Tests scaling of
   null safety analysis and bpf_auto_map tactic with multiple
   non-deterministic map lookups in a single programme. *)
let spec : bpf_spec =
  post_only (fun _ -> True)
