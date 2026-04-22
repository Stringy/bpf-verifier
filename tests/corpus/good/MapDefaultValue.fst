module MapDefaultValue

open BPF.State
open BPF.Spec

(* Common BPF pattern: map lookup with a default value fallback.
   If the lookup succeeds, returns the map value; if null, returns 42.
   Tests that the null safety checker handles the ternary-style
   null check pattern (conditional move or branch). *)
let spec : bpf_spec =
  post_only (fun _ -> True)
