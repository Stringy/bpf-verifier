module MapLookup

open BPF.State
open BPF.Spec

(* The key property: this programme doesn't crash. It null-checks the
   map lookup result before dereferencing, so execution never reaches
   a null pointer dereference (which would produce None / UB). *)
let spec : bpf_spec =
  post_only (fun _ -> True)
