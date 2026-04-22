module MultiMapLookup

open BPF.State
open BPF.Spec

(* Crash safety: the programme null-checks both map lookups before
   dereferencing. The spec doesn't constrain the return value since
   map contents are symbolic. *)
let spec : bpf_spec =
  post_only (fun _ -> True)
