module KtimeGetNs

open BPF.State
open BPF.Spec

(* Calls bpf_ktime_get_ns (helper #5) which returns a scalar.
   The programme branches on the result. Tests that RetScalar
   helpers are handled correctly by the type safety and null
   safety checkers — r0 should be TScalar/NotMap after the call. *)
let spec : bpf_spec =
  post_only (fun _ -> True)
