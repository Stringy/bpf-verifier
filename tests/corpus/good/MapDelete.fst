module MapDelete

open BPF.State
open BPF.Spec

(* Calls bpf_map_lookup_elem then bpf_map_delete_elem (helper #3).
   Tests RetErrorCode helper with WriteMapValue effect alongside
   a null-checked map pointer dereference. *)
let spec : bpf_spec =
  post_only (fun _ -> True)
