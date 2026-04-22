module MapUpdate

open BPF.State
open BPF.Spec

(* Calls bpf_map_update_elem (helper #2) then bpf_map_lookup_elem.
   Tests RetErrorCode helper alongside RetMapPtr helper. The update
   returns an error code (TScalar), the lookup returns a map pointer
   (TUnknown/Unchecked). Both are handled generically via helper_spec. *)
let spec : bpf_spec =
  post_only (fun _ -> True)
