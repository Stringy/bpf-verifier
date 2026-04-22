module GetPrandom

open BPF.State
open BPF.Spec

(* Calls bpf_get_prandom_u32 (helper #7) and masks the result.
   Tests RetScalar helper with bitwise operations on the return value. *)
let spec : bpf_spec =
  post_only (fun _ -> True)
