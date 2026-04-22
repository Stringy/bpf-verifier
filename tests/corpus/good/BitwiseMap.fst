module BitwiseMap

open BPF.State
open BPF.Spec

(* Map lookup with bitwise AND on the result value.
   Tests interaction between bitwise operation hints and map lookup
   null safety. The programme null-checks before dereferencing,
   then applies a bitwise mask to the loaded value. *)
let spec : bpf_spec =
  post_only (fun _ -> True)
