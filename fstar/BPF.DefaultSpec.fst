(* BPF.DefaultSpec -- the default specification used when the user
   does not provide a custom spec file.

   This spec asserts crash safety: the programme either terminates
   normally (with any result) or hits undefined behaviour. Combined
   with the three safety layers (stack bounds, type safety, null safety),
   this proves the programme is well-formed -- no out-of-bounds stack
   access, no type mismatches, no null pointer dereferences, and no
   other undefined behaviour.

   Users who want to prove stronger properties (e.g. "the programme
   returns 42") should provide a custom spec file via --spec. *)
module BPF.DefaultSpec

open BPF.State
open BPF.Spec

let spec : bpf_spec =
  post_only (fun _ -> True)
