(* BPF.Provenance — spec comparison that preserves origin information.

   scalar_is compares a register value against an expected scalar,
   ignoring the origin PC. It lives in its own module so that tactics
   can normalise all BPF execution (BPF.State, BPF.Semantics, etc.)
   while keeping scalar_is opaque — this preserves the Scalar origin
   in proof dumps for diagnostics.

   After dumping, a second normalisation pass unfolds this module
   so SMT can reason about the comparison. *)
module BPF.Provenance

open FStar.UInt64
open BPF.State

let scalar_is (v: reg_val) (expected: UInt64.t) : prop =
  match v with
  | Scalar actual _ -> actual == expected
  | _ -> False
