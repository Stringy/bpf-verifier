(* BPF.Tactic — proof tactics for BPF programme verification.

   Two proof strategies depending on programme characteristics:

   bpf_auto_pure: For programmes without non-determinism (no map
   lookups). Uses full delta normalisation — F* evaluates the entire
   execution, leaving Z3 with a trivial equality. Very fast, scales
   to 100+ instructions.

   bpf_auto_map: For programmes with map lookups (non-deterministic
   results). Uses selective delta_namespace normalisation that keeps
   FStar.Pervasives (option type) opaque so Z3 can reason about both
   branches of a null check. Slower but handles non-determinism.

   The Rust codegen chooses which tactic to emit based on whether the
   programme contains BPF_CALL instructions. *)
module BPF.Tactic

open FStar.Tactics.V2
open BPF.State
open BPF.Semantics
open BPF.Spec
open BPF.Verify

(* Full delta normalisation — unfolds everything. Fast and complete
   for deterministic programmes. Breaks on non-determinism because
   option constructors get over-normalised. *)
let bpf_auto_pure () : Tac unit =
  norm [delta; iota; zeta; primops];
  smt ()

(* Selective normalisation — unfolds BPF semantics and F* integer
   types but keeps option/pervasives opaque. Handles non-deterministic
   programmes (map lookups) but is slower because some terms remain
   symbolic for Z3 to process. *)
let bpf_auto_map () : Tac unit =
  norm [delta_namespace ["BPF"; "Verify_"; "Prims";
                         "FStar.UInt64"; "FStar.UInt32"; "FStar.UInt8"; "FStar.UInt";
                         "FStar.Int32"; "FStar.Int64"; "FStar.Int";
                         "FStar.Int.Cast"; "FStar.Int.Cast.Full";
                         "FStar.Mul"; "FStar.List.Tot"];
        iota; zeta; primops];
  smt ()
