(* BPF.Spec — user-facing specification combinators.

   A spec is a pair of predicates: a precondition on the initial state
   and a postcondition on the final state. Users compose specs using
   these combinators rather than writing raw F* propositions.

   F* notes:
   - `prop` is F*'s type for logical propositions (things that can be
     true or false). A predicate `bpf_state -> prop` is a property
     that may or may not hold for a given state.
   - `MkSpec?.pre s` extracts the `pre` field from a `MkSpec` value.
     The `?` is F*'s accessor syntax for inductive type fields.
*)
module BPF.Spec

open FStar.UInt64
open BPF.State
open BPF.Semantics

(* A specification: precondition on the initial state and postcondition
   on the final state. `noeq` because predicates don't have decidable
   equality. *)
noeq
type bpf_spec =
  | MkSpec : pre:(bpf_state -> prop) -> post:(bpf_state -> prop) -> bpf_spec

let spec_pre (s: bpf_spec) : bpf_state -> prop =
  MkSpec?.pre s

let spec_post (s: bpf_spec) : bpf_state -> prop =
  MkSpec?.post s

let trivial_pre (_: bpf_state) : prop = True

(* Postcondition only — no constraints on the initial state.
   Use for programmes whose result doesn't depend on inputs. *)
let post_only (p: bpf_state -> prop) : bpf_spec =
  MkSpec trivial_pre p

(* Add a precondition to an existing spec. Preconditions are
   conjoined, so calling with_pre multiple times adds multiple
   constraints that must all hold. *)
let with_pre (p: bpf_state -> prop) (spec: bpf_spec) : bpf_spec =
  MkSpec (fun st -> p st /\ spec_pre spec st) (spec_post spec)

(* Shorthand: the programme must return a specific value in r0. *)
let returns_value (v: UInt64.t) : bpf_spec =
  post_only (fun st -> state_get_reg st r0 == v)
