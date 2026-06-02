(* BPF.Spec — user-facing specification combinators.

   A spec is a pair of predicates: a precondition on the initial state
   and a postcondition on the final state. Users compose specs using
   these combinators rather than writing raw F* propositions.

   F* notes:
   - `prop` is F*'s type for logical propositions
   - A predicate `bpf_state -> prop` is a property that may or may not
     hold for a given state
   - `MkSpec?.pre s` extracts the `pre` field from a `MkSpec` value
*)
module BPF.Spec

open FStar.UInt64
open BPF.State
open BPF.Semantics

noeq
type bpf_spec =
  | MkSpec : pre:(bpf_state -> prop) -> post:(bpf_state -> prop) -> bpf_spec

let spec_pre (s: bpf_spec) : bpf_state -> prop =
  MkSpec?.pre s

let spec_post (s: bpf_spec) : bpf_state -> prop =
  MkSpec?.post s

let trivial_pre (_: bpf_state) : prop = True

(* Postcondition only — no constraints on the initial state. *)
let post_only (p: bpf_state -> prop) : bpf_spec =
  MkSpec trivial_pre p

(* Add a precondition to an existing spec. *)
let with_pre (p: bpf_state -> prop) (spec: bpf_spec) : bpf_spec =
  MkSpec (fun st -> p st /\ spec_pre spec st) (spec_post spec)

(* Shorthand: the programme returns a specific scalar value in r0. *)
let returns_value (v: UInt64.t) : bpf_spec =
  post_only (fun st -> state_get_reg st r0 == Scalar v)

(* Postcondition on ring buffer contents. The predicate receives
   the ring buffer memory and can assert what was written at which
   offsets. Use with ringbuf_read to check specific fields:

     ringbuf_written (fun rb ->
       ringbuf_read rb 0 0 W32 == Some 42uL
     )
*)
let ringbuf_written (p: ringbuf_mem -> prop) : bpf_spec =
  post_only (fun st -> p st.ringbuf)

(* Combined: returns a value AND ring buffer satisfies a predicate. *)
let returns_and_writes (v: UInt64.t) (p: ringbuf_mem -> prop) : bpf_spec =
  post_only (fun st ->
    state_get_reg st r0 == Scalar v /\
    p st.ringbuf
  )

(* Assert the ring buffer contains exactly `n` writes.
   Combine with ringbuf_read_any to prove a programme writes
   *only* the expected fields — no extra writes. *)
let ringbuf_writes_exactly (n: nat) (p: ringbuf_mem -> prop) : bpf_spec =
  post_only (fun st ->
    ringbuf_write_count st.ringbuf == n /\
    p st.ringbuf
  )
