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

let post_only (p: bpf_state -> prop) : bpf_spec =
  MkSpec trivial_pre p

let with_pre (p: bpf_state -> prop) (spec: bpf_spec) : bpf_spec =
  MkSpec (fun st -> p st /\ spec_pre spec st) (spec_post spec)

let returns_value (v: UInt64.t) : bpf_spec =
  post_only (fun st -> state_get_reg st r0 == v)
