module RingBufWrongReturn

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Claims the programme returns 5, but it returns 0 (success path)
   or 1 (reserve failed path). *)
let spec : bpf_spec = returns_value 5uL
