module Verify_{{ program_name }}

open FStar.Mul
open FStar.Tactics.V2
open BPF.State
open BPF.Semantics
open BPF.Spec
open BPF.Verify
open BPF.Tactic
open BPF.Check.StackBounds
open BPF.Check.TypeSafety
open BPF.Tactic.Layered
open {{ spec_module }}

let program : bpf_program = [
{%- for insn in instructions %}
  {{ insn }}{% if !loop.last %};{% endif %}
{%- endfor %}

]
{%- if !hints.is_empty() %}

open FStar.UInt32
open FStar.UInt64
{% for hint in hints %}

{{ hint }}
{%- endfor %}
{%- endif %}

(* Stack bounds safety — verified by abstract interpretation *)
#push-options "--z3rlimit 60"
let sb_proof : squash (stack_bounds_check program = true) =
  _ by (stack_bounds_tac ())
#pop-options

(* Type safety — verified by abstract interpretation *)
#push-options "--z3rlimit 60"
let ts_proof : squash (type_check program = true) =
  _ by (type_check_tac ())
#pop-options

(* Functional correctness *)
#push-options "--z3rlimit 60"
let proof : squash (program_satisfies program {{ spec_name }}) =
{%- for i in 0..hints.len() %}
  FStar.Classical.forall_intro (FStar.Classical.move_requires bitwise_hint_{{ i }});
{%- endfor %}
  _ by (bpf_auto_{% if has_map_calls %}map{% else %}pure{% endif %} ())
#pop-options
