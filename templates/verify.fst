module Verify_{{ program_name }}

open FStar.Mul
open FStar.Tactics.V2
open BPF.State
open BPF.Semantics
open BPF.Spec
open BPF.Verify
open BPF.Tactic
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

#push-options "--z3rlimit 30"
let proof : squash (program_satisfies program {{ spec_name }}) =
{%- for i in 0..hints.len() %}
  FStar.Classical.forall_intro (FStar.Classical.move_requires bitwise_hint_{{ i }});
{%- endfor %}
  _ by (bpf_auto [])
#pop-options
