module Verify_{{ program_name }}

open FStar.Mul
open BPF.State
open BPF.Semantics
open BPF.Spec
open BPF.Verify
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

#push-options "--fuel {{ fuel }} --ifuel 2 --z3rlimit 60"
let proof : squash (program_satisfies program {{ spec_name }}) =
{%- for i in 0..hints.len() %}
  FStar.Classical.forall_intro (FStar.Classical.move_requires bitwise_hint_{{ i }});
{%- endfor %}
  ()
#pop-options
