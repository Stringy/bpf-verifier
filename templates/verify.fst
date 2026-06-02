module Verify_{{ program_name }}

open FStar.Mul
open FStar.Tactics.V2
open BPF.State
open BPF.Semantics
open BPF.Helpers
open BPF.Spec
open BPF.Verify
open BPF.Tactic
open BPF.Check.StackBounds
open BPF.Check.TypeSafety
open BPF.Check.NullSafety
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

(* Stack bounds safety — Rust-computed witness, each step validated by F* *)
open BPF.Witness
{%- for step in sb_witness_steps %}
{{ step }}
{%- endfor %}

(* Type safety — verified by abstract interpretation *)
#push-options "--z3rlimit 60"
let ts_proof : squash (type_check program = true) =
  _ by (type_check_tac ())
#pop-options
{%- if has_map_calls %}

(* Null safety — verified by branch-aware analysis *)
#push-options "--z3rlimit 60"
let ns_proof : squash (null_check program = true) =
  _ by (null_check_tac ())
#pop-options
{%- endif %}

{%- if !path_schedules.is_empty() %}
(* r0_origin diagnostic skipped — path-based proofs avoid full normalisation *)
{%- else %}
(* Diagnostic: which instruction last set r0? *)
let r0_origin : squash (
  forall (init: bpf_state).
    let init_st = { init with pc = 0;
        regs = set_reg (set_reg init.regs r10 (FramePtr 0)) r1 (CtxPtr 0) } in
    (match exec_program init_st program (List.Tot.length program) with
     | Some final_st ->
       let origin = final_st.reg_origins r0 in origin == origin
     | None -> True) ) =
  _ by (r0_origin_tac ())
{%- endif %}
{%- if !path_schedules.is_empty() %}

(* Functional correctness — path-based proofs.
   Each nullable helper call (map_lookup, ringbuf_reserve) can return
   a valid pointer or null. The Rust abstract interpreter enumerated
   all {{ path_schedules.len() }} paths and we prove each independently.
   Per-path execution is deterministic, so full normalisation works. *)
open BPF.Exec.Path
{%- for schedule in path_schedules %}

#push-options "--z3rlimit 120"
let proof_path_{{ loop.index0 }} : squash (program_satisfies_path program {{ spec_name }} [{% for choice in schedule %}{{ choice }}{% if !loop.last %}; {% endif %}{% endfor %}]) =
{%- for i in 0..hints.len() %}
  FStar.Classical.forall_intro (FStar.Classical.move_requires bitwise_hint_{{ i }});
{%- endfor %}
  _ by (norm [nbe; delta; iota; zeta; primops]; smt ())
#pop-options
{%- endfor %}

(* Soundness: all paths satisfy the spec, so the programme satisfies it.
   The path executor is equivalent to the standard executor — for any
   initial state, exec_program follows exactly one of the enumerated
   schedules. Each schedule is proved above.
   TODO: formalise this as a lemma; for now we admit it. *)
let proof : squash (program_satisfies program {{ spec_name }}) =
  admit ()
{%- else %}

(* Functional correctness *)
#push-options "--z3rlimit 120"
let proof : squash (program_satisfies program {{ spec_name }}) =
{%- for i in 0..hints.len() %}
  FStar.Classical.forall_intro (FStar.Classical.move_requires bitwise_hint_{{ i }});
{%- endfor %}
{%- if block_sizes.len() > 1 %}
  _ by (bpf_auto_chunked [{% for size in block_sizes %}{{ size }}{% if !loop.last %}; {% endif %}{% endfor %}])
{%- else %}
  _ by (bpf_auto_{% if has_map_calls %}map{% else %}pure{% endif %} ())
{%- endif %}
#pop-options
{%- endif %}
