(*
   BPF.Tactic.Layered -- tactics for the layered verification system

   This module provides two tactics for the layered approach to BPF verification:

   1. stack_bounds_tac: Proves stack safety via normalisation of the decidable
      stack_bounds_check function. Since the check is purely computational over
      concrete instruction lists, F*'s normaliser evaluates it to true, leaving
      a trivial goal.

   2. bpf_auto_layered: Proves functional correctness via the safe executor.
      When stack_safe evidence is available, the guarded executor's runtime
      checks become statically known (all guards evaluate to true), allowing
      the normaliser to reduce the guarded semantics to a deterministic trace.
      This eliminates branches and yields a pure computation that SMT can verify.

   The layered approach separates safety (proved by normalisation) from
   correctness (proved by SMT over the safe executor), improving scalability
   by giving Z3 a simpler, deterministic execution model.
*)
module BPF.Tactic.Layered

open FStar.Tactics.V2
open BPF.State
open BPF.Semantics
open BPF.Spec
open BPF.Verify
open BPF.Check.StackBounds
open BPF.Check.TypeSafety
open BPF.Check.NullSafety
open BPF.Exec.Safe

(*
   Prove that a concrete programme passes stack_bounds_check.

   How it works:
   - stack_bounds_check is a decidable boolean function that walks the
     instruction list and checks each stack operation against bounds
   - For a concrete programme (known instruction list), normalisation
     evaluates the check function step-by-step to either true or false
   - norm [delta; iota; zeta; primops] performs full normalisation:
     * delta: unfold all definitions
     * iota: reduce pattern matches
     * zeta: reduce let bindings
     * primops: evaluate primitive operations (arithmetic, comparisons)
   - After normalisation, the goal becomes `true == true`, which trivial()
     discharges immediately without invoking Z3

   Use this tactic when you need to prove stack_safe evidence for a programme.
*)
let stack_bounds_tac () : Tac unit =
  norm [nbe; delta; iota; zeta; primops];
  trivial ()

(*
   Prove that a concrete programme passes type_check.

   How it works:
   - type_check is a decidable boolean function that performs abstract
     interpretation to verify type safety of register operations
   - For a concrete programme (known instruction list), normalisation
     evaluates the type checker step-by-step to either true or false
   - norm [delta; iota; zeta; primops] performs full normalisation:
     * delta: unfold all definitions
     * iota: reduce pattern matches
     * zeta: reduce let bindings
     * primops: evaluate primitive operations (arithmetic, comparisons)
   - After normalisation, the goal becomes `true == true`, which trivial()
     discharges immediately without invoking Z3

   Use this tactic when you need to prove type safety for a programme.
   Same strategy as stack_bounds_tac: full normalisation evaluates the
   decidable check to true on concrete programmes.
*)
let type_check_tac () : Tac unit =
  norm [nbe; delta; iota; zeta; primops];
  trivial ()

(*
   Prove that a concrete programme passes null_check.

   How it works:
   - null_check is a decidable boolean function that performs branch-aware
     analysis to verify that all map value reads are protected by null checks
   - For a concrete programme (known instruction list), normalisation
     evaluates the checker step-by-step to either true or false
   - norm [delta; iota; zeta; primops] performs full normalisation:
     * delta: unfold all definitions
     * iota: reduce pattern matches
     * zeta: reduce let bindings
     * primops: evaluate primitive operations (arithmetic, comparisons)
   - After normalisation, the goal becomes `true == true`, which trivial()
     discharges immediately without invoking Z3

   Use this tactic when you need to prove null safety for a programme that
   uses map lookups. Same strategy as the other check tactics: full
   normalisation evaluates the decidable check to true on concrete programmes.
*)
let null_check_tac () : Tac unit =
  norm [nbe; delta; iota; zeta; primops];
  trivial ()

(*
   Prove functional correctness via the safe executor.

   How it works:
   - The safe executor (exec_insn_safe, exec_program_safe) wraps each
     potentially unsafe operation in a guard: if (bounds_check) then ... else None
   - When stack_safe evidence is available, the type system knows all guard
     conditions hold, but the SMT solver still sees the if-branches in the code
   - Full normalisation evaluates these guards on concrete inputs:
     * Guards with known-true conditions reduce to their then-branch
     * Guards with known-false conditions reduce to their else-branch
     * For safe programmes with stack_safe evidence, all safety guards reduce
       to true, eliminating the else-branches entirely
   - After normalisation, the guarded executor becomes a deterministic function
     over registers and memory, similar to a pure interpreter
   - smt() then proves correctness by reasoning about this simplified execution,
     without needing to explore all the safety-check branches that have been
     statically eliminated

   Use this tactic when proving exec_program_safe produces the correct result
   for a programme that has stack_safe evidence.
*)
let bpf_auto_layered () : Tac unit =
  norm [nbe; delta; iota; zeta; primops];
  smt ()
