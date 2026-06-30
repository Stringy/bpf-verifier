(*
  BPF.AST.Tactic — Tactic for AST-level verification

  Entry-point tactic for generated verification modules. The generated
  module defines a surface AST value, and the proof obligation is that
  check_ok evaluates to true. The tactic normalises this application on
  concrete data — if the programme is well-formed, the normaliser
  reduces check_ok to true, and trivial() discharges the goal.
*)
module BPF.AST.Tactic

open FStar.Tactics.V2

(* Normalise the check_ok application and discharge.
   Same strategy as the object-level stack_bounds_tac / type_check_tac. *)
let ast_check_tac () : Tac unit =
  norm [nbe; delta; iota; zeta; primops];
  trivial ()
