(* BPF.Witness -- concrete representations of abstract states for
   witness validation.

   The safety checkers use function-based abstract states (reg_idx -> abs_reg)
   which can't be serialised to F* source code. This module provides
   concrete list-based representations and conversion functions.

   The Rust-side analysis computes the abstract interpretation natively
   and emits witnesses using these concrete types. F* validates each
   step by converting to the function-based state and checking that
   check_insn_sb produces the expected result. *)
module BPF.Witness

open BPF.State
open BPF.Check.StackBounds

(* Convert a concrete list of (register_index, abs_reg) pairs to the
   function-based abs_state used by the stack bounds checker.
   Registers not in the list default to the initial state
   (r10 = AbsFramePtr 0, all others = AbsOther). *)
let rec to_abs_state_sb (entries: list (nat & abs_reg)) : abs_state =
  fun r -> match entries with
           | [] -> if r = r10 then AbsFramePtr 0 else AbsOther
           | (idx, v) :: rest ->
             if r = idx then v else to_abs_state_sb rest r

(* Convert a concrete list of (pc, register_entries) pairs to the
   function-based target_map used by the stack bounds checker.
   PCs not in the list have no saved branch state. *)
let rec to_target_map_sb (entries: list (int & list (nat & abs_reg))) : target_map =
  fun pc -> match entries with
            | [] -> None
            | (tpc, state) :: rest ->
              if pc = tpc then Some (to_abs_state_sb state)
              else to_target_map_sb rest pc
