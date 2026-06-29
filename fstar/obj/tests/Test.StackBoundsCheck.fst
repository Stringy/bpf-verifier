(* Test.StackBoundsCheck -- validates the stack bounds checker.

   Tests that stack_bounds_check correctly accepts programmes with valid
   stack accesses and rejects those with out-of-bounds accesses.

   F* notes for BPF developers:
   - `assert_norm` is a compile-time assertion evaluated by normalisation
   - The `l` suffix creates an Int32 literal (signed 32-bit)
   - Register constants (r0, r2, r10) are defined in BPF.State *)
module Test.StackBoundsCheck

open FStar.Int32
open BPF.State
open BPF.Semantics
open BPF.Check.StackBounds

(* Valid stack access: store W32 at offset -4 from r10.
   index = 512 + (-4) = 508, end = 508 + 4 = 512 -- exactly at boundary. *)
let good_program : bpf_program = [
  BPF_ALU64_REG MOV r2 r10;
  BPF_ALU64_IMM ADD r2 (-4l);
  BPF_ST W32 r2 0l 42l;
  BPF_ALU32_IMM MOV r0 0l;
  BPF_EXIT
]

let good_test : squash (stack_bounds_check good_program = true) =
  assert_norm (stack_bounds_check good_program = true)

(* Out-of-bounds: store W64 at offset 0 from r10.
   index = 512 + 0 = 512, end = 512 + 8 = 520 > 512 -- exceeds stack. *)
let bad_program : bpf_program = [
  BPF_ALU64_REG MOV r2 r10;
  BPF_ST W64 r2 0l 42l;
  BPF_ALU32_IMM MOV r0 0l;
  BPF_EXIT
]

let bad_test : squash (stack_bounds_check bad_program = false) =
  assert_norm (stack_bounds_check bad_program = false)

(* Branch-aware test: r2 = FramePtr(-4) on fall-through path,
   r2 = AbsOther (overwritten) on taken path. After the branch
   merges, r2 should be AbsOther, so the store passes even though
   the offset would be invalid if r2 were still FramePtr(-4).

   pc 0: r2 = r10             -- AbsFramePtr(0)
   pc 1: r2 += -4             -- AbsFramePtr(-4)
   pc 2: r0 = 0
   pc 3: jeq r0 0 +1          -- branch to pc 5. At pc 5, merge:
                                  fall-through has r2=AbsFramePtr(-4),
                                  taken has r2=AbsFramePtr(-4) too
   pc 4: r2 = 0               -- r2 = AbsOther (only on fall-through)
   pc 5: store W64 [r2+0]     -- merged: r2 = join(AbsOther, AbsFramePtr(-4))
                                  = AbsOther, so check passes *)
let branch_program : bpf_program = [
  BPF_ALU64_REG MOV r2 r10;
  BPF_ALU64_IMM ADD r2 (-4l);
  BPF_ALU32_IMM MOV r0 0l;
  BPF_JMP64_IMM JEQ r0 0l 1;
  BPF_ALU64_IMM MOV r2 0l;
  BPF_ST W64 r2 0l 42l;
  BPF_ALU32_IMM MOV r0 0l;
  BPF_EXIT
]

let branch_test : squash (stack_bounds_check branch_program = true) =
  assert_norm (stack_bounds_check branch_program = true)
