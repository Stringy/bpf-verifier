(* Test.StackBoundsCheck — validates the stack bounds checker.

   This test ensures that `stack_bounds_check` correctly distinguishes
   between programmes with valid stack accesses and those with out-of-bounds
   accesses.

   The stack bounds checker performs forward abstract interpretation to track
   which registers hold derived frame pointers (offsets from r10) and verifies
   that all memory accesses through frame pointers fall within the 512-byte
   stack region.

   We test two programmes:
   1. good_program: stores a 32-bit value at offset -4 from r10, which is
      valid (effective offset = -4, width = 4 bytes, index = 512-4 = 508,
      end = 508+4 = 512, which is exactly at the stack boundary).
   2. bad_program: stores a 64-bit value at offset 0 from r10, which is
      out-of-bounds (effective offset = 0, width = 8 bytes, index = 512+0 = 512,
      end = 512+8 = 520 > 512, which exceeds the stack).

   F* notes for BPF developers:
   - `assert_norm` is a compile-time assertion that F* evaluates by
     normalisation (reduction). If the expression doesn't reduce to `true`,
     F* rejects the file at typecheck time.
   - The `l` suffix creates an Int32 literal (signed 32-bit), matching
     BPF's immediate operand encoding.
   - Register constants (r0, r2, r10) are defined in BPF.State.
*)
module Test.StackBoundsCheck

open FStar.Int32
open BPF.State
open BPF.Semantics
open BPF.Check.StackBounds

(* A programme with valid stack access.
   - Copy r10 (frame pointer) to r2
   - Add -4 to r2 (now r2 = FramePtr(-4))
   - Store 32-bit immediate 42 at [r2+0], effective offset = -4
   - Set r0 = 0 (return value)
   - Exit

   The store at offset -4 with W32 (4 bytes) is valid:
   index = 512 + (-4) = 508
   end = 508 + 4 = 512 (exactly at the boundary, valid)
*)
let good_program : bpf_program = [
  BPF_ALU64_REG MOV r2 r10;         // r2 = r10 (copy frame pointer)
  BPF_ALU64_IMM ADD r2 (-4l);       // r2 += -4 (derive stack pointer)
  BPF_ST W32 r2 0l 42l;             // store 42 (W32) at [r2+0]
  BPF_ALU32_IMM MOV r0 0l;          // r0 = 0 (return success)
  BPF_EXIT
]

(* Verify that stack_bounds_check accepts the good programme.
   F* will normalise `stack_bounds_check good_program` at compile time
   and verify it reduces to `true`. *)
let good_test : squash (stack_bounds_check good_program = true) =
  assert_norm (stack_bounds_check good_program = true)

(* A programme with out-of-bounds stack access.
   - Copy r10 (frame pointer) to r2
   - Store 64-bit immediate 42 at [r2+0], effective offset = 0
   - Set r0 = 0
   - Exit

   The store at offset 0 with W64 (8 bytes) is out-of-bounds:
   index = 512 + 0 = 512
   end = 512 + 8 = 520 > 512 (exceeds stack size, invalid)
*)
let bad_program : bpf_program = [
  BPF_ALU64_REG MOV r2 r10;         // r2 = r10 (copy frame pointer)
  BPF_ST W64 r2 0l 42l;             // store 42 (W64) at [r2+0] — OUT OF BOUNDS
  BPF_ALU32_IMM MOV r0 0l;          // r0 = 0
  BPF_EXIT
]

(* Verify that stack_bounds_check rejects the bad programme.
   F* will normalise `stack_bounds_check bad_program` at compile time
   and verify it reduces to `false`. *)
let bad_test : squash (stack_bounds_check bad_program = false) =
  assert_norm (stack_bounds_check bad_program = false)
