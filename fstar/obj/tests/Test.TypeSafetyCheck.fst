(* Test.TypeSafetyCheck — validates the type safety checker.

   This test ensures that `type_check` correctly distinguishes between
   programmes with valid type usage and those with type errors.

   The type safety checker performs forward abstract interpretation to track
   the abstract type of each register (scalar, frame pointer, map pointer,
   null, or unknown) and verifies that instructions receive operands of the
   correct type.

   We test two programmes:
   1. good_program: performs valid scalar arithmetic (MOV immediate to r0,
      ADD immediate to r0, then exit). All operands are scalars, which is
      valid for ALU operations.
   2. bad_program: attempts to ADD two frame pointers (r2 and r10). Frame
      pointers are not scalar types, so ADD with two pointer operands is
      a type error. The kernel's BPF verifier allows pointer+scalar (offset
      arithmetic) but not pointer+pointer.

   F* notes for BPF developers:
   - `assert_norm` is a compile-time assertion that F* evaluates by
     normalisation (reduction). If the expression doesn't reduce to the
     expected value, F* rejects the file at typecheck time.
   - The `l` suffix creates an Int32 literal (signed 32-bit), matching
     BPF's immediate operand encoding.
   - Register constants (r0, r2, r10) are defined in BPF.State.
   - `squash` is a proof-irrelevance wrapper -- it says "we only care that
     this proposition is true, not how it's proved". It's used here to
     make the test result type-check cleanly.
*)
module Test.TypeSafetyCheck

open FStar.Int32
open BPF.State
open BPF.Semantics
open BPF.Check.TypeSafety

(* A programme with valid type usage.
   - Move immediate 1 into r0 (r0 = TScalar)
   - Add immediate 2 to r0 (r0 = TScalar + 2, still TScalar)
   - Exit

   All ALU operations use scalar operands, which is correct.
*)
let good_program : bpf_program = [
  BPF_ALU64_IMM MOV r0 1l;          // r0 = 1 (scalar)
  BPF_ALU64_IMM ADD r0 2l;          // r0 += 2 (scalar arithmetic)
  BPF_EXIT
]

(* Verify that type_check accepts the good programme.
   F* will normalise `type_check good_program` at compile time
   and verify it reduces to `true`. *)
let good_test : squash (type_check good_program = true) =
  assert_norm (type_check good_program = true)

(* A programme with a type error.
   - Copy r10 (frame pointer) to r2 (r2 = TFramePtr)
   - ADD r2 and r10 (both TFramePtr) — TYPE ERROR
   - Exit

   The ADD operation receives two frame pointers, but ALU operations
   (other than MOV) require scalar operands. The is_scalar_type predicate
   returns false for TFramePtr, so this programme is rejected.

   Note: The kernel allows pointer+scalar (e.g., r2 = r10 + offset) because
   that's necessary for stack addressing. But pointer+pointer makes no sense
   and is forbidden.
*)
let bad_program : bpf_program = [
  BPF_ALU64_REG MOV r2 r10;         // r2 = r10 (copy frame pointer)
  BPF_ALU64_REG ADD r2 r10;         // ADD TFramePtr TFramePtr — TYPE ERROR
  BPF_EXIT
]

(* Verify that type_check rejects the bad programme.
   F* will normalise `type_check bad_program` at compile time
   and verify it reduces to `false`. *)
let bad_test : squash (type_check bad_program = false) =
  assert_norm (type_check bad_program = false)
