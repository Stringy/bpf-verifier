(* Test.ExecSafe — validates guarded executor properties.

   This test file verifies two critical properties of the guarded executor:

   1. Equivalence: exec_insn_safe with evidence_none produces the same result
      as exec_insn. This proves that when no safety evidence is available,
      the guarded executor behaves identically to the original executor.

   2. Guard reduction: exec_insn_safe with evidence_stack produces the same
      result as exec_insn for a bounds-safe programme. This is the CRITICAL
      test — it validates that F*'s normaliser can reduce "if true then fast_path"
      to just "fast_path" and eliminate the conditional entirely.

   Both tests use `assert_norm`, which asks F* to normalise the left and right
   sides of the equality and check they reduce to the same term. If F* can't
   prove the equality by normalisation alone, the verification fails.

   The guard_test is the key validation for the entire architecture. If it
   fails, it means F*'s normaliser isn't eliminating the stack_safe guards,
   and the "verified fast path" approach doesn't work.

   F* notes:
   - `assert_norm` is a compile-time check — F* evaluates the assertion during
     type-checking, not at runtime. If the terms don't normalise to equal values,
     the file won't compile.
   - `squash` turns a proposition (type) into a unit value — we use it here to
     give the test a type signature.
*)
module Test.ExecSafe

open FStar.UInt64
open FStar.Int32
open BPF.State
open BPF.Semantics
open BPF.Exec.Safe

(* A test state with a valid stack slot at offset -4.
   - r10 = FramePtr 0 (frame pointer, always initialised to top of stack)
   - r2 = FramePtr (-4) (a derived pointer pointing 4 bytes into the stack)
   - stack contains a W32 (4-byte) slot at offset -4 with value 42

   This models a typical BPF programme pattern:
     r2 = r10
     r2 += -4
     store u32 at [r2 + 0], value 42
     load u32 from [r2 + 0] into r0
*)
let test_state : bpf_state = {
  regs = set_reg (set_reg (fun _ -> Scalar 0uL) r10 (FramePtr 0)) r2 (FramePtr (-4));
  pc = 0;
  stack = [{ offset = -4; width = W32; value = 42uL }];
  map_values = [];
  next_map_id = 0;
}

(* A valid stack load instruction: LDX W32 r0 r2 0
   This loads a 4-byte value from [r2 + 0]:
   - r2 = FramePtr(-4), so r2 + 0 = offset -4
   - The stack has a W32 slot at offset -4, so the load succeeds
   - The load returns 42uL and writes it to r0
*)
let test_insn : bpf_insn = BPF_LDX W32 r0 r2 0l

(* Equivalence test: with evidence_none, exec_insn_safe == exec_insn.

   Since evidence_none has stack_safe = false, exec_insn_safe falls back
   to the checked path (stack_load). This is identical to exec_insn, so
   both functions should produce the same result.

   If this test fails, the guarded executor has diverged from the original
   semantics even when all guards are disabled — that's a fundamental bug.
*)
let equiv_test : squash (exec_insn_safe test_state test_insn evidence_none
                         == exec_insn test_state test_insn) =
  assert_norm (exec_insn_safe test_state test_insn evidence_none
               == exec_insn test_state test_insn)

(* Guard reduction test: with evidence_stack, same result for valid access.

   Since evidence_stack has stack_safe = true, exec_insn_safe skips the
   stack_offset_valid check and calls stack_read directly. For a bounds-safe
   access, this should produce the same result as the checked path.

   This is the CRITICAL validation. If F*'s normaliser can't reduce the guard:
     if ev.stack_safe then stack_read ... else stack_load ...
   to just:
     stack_read ...
   then the entire "verified fast path" architecture fails. The test proves
   that normalisation eliminates the conditional, producing identical results
   for exec_insn_safe and exec_insn.

   If this test fails, report back with DONE_WITH_CONCERNS and include the
   full F* error output — it's a blocker for the guarded executor approach.
*)
let guard_test : squash (exec_insn_safe test_state test_insn evidence_stack
                         == exec_insn test_state test_insn) =
  assert_norm (exec_insn_safe test_state test_insn evidence_stack
               == exec_insn test_state test_insn)
