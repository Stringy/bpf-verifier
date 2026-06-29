(* Test.LayeredProof -- end-to-end validation of the layered verification architecture.

   This is the architecture validation test. It proves a programme correct using
   the layered approach (stack bounds + safe executor) and compares it to the
   original monolithic verifier.

   The test programme stores 42 to the stack, loads it back, and returns it:
     r2 = r10           (copy frame pointer to r2)
     r2 += -8           (derive pointer to stack offset -8)
     store 42 at [r2+0] (write to stack)
     r0 = load [r2+0]   (read from stack)
     exit               (return r0 == 42)

   The three-step verification process:

   1. Stack bounds check: Prove statically that all stack accesses are within
      the 512-byte frame. This is done via normalisation of stack_bounds_check
      (a decidable boolean function) -- no SMT solver needed.

   2. Functional correctness via safe executor: Prove the programme produces
      the correct result using program_satisfies_safe with evidence_stack.
      The stack_safe flag tells the executor to skip runtime bounds checks,
      since step 1 proved them statically. The bpf_auto_layered tactic uses
      full normalisation to reduce the guarded executor to a deterministic
      trace, then invokes SMT to prove correctness.

   3. Comparison with original verifier: For validation, we also prove the
      same programme using the original program_satisfies (which includes
      bounds checks in the SMT formula). Both proofs should succeed, confirming
      that the layered approach is sound.

   If safe_proof succeeds, the entire architecture works end-to-end. If it
   fails while orig_proof succeeds, that's a BLOCKER -- the layered approach
   is broken and needs investigation.
*)
module Test.LayeredProof

open FStar.UInt64
open FStar.Int32
open FStar.Tactics.V2
open BPF.State
open BPF.Semantics
open BPF.Spec
open BPF.Verify
open BPF.Check.StackBounds
open BPF.Exec.Safe
open BPF.Tactic.Layered

(* Test programme: store 42 to stack, load it back, return it.

   Instruction breakdown:
   1. BPF_ALU64_REG MOV r2 r10
      Move r10 (frame pointer = FramePtr 0) to r2
      Abstract state: r2 becomes AbsFramePtr 0

   2. BPF_ALU64_IMM ADD r2 (-8l)
      Add -8 to r2 (frame pointer arithmetic)
      Abstract state: r2 becomes AbsFramePtr -8
      Stack bounds: -8 is within [-512, 0), so this is safe

   3. BPF_ST W64 r2 0l 42l
      Store immediate 42 at [r2 + 0] as a 64-bit value
      Effective offset: -8 + 0 = -8
      Stack bounds: offset -8, width 8 bytes -> range [-8, 0)
      This is the tightest possible fit (ends exactly at stack top)

   4. BPF_LDX W64 r0 r2 0l
      Load 64-bit value from [r2 + 0] into r0
      Effective offset: -8 + 0 = -8
      Stack bounds: same as above, safe

   5. BPF_EXIT
      Return (r0 holds the loaded value, which is 42)
*)
let test_program : bpf_program = [
  BPF_ALU64_REG MOV r2 r10;
  BPF_ALU64_IMM ADD r2 (-8l);
  BPF_ST W64 r2 0l 42l;
  BPF_LDX W64 r0 r2 0l;
  BPF_EXIT
]

(* Functional specification: the programme returns 42 in r0.

   post_only means no precondition -- the spec holds for any initial state.
   The postcondition checks that r0 holds the scalar value 42. *)
let test_spec : bpf_spec =
  post_only (fun st -> state_get_reg st r0 == Scalar 42uL)

(* Step 1: Stack bounds check passes.

   The stack_bounds_check function performs abstract interpretation over
   the instruction list, tracking frame pointer derivation and checking
   each memory access against the 512-byte stack bounds.

   assert_norm asks F* to normalise the expression at compile-time. For
   a concrete programme (known instruction list), F* evaluates the check
   function step-by-step and reduces it to `true`. The proof succeeds
   because `true == true` is trivial.

   If this fails, the programme has an out-of-bounds stack access and
   cannot use evidence_stack. *)
let sb_proof : squash (stack_bounds_check test_program = true) =
  assert_norm (stack_bounds_check test_program = true)

(* Step 2: Functional correctness via the safe executor.

   This uses program_satisfies_safe with evidence_stack, meaning the
   executor knows that all stack accesses are bounds-safe (proved above).

   The bpf_auto_layered tactic performs full delta normalisation, which:
   - Unfolds all function definitions (delta)
   - Evaluates pattern matches (iota)
   - Reduces let bindings (zeta)
   - Evaluates primitive operations (primops)

   For our programme, this normalisation reduces exec_program_safe to a
   deterministic sequence of register and memory operations, eliminating
   all the "if stack_safe then fast_path else checked_path" conditionals.
   The normalised form is a pure computation that SMT can verify.

   The z3rlimit is set to 60 (slightly higher than the default 20) to
   give Z3 enough budget to verify the normalised execution trace.

   If this proof fails while orig_proof succeeds, the layered architecture
   is broken -- report DONE_WITH_CONCERNS with full error output. *)
#push-options "--z3rlimit 60"
let safe_proof : squash (program_satisfies_safe test_program test_spec evidence_stack) =
  _ by (bpf_auto_layered ())
#pop-options

(* Step 3: For comparison, the original proof still works.

   This uses the original program_satisfies (not program_satisfies_safe),
   which uses exec_program from BPF.Semantics. The executor includes runtime
   bounds checks (stack_offset_valid in stack_load/stack_store), and the
   SMT solver must reason about those checks as part of the formula.

   Both safe_proof and orig_proof should succeed. If safe_proof fails but
   orig_proof succeeds, it's a blocker. If both fail, the programme or spec
   is wrong. If both succeed, the architecture is validated! *)
#push-options "--z3rlimit 60"
let orig_proof : squash (program_satisfies test_program test_spec) =
  _ by (bpf_auto_layered ())
#pop-options
