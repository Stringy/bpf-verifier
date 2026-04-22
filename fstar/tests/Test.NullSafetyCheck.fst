(* Test.NullSafetyCheck — validates the null pointer safety checker.

   This test ensures that `null_check` correctly distinguishes between
   programmes with proper null checks before map pointer dereferences and
   those that dereference unchecked pointers.

   The null safety checker performs forward abstract interpretation with
   branch-aware state tracking to verify that every map pointer returned
   by MAP_LOOKUP_ELEM is null-checked before being dereferenced. When
   bpf_map_lookup_elem returns a pointer in r0, that pointer could be
   either a valid map value pointer or null. The programme must branch
   on the result (e.g. "if r0 == 0 goto error") before dereferencing.

   We test two programmes:
   1. good_program: performs map lookup, null-checks via JEQ, and only
      dereferences on the non-null branch (standard pattern).
   2. bad_program: performs map lookup and immediately dereferences
      without a null check (unsafe).

   F* notes for BPF developers:
   - `assert_norm` is a compile-time assertion that F* evaluates by
     normalisation (reduction). If the expression doesn't reduce to the
     expected value, F* rejects the file at typecheck time.
   - The `l` suffix creates an Int32 literal (signed 32-bit), matching
     BPF's immediate operand encoding.
   - The `uL` suffix creates a UInt64 literal (unsigned 64-bit).
   - Register constants (r0, r1, r2, r10) are defined in BPF.State.
*)
module Test.NullSafetyCheck

open FStar.Int32
open BPF.State
open BPF.Semantics
open BPF.Check.NullSafety

(* A programme with proper null checking before dereference.
   This is the standard map lookup pattern:
   - Set up a key on the stack at [r10-4]
   - Call MAP_LOOKUP_ELEM with r1 = map fd, r2 = key address
   - r0 now holds the lookup result (Unchecked status)
   - Copy r0 to r1 (preserves Unchecked status)
   - Set default return value r0 = -1
   - Check if r1 == 0 (null check):
     * If r1 == 0 (jump target): r1 is IsNull, skip the load
     * If r1 != 0 (fall-through): r1 is Checked, safe to dereference
   - Load from [r1+0] on the non-null branch (r1 is Checked here)
   - Exit

   The null check at pc 8 (JEQ r1 0 +1) forks the abstract state:
   - Fall-through path: r1 becomes Checked, proceeds to pc 9 (load)
   - Jump target path: r1 becomes IsNull, proceeds to pc 10 (exit)
   The load at pc 9 is safe because r1 has Checked status.
*)
let good_program : bpf_program = [
  BPF_ALU32_IMM MOV r1 0l;          (* pc 0: key = 0 *)
  BPF_STX W32 r10 r1 (-4l);         (* pc 1: store key to stack at [r10-4] *)
  BPF_ALU64_REG MOV r2 r10;         (* pc 2: r2 = frame pointer *)
  BPF_ALU64_IMM ADD r2 (-4l);       (* pc 3: r2 = key address (r10-4) *)
  BPF_LD_IMM64 r1 0uL;              (* pc 4: r1 = map fd (0 for test) *)
  BPF_CALL MAP_LOOKUP_ELEM;         (* pc 5: r0 = map lookup result (Unchecked) *)
  BPF_ALU64_REG MOV r1 r0;          (* pc 6: r1 = lookup result (copies Unchecked) *)
  BPF_ALU32_IMM MOV r0 (-1l);       (* pc 7: default return = -1 *)
  BPF_JMP64_IMM JEQ r1 0l 1;        (* pc 8: if r1 == null, skip load (+1 offset)
                                       - Fall-through (r1 != 0): r1 -> Checked, go to pc 9
                                       - Jump target (r1 == 0): r1 -> IsNull, go to pc 10 *)
  BPF_LDX W32 r0 r1 0l;             (* pc 9: load from [r1+0] (r1 is Checked, safe) *)
  BPF_EXIT                          (* pc 10: exit *)
]

(* Verify that null_check accepts the good programme.
   F* will normalise `null_check good_program` at compile time and
   verify it reduces to `true`. *)
let good_test : squash (null_check good_program = true) =
  assert_norm (null_check good_program = true)

(* A programme that dereferences a map pointer without null checking.
   - Set up r1 = map fd (simplified, just use immediate)
   - Call MAP_LOOKUP_ELEM, r0 now holds result (Unchecked)
   - Directly load from [r0+0] without checking if r0 is null
   - Exit

   The load at pc 2 attempts to dereference r0, which still has
   Unchecked status (has not been null-checked). This violates null
   safety and the checker should reject the programme.
*)
let bad_program : bpf_program = [
  BPF_LD_IMM64 r1 0uL;              (* pc 0: r1 = map fd *)
  BPF_CALL MAP_LOOKUP_ELEM;         (* pc 1: r0 = map lookup result (Unchecked) *)
  BPF_LDX W32 r1 r0 0l;             (* pc 2: load from [r0+0] — r0 is still Unchecked! *)
  BPF_EXIT                          (* pc 3: exit *)
]

(* Verify that null_check rejects the bad programme.
   F* will normalise `null_check bad_program` at compile time and
   verify it reduces to `false`. *)
let bad_test : squash (null_check bad_program = false) =
  assert_norm (null_check bad_program = false)
