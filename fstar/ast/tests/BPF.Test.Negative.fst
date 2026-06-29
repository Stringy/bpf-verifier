(*
  BPF.Test.Negative — Negative tests: programmes that MUST fail to typecheck

  Uses [@@expect_failure] to verify that ill-formed programmes are
  rejected by the type system. If any of these "succeed", it means
  our type system has a soundness hole.

  Tests:
  1. Reading an uninitialised variable
  2. Returning without setting the return value
  3. Constructing a Deref of CPtr_or_null (null-unsafe dereference)
*)
module BPF.Test.Negative

open BPF.AST.Types
open BPF.AST.Expr
open BPF.AST.Stmt
open BPF.VarCtx
open BPF.ValClass
open BPF.Helpers

(* --- Test 1: Reading an uninitialised variable --- *)

(* Context with an uninitialised variable *)
let ctx_with_uninit : var_ctx = declare [("ctx", PtrToCtx 0)] "x"

(* Verify x is declared but not readable *)
let _ : squash (is_declared ctx_with_uninit "x") = ()
let _ : squash (not (BPF.VarCtx.is_readable ctx_with_uninit "x")) = ()

(* Attempting to reference an uninitialised variable should fail.
   VarRef requires squash (is_readable ctx name). Since x is Uninit,
   is_readable returns false, and the squash proof is unprovable. *)
[@@expect_failure]
let bad_read_uninit : expr ctx_with_uninit c_u64 =
  VarRef "x" c_u64 ()

(* --- Test 2: Reading a variable that doesn't exist --- *)

let ctx_no_y : var_ctx = [("ctx", PtrToCtx 0)]

(* Variable "y" is not in context at all *)
[@@expect_failure]
let bad_read_missing : expr ctx_no_y c_u64 =
  VarRef "y" c_u64 ()

(* --- Test 3: Null-unsafe dereference --- *)

(* Suppose we have a variable that holds CPtr_or_null.
   Constructing a Deref expression for it requires CPtr, not CPtr_or_null.
   This should be a type error.

   Note: we can't directly test this at the expr level because Deref
   takes an expr indexed by CPtr, and there's no way to construct an
   expr of type CPtr_or_null that we can feed to Deref — the type
   indices prevent it. The test below tries to construct a Deref of
   CPtr_or_null and should fail. *)
[@@expect_failure]
let bad_null_deref (#ctx:var_ctx) (e:expr ctx (CPtr_or_null (CUInt W32)))
  : expr ctx (CUInt W32)
  = Deref e  (* CPtr_or_null ≠ CPtr — type error *)

(* --- Test 4: Return with unreleased references --- *)

(* A context with a socket reference that hasn't been released *)
let ctx_with_ref : var_ctx =
  [("sk", PtrToSocket 1); ("ctx", PtrToCtx 0)]

(* Verify the context has unreleased refs *)
let _ : squash (not (all_refs_released ctx_with_ref)) = ()

(* Attempting to return without releasing the socket should fail.
   Return requires squash (all_refs_released ctx). *)
[@@expect_failure]
let bad_return_with_ref : stmt ctx_with_ref [] =
  Return #ctx_with_ref (IntLit #ctx_with_ref 0 W32) ()
