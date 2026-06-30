(*
  BPF.Test.Surface — Tests for the surface AST elaboration

  These tests construct surface AST values and verify them via
  normalisation of the check_ok function. If a test module
  type-checks, the programme passed verification.
*)
module BPF.Test.Surface

open BPF.AST.Types
open BPF.AST.Expr
open BPF.AST.Surface
open BPF.AST.Elaborate
open BPF.AST.Tactic

(* --- Test 1: return 7 ---
   int return_const(void *ctx) { return 7; }
*)
let test_return_const : s_prog = {
  sp_name = "return_const";
  sp_section = "test";
  sp_param_name = "ctx";
  sp_body = SReturn (Some (SIntLit 7 W32));
}

let _ : squash (check_ok ProgSocketFilter test_return_const == true) =
  _ by (ast_check_tac ())

(* --- Test 2: declare and return ---
   int test(void *ctx) { int x = 42; return x; }
*)
let test_declare_return : s_prog = {
  sp_name = "test_declare_return";
  sp_section = "test";
  sp_param_name = "ctx";
  sp_body = SSeq
    (SDeclare "x" (CInt W32) (Some (SIntLit 42 W32)))
    (SReturn (Some (SVarRef "x")));
}

let _ : squash (check_ok ProgSocketFilter test_declare_return == true) =
  _ by (ast_check_tac ())

(* --- Test 3: if-else ---
   int test(void *ctx) { int x = 1; if (x) { return 1; } else { return 0; } }
*)
let test_if_else : s_prog = {
  sp_name = "test_if_else";
  sp_section = "test";
  sp_param_name = "ctx";
  sp_body = SSeq
    (SDeclare "x" (CInt W32) (Some (SIntLit 1 W32)))
    (SIf (SVarRef "x")
      (SReturn (Some (SIntLit 1 W32)))
      (SReturn (Some (SIntLit 0 W32))));
}

(* Note: SVarRef "x" has type CUInt W64 (scalar_unknown), not CBool.
   The checker accepts it because expr_ok passes (it's a valid expression).
   The condition doesn't need to be strictly CBool for our checker —
   any well-typed expression in condition position is accepted. *)
let _ : squash (check_ok ProgSocketFilter test_if_else == true) =
  _ by (ast_check_tac ())

(* --- Test 4: helper call ---
   int test(void *ctx) {
     __u64 pid = bpf_get_current_pid_tgid();
     return 0;
   }
*)
let test_helper_call : s_prog = {
  sp_name = "test_helper_call";
  sp_section = "test";
  sp_param_name = "ctx";
  sp_body = SSeq
    (SCallStmt "pid" "bpf_get_current_pid_tgid" [])
    (SReturn (Some (SIntLit 0 W32)));
}

let _ : squash (check_ok ProgSocketFilter test_helper_call == true) =
  _ by (ast_check_tac ())

(* --- Test 5: uninitialised read should fail ---
   int test(void *ctx) { int x; return x; }
*)
let test_uninit_read : s_prog = {
  sp_name = "test_uninit_read";
  sp_section = "test";
  sp_param_name = "ctx";
  sp_body = SSeq
    (SDeclare "x" (CInt W32) None)
    (SReturn (Some (SVarRef "x")));
}

(* This should fail — x is declared but not initialised *)
let _ : squash (check_ok ProgSocketFilter test_uninit_read == false) =
  _ by (ast_check_tac ())

(* --- Test 6: undeclared variable should fail ---
   int test(void *ctx) { return y; }
*)
let test_undeclared : s_prog = {
  sp_name = "test_undeclared";
  sp_section = "test";
  sp_param_name = "ctx";
  sp_body = SReturn (Some (SVarRef "y"));
}

let _ : squash (check_ok ProgSocketFilter test_undeclared == false) =
  _ by (ast_check_tac ())
