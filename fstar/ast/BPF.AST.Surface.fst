(*
  BPF.AST.Surface — Unindexed surface AST

  Plain inductive types with no dependent indices. These are trivial to
  construct (from a code generator or by hand) and serve as input to the
  elaboration function in BPF.AST.Elaborate.

  The elaboration function walks a surface AST, infers types and variable
  contexts, and produces the corresponding indexed AST from BPF.AST.Expr
  and BPF.AST.Stmt. If elaboration succeeds, the programme is verified.

  Design:
  - Every constructor is prefixed with S to distinguish from indexed AST
  - No var_ctx, no c_type indices, no squash proofs
  - Option types for optional sub-expressions (e.g. return with/without value)
  - Helper calls carry the helper name as a string, resolved during elaboration
  - The structure mirrors BPF C source closely
*)
module BPF.AST.Surface

open BPF.AST.Types
open BPF.AST.Expr

(* --- Surface expressions --- *)

noeq
type s_expr =
  (* Literals *)
  | SIntLit : v:int -> w:int_width -> s_expr
  | SUIntLit : v:nat -> w:int_width -> s_expr
  | SBoolLit : v:bool -> s_expr

  (* Variable reference (by name) *)
  | SVarRef : name:string -> s_expr

  (* Binary operation *)
  | SBinOp : op:binop -> lhs:s_expr -> rhs:s_expr -> s_expr

  (* Unary operation *)
  | SUnaryOp : op:unaryop -> operand:s_expr -> s_expr

  (* Pointer dereference *)
  | SDeref : ptr:s_expr -> s_expr

  (* Address-of *)
  | SAddrOf : inner:s_expr -> s_expr

  (* Struct field access (base.field) *)
  | SFieldAccess : base:s_expr -> field:string -> s_expr

  (* Type cast *)
  | SCast : target:c_type -> inner:s_expr -> s_expr

  (* sizeof — evaluated to a constant *)
  | SSizeOf : size:nat -> s_expr

  (* Function call in expression position (helper name + args) *)
  | SCall : func:string -> args:list s_expr -> s_expr

(* --- Surface statements --- *)

noeq
type s_stmt =
  (* Variable declaration with optional initialiser *)
  | SDeclare : name:string -> ty:c_type -> init:option s_expr -> s_stmt

  (* Assignment: var = expr *)
  | SAssign : name:string -> value:s_expr -> s_stmt

  (* Sequential composition *)
  | SSeq : first:s_stmt -> second:s_stmt -> s_stmt

  (* Conditional *)
  | SIf : cond:s_expr -> then_branch:s_stmt -> else_branch:s_stmt -> s_stmt

  (* Return *)
  | SReturn : value:option s_expr -> s_stmt

  (* Helper call as a statement: var = helper(args) *)
  | SCallStmt : name:string -> func:string -> args:list s_expr -> s_stmt

  (* No-op *)
  | SNop : s_stmt

(* --- Surface programme --- *)

noeq
type s_prog = {
  sp_name : string;
  sp_section : string;
  sp_param_name : string;
  sp_body : s_stmt;
}
