(*
  BPF.AST.Expr — Expression AST indexed by variable context and result type

  Expressions are indexed by two things:
  1. The variable context (var_ctx) — what variables are in scope
  2. The C type the expression produces (c_type)

  This dual indexing means:
  - VarRef can only reference variables that exist in the context
  - Deref requires a CPtr (not CPtr_or_null) — null-unsafe derefs are untypable
  - BinOp produces the correct result type for the operation
  - MapLookup always produces CPtr_or_null — the caller must null-check
  - FieldAccess requires the field to exist in the struct

  The context parameter is read-only in expressions — expressions don't modify
  state. Only statements (assignments, declarations) modify the context.
*)
module BPF.AST.Expr

open BPF.AST.Types
open BPF.VarCtx
open BPF.ValClass

(* Binary operators *)
type binop =
  | Add | Sub | Mul | Div | Mod      (* arithmetic *)
  | BitAnd | BitOr | BitXor          (* bitwise *)
  | ShiftL | ShiftR                   (* shifts *)
  | Eq | Ne                           (* equality *)
  | Lt | Le | Gt | Ge                 (* unsigned comparison *)
  | SLt | SLe | SGt | SGe            (* signed comparison *)
  | LAnd | LOr                        (* logical *)

(* Unary operators *)
type unaryop =
  | Neg         (* arithmetic negation *)
  | BitNot      (* bitwise complement *)
  | LNot        (* logical not *)

(* Result type of a binary operation *)
let binop_result_type (op:binop) (t1 t2:c_type) : option c_type =
  match op with
  (* Arithmetic: both operands must be same integer type, result is same type *)
  | Add | Sub | Mul | Div | Mod ->
    begin match t1, t2 with
    | CUInt w1, CUInt w2 -> if w1 = w2 then Some (CUInt w1) else None
    | CInt w1, CInt w2 -> if w1 = w2 then Some (CInt w1) else None
    | _, _ -> None
    end

  (* Bitwise: same integer type *)
  | BitAnd | BitOr | BitXor ->
    begin match t1, t2 with
    | CUInt w1, CUInt w2 -> if w1 = w2 then Some (CUInt w1) else None
    | CInt w1, CInt w2 -> if w1 = w2 then Some (CInt w1) else None
    | _, _ -> None
    end

  (* Shifts: left operand is the value type, right is the shift amount *)
  | ShiftL | ShiftR ->
    begin match t1, t2 with
    | CUInt w1, CUInt _ -> Some (CUInt w1)
    | CInt w1, CUInt _ -> Some (CInt w1)
    | _, _ -> None
    end

  (* Comparison: both operands same numeric type, result is bool *)
  | Eq | Ne | Lt | Le | Gt | Ge | SLt | SLe | SGt | SGe ->
    if is_numeric t1 && is_numeric t2 then Some CBool
    else if is_ptr t1 && is_ptr t2 then Some CBool  (* pointer comparison *)
    else None

  (* Logical: both bools, result is bool *)
  | LAnd | LOr ->
    begin match t1, t2 with
    | CBool, CBool -> Some CBool
    | _, _ -> None
    end

(* Result type of a unary operation *)
let unaryop_result_type (op:unaryop) (t:c_type) : option c_type =
  match op with
  | Neg ->
    begin match t with
    | CInt w -> Some (CInt w)
    | CUInt w -> Some (CUInt w)
    | _ -> None
    end
  | BitNot ->
    begin match t with
    | CInt w -> Some (CInt w)
    | CUInt w -> Some (CUInt w)
    | _ -> None
    end
  | LNot ->
    begin match t with
    | CBool -> Some CBool
    | _ -> None
    end

(* Helper function signature for BPF helper calls.
   Simplified: we model helpers as having a name, argument types, and
   a return type. The return type may be CPtr_or_null for lookup helpers. *)
noeq
type helper_sig = {
  helper_name : string;
  helper_args : list c_type;
  helper_ret  : c_type;
}

(*
  The expression AST.

  Indexed by:
  - ctx : var_ctx — the variables in scope (read-only, expressions don't modify state)
  - t   : c_type  — the type this expression produces

  Each constructor's type index enforces well-formedness:
  - VarRef requires the variable to be in context and readable
  - Deref requires CPtr (not CPtr_or_null) — null-safety by construction
  - BinOp requires the operation to be type-correct
  - FieldAccess requires the field to exist in the struct
*)
noeq
type expr : var_ctx -> c_type -> Type =

  (* Integer literal *)
  | IntLit : #ctx:var_ctx ->
             v:int ->
             w:int_width ->
             expr ctx (CInt w)

  (* Unsigned integer literal *)
  | UIntLit : #ctx:var_ctx ->
              v:nat ->
              w:int_width ->
              expr ctx (CUInt w)

  (* Boolean literal *)
  | BoolLit : #ctx:var_ctx ->
              v:bool ->
              expr ctx CBool

  (* Variable reference: the variable must be in context and readable *)
  | VarRef : #ctx:var_ctx ->
             name:var_name ->
             t:c_type ->
             squash (BPF.VarCtx.is_readable ctx name) ->
             expr ctx t

  (* Binary operation: both operands must type-check, and the operation
     must be valid for those types *)
  | BinOp : #ctx:var_ctx ->
            #t1:c_type ->
            #t2:c_type ->
            #tr:c_type ->
            op:binop ->
            lhs:expr ctx t1 ->
            rhs:expr ctx t2 ->
            squash (binop_result_type op t1 t2 == Some tr) ->
            expr ctx tr

  (* Unary operation *)
  | UnaryOp : #ctx:var_ctx ->
              #t:c_type ->
              #tr:c_type ->
              op:unaryop ->
              operand:expr ctx t ->
              squash (unaryop_result_type op t == Some tr) ->
              expr ctx tr

  (* Pointer dereference: requires CPtr, NOT CPtr_or_null.
     This is where null-safety is enforced structurally —
     you cannot dereference a CPtr_or_null. The only way to get
     a CPtr from a CPtr_or_null is through a null check in an If
     statement, which refines the variable context. *)
  | Deref : #ctx:var_ctx ->
            #t:c_type ->
            ptr:expr ctx (CPtr t) ->
            expr ctx t

  (* Address-of: take the address of a dereferenceable expression *)
  | AddrOf : #ctx:var_ctx ->
             #t:c_type ->
             inner:expr ctx t ->
             expr ctx (CPtr t)

  (* Struct field access: the field must exist in the struct *)
  | FieldAccess : #ctx:var_ctx ->
                  #sd:struct_def ->
                  obj:expr ctx (CStruct sd) ->
                  field:field_name{has_field sd field} ->
                  expr ctx (get_field_type sd field)

  (* Type cast between numeric types *)
  | Cast : #ctx:var_ctx ->
           #t_from:c_type{is_numeric t_from} ->
           t_to:c_type{is_numeric t_to} ->
           inner:expr ctx t_from ->
           expr ctx t_to

  (* Array indexing: arr[idx] — index must be an unsigned integer *)
  | ArrayIndex : #ctx:var_ctx ->
                 #elem_t:c_type ->
                 #n:nat ->
                 arr:expr ctx (CArray elem_t n) ->
                 idx:expr ctx (CUInt W64) ->
                 expr ctx elem_t

  (* Sizeof expression: returns the size of a type as a constant *)
  | SizeOf : #ctx:var_ctx ->
             t:c_type ->
             expr ctx (CUInt W64)
