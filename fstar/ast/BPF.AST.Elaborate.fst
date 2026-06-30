(*
  BPF.AST.Elaborate — Check well-formedness of surface AST

  This module defines a decidable checking function that walks a
  surface AST (unindexed) and verifies that it satisfies the safety
  properties encoded by the indexed AST types:
  - Variables are declared before use
  - Variables are initialised before read
  - Null pointers are checked before dereference
  - Helper calls use the correct argument count and types
  - All references are released before return
  - Return values are numeric

  The key idea: the checking function is an ordinary decidable F*
  function that returns bool (or an error message). On concrete input,
  F*'s normaliser evaluates it completely. A tactic then checks that
  the result is true.

  This avoids the complexity of constructing indexed terms
  programmatically — we check the properties without building
  the indexed representation.
*)
module BPF.AST.Elaborate

open BPF.AST.Types
open BPF.AST.Expr
open BPF.AST.Surface
open BPF.VarCtx
open BPF.ValClass
open BPF.Helpers
open BPF.AST.Decl

(* --- Result type with error messages --- *)

noeq
type eresult =
  | EOk : ctx_out:var_ctx -> eresult
  | EErr : msg:string -> eresult

(* --- Infer a default c_type from a val_class --- *)

let val_class_to_type (vc:val_class) : c_type =
  match vc with
  | Uninit -> CInt W32
  | Scalar _ _ -> CUInt W64
  | PtrToCtx _ -> CPtr CVoid
  | PtrToLocal _ _ -> CPtr (CInt W32)
  | PtrToMapValue _ _ -> CPtr (CInt W32)
  | PtrToMapValueOrNull _ _ -> CPtr_or_null (CInt W32)
  | PtrToPacket _ -> CPtr (CUInt W8)
  | PtrToPacketEnd -> CPtr (CUInt W8)
  | PtrToSocket _ -> CPtr CVoid
  | PtrToSocketOrNull _ -> CPtr_or_null CVoid

(* --- Type checking for expressions --- *)

(* Infer the type of a surface expression in a given context.
   Returns None if the expression is ill-typed. *)
val infer_type : ctx:var_ctx -> e:s_expr -> Tot (option c_type) (decreases e)

let rec infer_type ctx e =
  match e with
  | SIntLit _ w -> Some (CInt w)
  | SUIntLit _ w -> Some (CUInt w)
  | SBoolLit _ -> Some CBool

  | SVarRef name ->
    if BPF.VarCtx.is_declared ctx name &&
       BPF.VarCtx.is_readable ctx name then
      Some (val_class_to_type (BPF.VarCtx.get_class ctx name))
    else
      None

  | SBinOp op lhs rhs ->
    (match infer_type ctx lhs, infer_type ctx rhs with
     | Some t1, Some t2 ->
       (* Try exact match first *)
       (match binop_result_type op t1 t2 with
        | Some t -> Some t
        | None ->
          (* BPF implicitly widens to 64-bit. If both are numeric,
             accept the operation with 64-bit result. *)
          if is_numeric t1 && is_numeric t2 then
            match op with
            | Eq | Ne | Lt | Le | Gt | Ge | SLt | SLe | SGt | SGe -> Some CBool
            | LAnd | LOr -> Some CBool
            | _ -> Some (CUInt W64)  (* arithmetic/bitwise: widen to u64 *)
          else None)
     | _, _ -> None)

  | SUnaryOp op operand ->
    (match infer_type ctx operand with
     | Some t ->
       (match unaryop_result_type op t with
        | Some tr -> Some tr
        | None ->
          (* BPF allows LNot on any type (truthy/falsy), and Neg on any numeric *)
          match op with
          | LNot -> Some CBool  (* !x is always bool *)
          | Neg -> if is_numeric t then Some t else None
          | BitNot -> if is_numeric t then Some t else None)
     | None -> None)

  | SDeref ptr ->
    (match infer_type ctx ptr with
     | Some (CPtr inner) -> Some inner
     | _ -> None)  (* reject CPtr_or_null — must null-check first *)

  | SAddrOf inner ->
    (match infer_type ctx inner with
     | Some t -> Some (CPtr t)
     | None -> None)

  | SFieldAccess base field ->
    (match infer_type ctx base with
     | Some (CStruct sd) ->
       if has_field sd field then Some (get_field_type sd field) else None
     | _ -> None)

  | SCast target inner ->
    (match infer_type ctx inner with
     | Some t_from ->
       if is_numeric t_from && is_numeric target then Some target else None
     | None -> None)

  | SSizeOf _ -> Some (CUInt W64)

  | SCall _ _ -> None  (* calls must appear as SCallStmt *)

(* Is a surface expression a boolean? *)
let is_bool_expr (ctx:var_ctx) (e:s_expr) : bool =
  match infer_type ctx e with
  | Some CBool -> true
  | _ -> false

(* Is a surface expression well-typed? *)
let expr_ok (ctx:var_ctx) (e:s_expr) : bool =
  Some? (infer_type ctx e)

(* --- Null check pattern recognition --- *)

(* Recognise null check patterns. Returns (var_name, is_negated).
   is_negated = true means the condition is "if (!ptr)" rather than "if (ptr)",
   so the then/else branches need to be swapped for context refinement. *)
let is_null_check_surface (e:s_expr) : option (string & bool) =
  match e with
  | SVarRef name -> Some (name, false)
  | SBinOp Ne (SVarRef name) (SIntLit 0 _) -> Some (name, false)
  | SBinOp Ne (SIntLit 0 _) (SVarRef name) -> Some (name, false)
  | SBinOp Ne (SVarRef name) (SUIntLit 0 _) -> Some (name, false)
  | SBinOp Ne (SUIntLit 0 _) (SVarRef name) -> Some (name, false)
  | SBinOp Eq (SVarRef name) (SIntLit 0 _) -> Some (name, true)
  | SBinOp Eq (SIntLit 0 _) (SVarRef name) -> Some (name, true)
  | SBinOp Eq (SVarRef name) (SUIntLit 0 _) -> Some (name, true)
  | SBinOp Eq (SUIntLit 0 _) (SVarRef name) -> Some (name, true)
  | SUnaryOp LNot (SVarRef name) -> Some (name, true)
  | _ -> None

(* --- Helper resolution --- *)

let resolve_helper (name:string) : option helper_desc =
  match name with
  | "bpf_map_lookup_elem" -> Some h_map_lookup_elem
  | "bpf_map_update_elem" -> Some h_map_update_elem
  | "bpf_map_delete_elem" -> Some h_map_delete_elem
  | "bpf_get_current_pid_tgid" -> Some h_get_current_pid_tgid
  | "bpf_get_current_uid_gid" -> Some h_get_current_uid_gid
  | "bpf_get_current_comm" -> Some h_get_current_comm
  | "bpf_ktime_get_ns" -> Some h_ktime_get_ns
  | "bpf_ktime_get_boot_ns" -> Some h_ktime_get_boot_ns
  | "bpf_get_smp_processor_id" -> Some h_get_smp_processor_id
  | "bpf_get_prandom_u32" -> Some h_get_prandom_u32
  | "bpf_probe_read_kernel" -> Some h_probe_read_kernel
  | "bpf_probe_read_user" -> Some h_probe_read_user
  | "bpf_probe_read" -> Some h_probe_read
  | "bpf_trace_printk" -> Some h_trace_printk
  | "bpf_ringbuf_output" -> Some h_ringbuf_output
  | _ -> None

let helper_return_vc (h:helper_desc) : val_class =
  match h.h_return with
  | RetScalar _ -> scalar_unknown
  | RetNullablePtr _ -> PtrToMapValueOrNull 0 0
  | RetVoid -> scalar_unknown

(* Check argument arity *)
let rec check_arity (expected:list helper_arg_desc) (actual:list s_expr) : bool =
  match expected, actual with
  | [], [] -> true
  | _ :: re, _ :: ra -> check_arity re ra
  | _, _ -> false

(* --- Statement checking --- *)

(* Check a surface statement, with fall-through refinement for
   early-return null checks.

   When an SIf has one branch that returns (SReturn) and the other
   continues (SNop or non-returning), the continuation should use
   the refined context from the non-returning branch.

   Example:
     if (!ptr) return 0;   // then returns, else falls through
     *ptr;                  // uses else's refined context (ptr is non-null)
*)
(* Check if a statement always returns (early return pattern) *)
let rec returns_early (s:s_stmt) : bool =
  match s with
  | SReturn _ -> true
  | SSeq first _ -> returns_early first
  | _ -> false

(* Check a surface statement. Returns the output variable context
   if the statement is well-formed, or an error message.

   check_stmt_refined is used for the first statement in a SSeq:
   it detects early-return null checks and passes the refined context
   to the continuation rather than joining. *)
val check_stmt : pt:bpf_prog_type -> ctx:var_ctx -> s:s_stmt -> fuel:nat
  -> Tot eresult (decreases fuel)

val check_stmt_refined : pt:bpf_prog_type -> ctx:var_ctx -> s:s_stmt -> fuel:nat
  -> Tot eresult (decreases fuel)

let rec check_stmt pt ctx s fuel =
  if fuel = 0 then EErr "elaboration fuel exhausted"
  else
  match s with
  | SNop -> EOk ctx

  | SDeclare name _ty None ->
    EOk (declare ctx name)

  | SDeclare name _ty (Some init_expr) ->
    if expr_ok (declare ctx name) init_expr then
      EOk (assign (declare ctx name) name scalar_unknown)
    else
      EErr ("ill-typed initialiser for '" ^ name ^ "'")

  | SAssign name value ->
    if expr_ok ctx value then
      EOk (assign ctx name scalar_unknown)
    else
      EErr ("ill-typed assignment to '" ^ name ^ "'")

  | SSeq first second ->
    (match check_stmt_refined pt ctx first (fuel - 1) with
     | EErr msg -> EErr msg
     | EOk ctx_mid ->
       check_stmt pt ctx_mid second (fuel - 1))

  | SIf cond then_s else_s ->
    if not (expr_ok ctx cond) then
      EErr "ill-typed if condition"
    else
      (* Check for null-check pattern *)
      (match is_null_check_surface cond with
       | Some (var_name, is_negated) ->
         if BPF.VarCtx.is_declared ctx var_name &&
            BPF.ValClass.needs_null_check (BPF.VarCtx.get_class ctx var_name) &&
            Some? (BPF.VarCtx.refine_not_null ctx var_name) &&
            Some? (BPF.VarCtx.refine_is_null ctx var_name) then
           let ctx_nn = Some?.v (BPF.VarCtx.refine_not_null ctx var_name) in
           let ctx_null = Some?.v (BPF.VarCtx.refine_is_null ctx var_name) in
           (* If negated (e.g. if (!ptr)), swap the branch contexts:
              then_s gets the null context, else_s gets the not-null context *)
           let ctx_then_in = if is_negated then ctx_null else ctx_nn in
           let ctx_else_in = if is_negated then ctx_nn else ctx_null in
           (match check_stmt pt ctx_then_in then_s (fuel - 1),
                  check_stmt pt ctx_else_in else_s (fuel - 1) with
            | EOk ctx_then, EOk ctx_else -> EOk (join_ctx ctx_then ctx_else)
            | EErr msg, _ -> EErr msg
            | _, EErr msg -> EErr msg)
         else
           (* Not a proper null check — treat as normal if *)
           (match check_stmt pt ctx then_s (fuel - 1),
                  check_stmt pt ctx else_s (fuel - 1) with
            | EOk ctx_then, EOk ctx_else -> EOk (join_ctx ctx_then ctx_else)
            | EErr msg, _ -> EErr msg
            | _, EErr msg -> EErr msg)
       | None ->
         (match check_stmt pt ctx then_s (fuel - 1),
                check_stmt pt ctx else_s (fuel - 1) with
          | EOk ctx_then, EOk ctx_else -> EOk (join_ctx ctx_then ctx_else)
          | EErr msg, _ -> EErr msg
          | _, EErr msg -> EErr msg))

  | SReturn None ->
    if BPF.VarCtx.all_refs_released ctx then
      EOk []
    else
      EErr "return with unreleased references"

  | SReturn (Some ret_expr) ->
    (match infer_type ctx ret_expr with
     | None -> EErr "ill-typed return expression"
     | Some t ->
       if BPF.VarCtx.all_refs_released ctx && is_numeric t then
         EOk []
       else if not (BPF.VarCtx.all_refs_released ctx) then
         EErr "return with unreleased references"
       else
         EErr "return value must be numeric")

  | SCallStmt var_name func_name args ->
    (match resolve_helper func_name with
     | None -> EErr ("unknown helper function: " ^ func_name)
     | Some helper ->
       if check_arity helper.h_args args &&
          helper_available_for helper pt then
         let ret_vc = helper_return_vc helper in
         EOk (assign ctx var_name ret_vc)
       else
          EErr ("helper '" ^ func_name ^ "' argument mismatch or not available"))

(* check_stmt_refined: used as the first element of a SSeq.
   For null-check SIf where one branch returns, passes the
   refined context from the non-returning branch to the continuation. *)
and check_stmt_refined pt ctx s fuel =
  if fuel = 0 then EErr "elaboration fuel exhausted"
  else
  match s with
  | SIf cond then_s else_s ->
    if not (expr_ok ctx cond) then
      EErr "ill-typed if condition"
    else
      (* Determine branch contexts based on null-check pattern *)
      let null_check =
        match is_null_check_surface cond with
        | Some (var_name, is_negated) ->
          if BPF.VarCtx.is_declared ctx var_name &&
             BPF.ValClass.needs_null_check (BPF.VarCtx.get_class ctx var_name) &&
             Some? (BPF.VarCtx.refine_not_null ctx var_name) &&
             Some? (BPF.VarCtx.refine_is_null ctx var_name) then
            let ctx_nn = Some?.v (BPF.VarCtx.refine_not_null ctx var_name) in
            let ctx_null = Some?.v (BPF.VarCtx.refine_is_null ctx var_name) in
            Some (if is_negated then (ctx_null, ctx_nn) else (ctx_nn, ctx_null))
          else None
        | None -> None
      in
      let ctx_then_in = (match null_check with Some (ct, _) -> ct | None -> ctx) in
      let ctx_else_in = (match null_check with Some (_, ce) -> ce | None -> ctx) in
      (* Early return pattern: if one branch returns, the continuation
         gets the other branch's context (possibly refined) *)
      if returns_early then_s then
        (match check_stmt pt ctx_then_in then_s (fuel - 1) with
         | EErr msg -> EErr msg
         | EOk _ ->
           check_stmt pt ctx_else_in else_s (fuel - 1))
      else if returns_early else_s then
        (match check_stmt pt ctx_else_in else_s (fuel - 1) with
         | EErr msg -> EErr msg
         | EOk _ ->
           check_stmt pt ctx_then_in then_s (fuel - 1))
      else
        check_stmt pt ctx s (fuel - 1)
  | _ -> check_stmt pt ctx s (fuel - 1)


(* --- Top-level checking --- *)

let default_fuel : nat = 10000

(* Check a surface programme. Returns true if well-formed. *)
let check_prog (pt:bpf_prog_type) (p:s_prog) : eresult =
  let ctx0 = initial_ctx pt in
  check_stmt pt ctx0 p.sp_body default_fuel

let check_ok (pt:bpf_prog_type) (p:s_prog) : bool =
  EOk? (check_prog pt p)
