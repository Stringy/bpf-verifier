(*
  BPF.AST.Elaborate — Elaborate surface AST into indexed AST

  This module defines a decidable elaboration function that walks a
  surface AST (unindexed) and constructs the corresponding indexed AST
  from BPF.AST.Expr and BPF.AST.Stmt.

  The key idea: the elaboration function is an ordinary F* function
  (not a tactic). On concrete input, F*'s normaliser evaluates it
  completely — producing either Some (the indexed term) or None (type
  error). A tactic then checks that the result is Some.

  This gives us:
  - Trivial code generation (just emit surface constructors)
  - Full soundness (the indexed term is intrinsically typed)
  - Good error diagnostics (we can return error messages with None)
*)
module BPF.AST.Elaborate

open BPF.AST.Types
open BPF.AST.Expr
open BPF.AST.Stmt
open BPF.AST.Surface
open BPF.VarCtx
open BPF.ValClass
open BPF.Helpers

(* --- Result type with error messages --- *)

(* We use a simple result type so that elaboration failures carry
   a diagnostic string. On success, we return the elaborated term
   along with any computed indices (type, output context, etc.). *)
type eresult (a:Type) =
  | EOk : v:a -> eresult a
  | EErr : msg:string -> eresult a

let ebind (#a #b:Type) (x:eresult a) (f:a -> eresult b) : eresult b =
  match x with
  | EOk v -> f v
  | EErr msg -> EErr msg

(* --- Infer a default c_type from a val_class --- *)

val val_class_to_type : val_class -> c_type
let val_class_to_type vc =
  match vc with
  | Uninit -> CInt W32  (* shouldn't be reached — Uninit is not readable *)
  | Scalar _ _ -> CUInt W64  (* scalars are 64-bit in BPF *)
  | PtrToCtx _ -> CPtr (CStruct { struct_name = "bpf_ctx"; fields = [] })
  | PtrToLocal _ _ -> CPtr (CInt W32)  (* approximate *)
  | PtrToMapValue _ _ -> CPtr (CInt W32)  (* approximate *)
  | PtrToMapValueOrNull _ _ -> CPtr_or_null (CInt W32)
  | PtrToPacket _ -> CPtr (CUInt W8)
  | PtrToPacketEnd -> CPtr (CUInt W8)
  | PtrToSocket _ -> CPtr (CStruct { struct_name = "bpf_sock"; fields = [] })
  | PtrToSocketOrNull _ -> CPtr_or_null (CStruct { struct_name = "bpf_sock"; fields = [] })

(* --- Expression elaboration --- *)

(* Elaborate a surface expression into an indexed expression.
   Returns the inferred type along with the expression. *)
val elab_expr : ctx:var_ctx -> e:s_expr
  -> Tot (eresult (t:c_type & expr ctx t))
         (decreases e)

let rec elab_expr ctx e =
  match e with
  | SIntLit v w ->
    EOk (| CInt w, IntLit v w |)

  | SUIntLit v w ->
    EOk (| CUInt w, UIntLit v w |)

  | SBoolLit v ->
    EOk (| CBool, BoolLit v |)

  | SVarRef name ->
    if BPF.VarCtx.is_declared ctx name then
      if BPF.VarCtx.is_readable ctx name then
        (* We need a type for the variable. Look up its val_class and
           pick a compatible c_type. *)
        let vc = BPF.VarCtx.get_class ctx name in
        let t = val_class_to_type vc in
        if BPF.VarCtx.var_type_compatible ctx name t then
          EOk (| t, VarRef name t () () |)
        else
          EErr ("variable '" ^ name ^ "' has incompatible type")
      else
        EErr ("variable '" ^ name ^ "' is not readable (uninitialised)")
    else
      EErr ("variable '" ^ name ^ "' is not declared")

  | SBinOp op lhs rhs ->
    (match elab_expr ctx lhs, elab_expr ctx rhs with
     | EErr msg, _ -> EErr msg
     | _, EErr msg -> EErr msg
     | EOk (| t1, e1 |), EOk (| t2, e2 |) ->
       match binop_result_type op t1 t2 with
       | Some tr -> EOk (| tr, BinOp op e1 e2 () |)
       | None -> EErr "type mismatch in binary operation")

  | SUnaryOp op operand ->
    (match elab_expr ctx operand with
     | EErr msg -> EErr msg
     | EOk (| t, inner |) ->
       match unaryop_result_type op t with
       | Some tr -> EOk (| tr, UnaryOp op inner () |)
       | None -> EErr "type mismatch in unary operation")

  | SDeref ptr ->
    (match elab_expr ctx ptr with
     | EErr msg -> EErr msg
     | EOk (| CPtr t_inner, e_ptr |) -> EOk (| t_inner, Deref e_ptr |)
     | EOk (| CPtr_or_null _, _ |) -> EErr "dereferencing a possibly-null pointer — add a null check"
     | EOk _ -> EErr "dereferencing a non-pointer")

  | SAddrOf inner ->
    (match elab_expr ctx inner with
     | EErr msg -> EErr msg
     | EOk (| t, e_inner |) ->
       EOk (| CPtr t, AddrOf e_inner |))

  | SFieldAccess base field ->
    (match elab_expr ctx base with
     | EErr msg -> EErr msg
     | EOk (| CStruct sd, e_base |) ->
       if has_field sd field then
         EOk (| get_field_type sd field, FieldAccess e_base field |)
       else
         EErr ("struct '" ^ sd.struct_name ^ "' has no field '" ^ field ^ "'")
     | EOk _ -> EErr "field access on non-struct type")

  | SCast target inner ->
    (match elab_expr ctx inner with
     | EErr msg -> EErr msg
     | EOk (| t_from, e_inner |) ->
       if is_numeric t_from && is_numeric target then
         EOk (| target, Cast target e_inner |)
       else
         EErr "cast between non-numeric types")

  | SSizeOf size ->
    EOk (| CUInt W64, SizeOf (CUInt W8) |)  (* sizeof returns u64; type arg is placeholder *)

  | SCall _ _ ->
    (* Function calls in expression position are not supported in the
       indexed AST — they must appear as SCallStmt at the statement level.
       The emitter should never produce SCall in expression position. *)
    EErr "function call in expression position — use SCallStmt instead"


(* --- Helper resolution --- *)

(* Map a C helper function name to its helper_desc.
   Returns None for unknown helpers. *)
val resolve_helper : string -> option helper_desc
let resolve_helper name =
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

(* Determine the val_class for a helper's return value *)
val helper_return_vc : helper_desc -> val_class
let helper_return_vc h =
  match h.h_return with
  | RetScalar _ -> scalar_unknown
  | RetNullablePtr _ -> PtrToMapValueOrNull 0 0
  | RetVoid -> scalar_unknown  (* void returns are modelled as scalar 0 *)

(* Collect the expected argument types from a helper *)
val helper_arg_types : helper_desc -> list c_type
let helper_arg_types h =
  List.Tot.map (fun (a:helper_arg_desc) -> a.arg_type) h.h_args

(* Check that a list of surface expression types matches helper args *)
val check_arg_types : list c_type -> list c_type -> bool
let rec check_arg_types expected actual =
  match expected, actual with
  | [], [] -> true
  | _ :: rest_e, _ :: rest_a -> check_arg_types rest_e rest_a
  (* For now, accept any type match — we just check arity *)
  | _, _ -> false


(* --- Null check pattern recognition --- *)

(* Recognise common null-check patterns in the surface AST:
   - SVarRef name (truthy check)
   - SBinOp Ne (SVarRef name) (SIntLit 0 _) or reverse
   - SBinOp Ne (SVarRef name) (SUIntLit 0 _) or reverse *)
val is_null_check_surface : s_expr -> option string
let is_null_check_surface e =
  match e with
  | SVarRef name -> Some name
  | SBinOp Ne (SVarRef name) (SIntLit 0 _) -> Some name
  | SBinOp Ne (SIntLit 0 _) (SVarRef name) -> Some name
  | SBinOp Ne (SVarRef name) (SUIntLit 0 _) -> Some name
  | SBinOp Ne (SUIntLit 0 _) (SVarRef name) -> Some name
  | _ -> None

(* --- Statement elaboration --- *)

(* Elaborate a surface statement into an indexed statement.
   Returns the output context along with the statement.

   Note: we need a fuel parameter because F* can't prove termination
   of the mutual recursion between elab_stmt and the list processing
   in SSeq chains. In practice, programmes are finite and the fuel
   is generous. *)
val elab_stmt : pt:bpf_prog_type -> ctx:var_ctx -> s:s_stmt -> fuel:nat
  -> Tot (eresult (ctx_out:var_ctx & stmt pt ctx ctx_out))
         (decreases fuel)

let rec elab_stmt pt ctx s fuel =
  if fuel = 0 then EErr "elaboration fuel exhausted"
  else
  match s with
  | SNop ->
    EOk (| ctx, Nop |)

  | SDeclare name ty None ->
    EOk (| declare ctx name, Declare name ty |)

  | SDeclare name ty (Some init_expr) ->
    let ctx1 = declare ctx name in
    (match elab_expr ctx1 init_expr with
     | EErr msg -> EErr msg
     | EOk (| _t, e |) ->
       let vc = scalar_unknown in
       EOk (| assign ctx1 name vc,
              Seq (Declare name ty) (Assign name e vc) |))

  | SAssign name value ->
    (match elab_expr ctx value with
     | EErr msg -> EErr msg
     | EOk (| _t, e |) ->
       let vc = scalar_unknown in
       EOk (| assign ctx name vc,
              Assign name e vc |))

  | SSeq first second ->
    (match elab_stmt pt ctx first (fuel - 1) with
     | EErr msg -> EErr msg
     | EOk (| ctx_mid, s1 |) ->
       match elab_stmt pt ctx_mid second (fuel - 1) with
       | EErr msg -> EErr msg
       | EOk (| ctx_out, s2 |) ->
         EOk (| ctx_out, Seq s1 s2 |))

  | SIf cond then_s else_s ->
    (match elab_expr ctx cond with
     | EErr msg -> EErr msg
     | EOk (| t_cond, e_cond |) ->
       match is_null_check_surface cond with
       | Some var_name ->
         if BPF.VarCtx.is_declared ctx var_name &&
            BPF.ValClass.needs_null_check (BPF.VarCtx.get_class ctx var_name) &&
            Some? (BPF.VarCtx.refine_not_null ctx var_name) &&
            Some? (BPF.VarCtx.refine_is_null ctx var_name) then
           let ctx_nn = Some?.v (BPF.VarCtx.refine_not_null ctx var_name) in
           let ctx_null = Some?.v (BPF.VarCtx.refine_is_null ctx var_name) in
           (match elab_stmt pt ctx_nn then_s (fuel - 1) with
            | EErr msg -> EErr msg
            | EOk (| ctx_then, s_then |) ->
              match elab_stmt pt ctx_null else_s (fuel - 1) with
              | EErr msg -> EErr msg
              | EOk (| ctx_else, s_else |) ->
                EOk (| join_ctx ctx_then ctx_else,
                       IfNull var_name () () () () s_then s_else |))
         else
           elab_if pt ctx e_cond t_cond then_s else_s fuel
       | None ->
         elab_if pt ctx e_cond t_cond then_s else_s fuel)

  | SReturn None ->
    if BPF.VarCtx.all_refs_released ctx then
      EOk (| [], Return (IntLit 0 W32) () |)
    else
      EErr "return with unreleased references"

  | SReturn (Some ret_expr) ->
    (match elab_expr ctx ret_expr with
     | EErr msg -> EErr msg
     | EOk (| t, e |) ->
       if BPF.VarCtx.all_refs_released ctx then
         if t = c_bpf_return then
           EOk (| [], Return e () |)
         else if is_numeric t then
           EOk (| [], Return (Cast c_bpf_return e) () |)
         else
           EErr "return value must be a numeric type"
       else
         EErr "return with unreleased references")

  | SCallStmt var_name func_name args ->
    (match resolve_helper func_name with
     | None -> EErr ("unknown helper function: " ^ func_name)
     | Some helper ->
       let ret_vc = helper_return_vc helper in
       match elab_arg_types ctx args with
       | EErr msg -> EErr msg
       | EOk actual_types ->
         if args_match_helper helper.h_args actual_types &&
            helper_available_for helper pt then
           EOk (| assign ctx var_name ret_vc,
                  CallAssign var_name helper actual_types () ret_vc |)
         else
           EErr ("helper '" ^ func_name ^ "' argument mismatch or not available"))

(* Elaborate a normal (non-null-check) If *)
and elab_if (pt:bpf_prog_type) (ctx:var_ctx)
            (e_cond:expr ctx CBool) (t_cond:c_type)
            (then_s else_s:s_stmt) (fuel:nat{fuel > 0})
  : Tot (eresult (ctx_out:var_ctx & stmt pt ctx ctx_out))
        (decreases fuel)
  =
  if t_cond = CBool then
    (match elab_stmt pt ctx then_s (fuel - 1) with
     | EErr msg -> EErr msg
     | EOk (| ctx_then, s_then |) ->
       match elab_stmt pt ctx else_s (fuel - 1) with
       | EErr msg -> EErr msg
       | EOk (| ctx_else, s_else |) ->
         EOk (| join_ctx ctx_then ctx_else,
                If e_cond s_then s_else |))
  else
    EErr "if condition must be boolean"

(* Elaborate a list of argument expressions, collecting their types *)
and elab_arg_types (ctx:var_ctx) (args:list s_expr)
  : Tot (eresult (list c_type))
        (decreases args)
  = match args with
    | [] -> EOk []
    | a :: rest ->
      match elab_expr ctx a with
      | EErr msg -> EErr msg
      | EOk (| t, _ |) ->
        match elab_arg_types ctx rest with
        | EErr msg -> EErr msg
        | EOk rest_types -> EOk (t :: rest_types)


(* --- Top-level elaboration --- *)

(* Default elaboration fuel — generous enough for any reasonable programme *)
let default_fuel : nat = 10000

(* Elaborate a surface programme into an indexed bpf_prog *)
val elab_prog : pt:bpf_prog_type -> p:s_prog
  -> eresult (stmt pt (initial_ctx pt) [])
let elab_prog pt p =
  let ctx0 = initial_ctx pt in
  elab_stmt pt ctx0 p.sp_body default_fuel

(* Convenience: check that elaboration succeeds *)
val elab_ok : bpf_prog_type -> s_prog -> bool
let elab_ok pt p =
  EOk? (elab_prog pt p)
