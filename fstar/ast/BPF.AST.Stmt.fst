(*
  BPF.AST.Stmt — Statement AST indexed by input and output variable context

  Statements transform the variable context. Each statement is indexed by
  (ctx_in, ctx_out) — the context before and after the statement executes.

  This is the DAG threading: information flows from earlier statements to
  later ones through the context index.

  - Seq chains contexts:  ctx1 → ctx2 → ctx3
  - If branches and joins: both arms see the same input context, the result
    is the join of both output contexts
  - Assign updates the context with the assigned variable's new classification
  - Return requires all references released and a valid return value
  - BoundedLoop: the loop body maps ctx → ctx, with a decreasing measure

  The key structural guarantees:
  - Uninitialised reads are impossible (VarRef in expr requires is_readable)
  - Null-unsafe derefs are impossible (Deref requires CPtr, not CPtr_or_null)
  - IfNull promotes CPtr_or_null → CPtr in the not-null branch
  - Return requires all acquired references to be released
*)
module BPF.AST.Stmt

open BPF.AST.Types
open BPF.AST.Expr
open BPF.VarCtx
open BPF.ValClass
open BPF.Helpers

(*
  Statement AST indexed by input context and output context.

  ctx_in:  what we know about variables before this statement
  ctx_out: what we know about variables after this statement
*)
noeq
type stmt : var_ctx -> var_ctx -> Type =

  (* Variable declaration: adds a new variable as Uninit *)
  | Declare : #ctx:var_ctx ->
              name:var_name ->
              t:c_type ->
              stmt ctx (declare ctx name)

  (* Assignment: evaluate expression, update variable's classification.
     The expression is well-typed in the current context. The variable's
     classification in the output context reflects the assigned value. *)
  | Assign : #ctx:var_ctx ->
             #t:c_type ->
             name:var_name ->
             value:expr ctx t ->
             vc:val_class{BPF.ValClass.is_readable vc} ->
             stmt ctx (assign ctx name vc)

  (* Sequential composition: thread the context through two statements *)
  | Seq : #ctx1:var_ctx ->
          #ctx2:var_ctx ->
          #ctx3:var_ctx ->
          first:stmt ctx1 ctx2 ->
          second:stmt ctx2 ctx3 ->
          stmt ctx1 ctx3

  (* Conditional: both branches see the same input context.
     The output context is the join of both branches. *)
  | If : #ctx:var_ctx ->
         #ctx_then:var_ctx ->
         #ctx_else:var_ctx ->
         cond:expr ctx CBool ->
         then_branch:stmt ctx ctx_then ->
         else_branch:stmt ctx ctx_else ->
         stmt ctx (join_ctx ctx_then ctx_else)

  (* Null check conditional: like If but with context refinement.
     In the not-null branch, the checked variable is promoted from
     PtrToMapValueOrNull/PtrToSocketOrNull to the concrete pointer type.
     In the null branch, the variable is demoted to scalar zero.

     This is the mechanism that makes null-unsafe derefs untypable:
     the only way to get a CPtr from a map lookup (which returns
     CPtr_or_null) is through this construct.

     The refined contexts are computed directly from the input context
     and the checked variable name, so F* can infer them without
     explicit squash proofs from the caller. *)
  | IfNull : #ctx:var_ctx ->
             checked_var:var_name ->
             squash (is_declared ctx checked_var) ->
             squash (needs_null_check (get_class ctx checked_var)) ->
             squash (Some? (refine_not_null ctx checked_var)) ->
             squash (Some? (refine_is_null ctx checked_var)) ->
             #ctx_then:var_ctx ->
             #ctx_else:var_ctx ->
             then_branch:stmt (Some?.v (refine_not_null ctx checked_var)) ctx_then ->
             else_branch:stmt (Some?.v (refine_is_null ctx checked_var)) ctx_else ->
             stmt ctx (join_ctx ctx_then ctx_else)

  (* Bounded loop: body maps ctx → ctx with a decreasing measure.
     The bound limits the maximum number of iterations.
     The loop condition is evaluated in the current context. *)
  | BoundedLoop : #ctx:var_ctx ->
                  bound:nat{bound > 0} ->
                  cond:expr ctx CBool ->
                  body:stmt ctx ctx ->
                  stmt ctx ctx

  (* Return: the programme exits. The return value must be a 32-bit int
     (BPF programmes always return int). All acquired references must
     have been released. *)
  | Return : #ctx:var_ctx ->
             value:expr ctx c_bpf_return ->
             squash (all_refs_released ctx) ->
             stmt ctx []  (* output context is empty — programme has exited *)

  (* No-op: identity on the context *)
  | Nop : #ctx:var_ctx ->
          stmt ctx ctx

  (* Helper function call as a statement (for side-effecting helpers
     like bpf_map_update_elem that don't just return a value).
     The return value is assigned to a variable. *)
  | CallAssign : #ctx:var_ctx ->
                 name:var_name ->
                 helper:helper_desc ->
                 args:list c_type ->
                 ret_vc:val_class{BPF.ValClass.is_readable ret_vc} ->
                 stmt ctx (assign ctx name ret_vc)
