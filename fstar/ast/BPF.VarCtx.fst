(*
  BPF.VarCtx — Variable typing context

  A variable context maps variable names to their current value classification.
  This is the C-level analogue of the kernel verifier's register file: instead
  of tracking R0–R10, we track named variables.

  The context is threaded through statements as an index, establishing the
  DAG of information flow. Each statement transforms a context, and downstream
  statements inherit the guarantees established by upstream ones.

  We also track a ghost set of acquired reference IDs for reference tracking
  (sockets, map elements that need release before programme exit).
*)
module BPF.VarCtx

open BPF.ValClass

(* Variable name *)
type var_name = string

(* A single binding: variable name and its current classification *)
type binding = var_name & val_class

(* The variable context is an association list.
   We use a list rather than a map for simplicity in the F* type system —
   list is a well-understood inductive type with straightforward structural
   recursion. *)
type var_ctx = list binding

(* --- Lookup --- *)

(* Find a variable's classification in the context.
   Returns None if the variable is not declared. *)
let rec lookup (ctx:var_ctx) (name:var_name)
  : Tot (option val_class) (decreases ctx)
  = match ctx with
  | [] -> None
  | (n, vc) :: rest ->
    if n = name then Some vc
    else lookup rest name

(* Is a variable declared in the context? *)
let is_declared (ctx:var_ctx) (name:var_name) : bool =
  Some? (lookup ctx name)

(* Is a variable readable (declared and not Uninit)? *)
let is_readable (ctx:var_ctx) (name:var_name) : bool =
  match lookup ctx name with
  | Some vc -> ValClass.is_readable vc
  | None -> false

(* Get the classification of a variable known to be declared *)
let get_class (ctx:var_ctx) (name:var_name{is_declared ctx name}) : val_class =
  Some?.v (lookup ctx name)

(* --- Modification --- *)

(* Update a variable's classification. If the variable exists, replace its
   classification. If it doesn't exist, add it. *)
let rec update (ctx:var_ctx) (name:var_name) (vc:val_class)
  : Tot var_ctx (decreases ctx)
  = match ctx with
  | [] -> [(name, vc)]
  | (n, old_vc) :: rest ->
    if n = name then (n, vc) :: rest
    else (n, old_vc) :: update rest name vc

(* Declare a new variable with Uninit classification *)
let declare (ctx:var_ctx) (name:var_name) : var_ctx =
  update ctx name Uninit

(* Assign a value to a variable (must already be declared or will be added) *)
let assign (ctx:var_ctx) (name:var_name) (vc:val_class) : var_ctx =
  update ctx name vc

(* --- Context join at branch merge points --- *)

(*
  Join two contexts from different branches of an If.
  For each variable present in both:
    - join their value classifications (via join_val_class)
    - if incompatible (join returns None), the variable becomes Uninit
  Variables present in only one branch are dropped (conservative).

  This is an over-approximation: the result context is weaker than either
  input, which is sound for verification.
*)
let rec join_ctx (ctx1 ctx2:var_ctx)
  : Tot var_ctx (decreases ctx1)
  = match ctx1 with
  | [] -> []
  | (name, vc1) :: rest ->
    let joined_rest = join_ctx rest ctx2 in
    match lookup ctx2 name with
    | None -> joined_rest  (* variable only in one branch: drop *)
    | Some vc2 ->
      match join_val_class vc1 vc2 with
      | Some vc_joined -> (name, vc_joined) :: joined_rest
      | None -> (name, Uninit) :: joined_rest  (* incompatible: mark uninit *)

(* --- Reference tracking --- *)

(* Collect all ref_ids from reference-counted variables in the context *)
let rec collect_refs (ctx:var_ctx) : Tot (list ref_id) (decreases ctx) =
  match ctx with
  | [] -> []
  | (_, vc) :: rest ->
    if is_refcounted vc
    then get_ref_id vc :: collect_refs rest
    else collect_refs rest

(* Are all references released? (no refcounted variables in context) *)
let all_refs_released (ctx:var_ctx) : bool =
  match collect_refs ctx with
  | [] -> true
  | _ -> false

(* --- Context for null-check refinement --- *)

(*
  Refine the context after a null check on a variable.
  In the true branch (variable != NULL), promote _OR_NULL to concrete pointer.
  In the false branch (variable == NULL), demote to scalar zero.
*)
let refine_not_null (ctx:var_ctx) (name:var_name)
  : option var_ctx  (* None if variable not found or not _OR_NULL *)
  = match lookup ctx name with
  | Some vc ->
    if needs_null_check vc
    then Some (update ctx name (promote_after_null_check vc))
    else None
  | None -> None

let refine_is_null (ctx:var_ctx) (name:var_name)
  : option var_ctx
  = match lookup ctx name with
  | Some vc ->
    if needs_null_check vc
    then Some (update ctx name (demote_after_null_check vc))
    else None
  | None -> None

(* --- Properties --- *)

(* Looking up in an updated context returns the new value *)
let rec lookup_update (ctx:var_ctx) (name:var_name) (vc:val_class)
  : Lemma (ensures lookup (update ctx name vc) name == Some vc)
          (decreases ctx)
  = match ctx with
  | [] -> ()
  | (n, _) :: rest ->
    if n = name then ()
    else lookup_update rest name vc

(* Updating doesn't affect other variables *)
let rec lookup_update_other (ctx:var_ctx) (name1 name2:var_name) (vc:val_class)
  : Lemma (requires name1 <> name2)
          (ensures lookup (update ctx name1 vc) name2 == lookup ctx name2)
          (decreases ctx)
  = match ctx with
  | [] -> ()
  | (n, _) :: rest ->
    if n = name1 then ()
    else lookup_update_other rest name1 name2 vc

(* A declared variable is still declared after updating another variable *)
let update_preserves_declared (ctx:var_ctx) (name1 name2:var_name) (vc:val_class)
  : Lemma (requires name1 <> name2 /\ is_declared ctx name2)
          (ensures is_declared (update ctx name1 vc) name2)
  = lookup_update_other ctx name1 name2 vc

(* After assignment, the variable is readable (unless assigned Uninit) *)
let assign_readable (ctx:var_ctx) (name:var_name) (vc:val_class)
  : Lemma (requires ValClass.is_readable vc)
          (ensures is_readable (assign ctx name vc) name)
  = lookup_update ctx name vc

(* After null-check promotion, the variable is dereferenceable *)
let refine_not_null_deref_safe (ctx:var_ctx) (name:var_name)
  : Lemma (requires Some? (refine_not_null ctx name))
          (ensures (let Some ctx' = refine_not_null ctx name in
                    is_declared ctx' name /\
                    is_deref_safe (get_class ctx' name)))
  = let Some vc = lookup ctx name in
    promoted_is_deref_safe vc;
    lookup_update ctx name (promote_after_null_check vc)
