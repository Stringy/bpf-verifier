(* BPF.Tactic — proof tactics for BPF programme verification.

   Two proof strategies depending on programme characteristics:

   bpf_auto_pure: For programmes without non-determinism (no map
   lookups). Uses full delta normalisation — F* evaluates the entire
   execution, leaving Z3 with a trivial equality. Very fast, scales
   to 100+ instructions.

   bpf_auto_map: For programmes with map lookups (non-deterministic
   results). Uses selective delta_namespace normalisation that keeps
   FStar.Pervasives (option type) opaque so Z3 can reason about both
   branches of a null check. Slower but handles non-determinism.

   The Rust codegen chooses which tactic to emit based on whether the
   programme contains BPF_CALL instructions. *)
module BPF.Tactic

open FStar.Tactics.V2
open FStar.Reflection.V2.Formula
open FStar.List.Tot
open BPF.State
open BPF.Semantics
open BPF.Spec
open BPF.Verify

(* Extract a structured counterexample from the normalised goal.
   Peels through squash/forall/implies to find the postcondition,
   then classifies it as an equality, disjunction, or complex term.
   Emits a COUNTEREXAMPLE line to stderr for Rust to parse.

   After normalisation, the goal is:
     squash (forall (init: bpf_state). pre ==> post)
   term_as_formula unsquashes, then the forall body may appear as
   an App (lambda applied to bound var) rather than a direct Forall,
   so we also peel through lambdas via inspect. *)
let rec extract_post_term (t: term) : Tac formula =
  match inspect t with
  | Tv_Abs _binder body -> extract_post_term body
  | _ -> extract_post (term_as_formula' t)

and extract_post (f: formula) : Tac formula =
  match f with
  | Forall _ _ body -> extract_post_term body
  | Implies _ rhs -> extract_post (term_as_formula' rhs)
  | App fn _arg -> extract_post_term fn
  | _ -> f

let rec collect_or_eqs (f: formula) : Tac (list (term & term)) =
  match f with
  | Or l r ->
    let left = collect_or_eqs (term_as_formula' l) in
    let right = collect_or_eqs (term_as_formula' r) in
    left @ right
  | Comp (Eq _) lhs rhs -> [(lhs, rhs)]
  | _ -> []

let extract_counterexample () : Tac unit =
  let goal = cur_goal () in
  let f = term_as_formula goal in
  let post = extract_post f in
  match post with
  | Comp (Eq _) lhs rhs ->
    print ("COUNTEREXAMPLE|eq|" ^ term_to_string lhs ^ "|" ^ term_to_string rhs)
  | Or _ _ ->
    let pairs = collect_or_eqs post in
    begin match pairs with
    | [] ->
      print ("COUNTEREXAMPLE|complex|" ^ formula_to_string post)
    | _ ->
      let (first_lhs, _) = List.Tot.hd pairs in
      let rhs_strs = Tactics.Util.map (fun (_, r) -> term_to_string r) pairs in
      print ("COUNTEREXAMPLE|or|" ^ term_to_string first_lhs ^ "|" ^
             String.concat "," rhs_strs)
    end
  | _ ->
    print ("COUNTEREXAMPLE|complex|" ^ formula_to_string post)

(* Postcondition diagnosis — walks the normalised goal to emit each
   conjunct separately. The Rust diagnostic parses these to display
   ALL postcondition requirements, not just the one F* pointed at.

   For a goal like `(r0 == 0 /\ count == 2) \/ (r0 == 1)`, emits:
     CONJUNCT|0|r0 == 0
     CONJUNCT|0|count == 2
     CONJUNCT|1|r0 == 1
   where the number is the disjunct index (0 = success path). *)

(* Replace newlines with spaces so each CONJUNCT stays on one line. *)
let flatten_string (s: string) : string =
  String.concat " " (String.split ['\n'] s)

let conjunct_to_string (f: formula) : Tac string =
  flatten_string (formula_to_string f)

let rec collect_conjuncts (f: formula) : Tac (list string) =
  match f with
  | And l r ->
    let left = collect_conjuncts (term_as_formula' l) in
    let right = collect_conjuncts (term_as_formula' r) in
    left @ right
  | _ -> [conjunct_to_string f]

let rec emit_disjuncts (f: formula) (idx: int) : Tac int =
  match f with
  | Or l r ->
    let idx' = emit_disjuncts (term_as_formula' l) idx in
    emit_disjuncts (term_as_formula' r) idx'
  | _ ->
    let conjuncts = collect_conjuncts f in
    let idx_str = string_of_int idx in
    Tactics.Util.iter
      (fun c -> print ("CONJUNCT|" ^ idx_str ^ "|" ^ c))
      conjuncts;
    idx + 1

let diagnose_conjuncts () : Tac unit =
  let goal = cur_goal () in
  let f = term_as_formula goal in
  let post = extract_post f in
  let _ = emit_disjuncts post 0 in
  ()

(* Full delta normalisation — unfolds everything. Fast and complete
   for deterministic programmes. Breaks on non-determinism because
   option constructors get over-normalised. *)
let bpf_auto_pure () : Tac unit =
  norm [nbe; delta; iota; zeta; primops];
  dump "NORMALISED_GOAL";
  extract_counterexample ();
  diagnose_conjuncts ();
  smt ()

(* Selective normalisation — unfolds BPF semantics and F* integer
   types but keeps option/pervasives opaque. Handles non-deterministic
   programmes (map lookups) but is slower because some terms remain
   symbolic for Z3 to process. *)
let bpf_auto_map () : Tac unit =
  norm [nbe; delta_namespace ["BPF"; "Verify_"; "Prims";
                         "FStar.UInt64"; "FStar.UInt32"; "FStar.UInt8"; "FStar.UInt";
                         "FStar.Int32"; "FStar.Int64"; "FStar.Int";
                         "FStar.Int.Cast"; "FStar.Int.Cast.Full";
                         "FStar.List.Tot"];
        iota; zeta; primops];
  dump "NORMALISED_GOAL";
  extract_counterexample ();
  diagnose_conjuncts ();
  smt ()
