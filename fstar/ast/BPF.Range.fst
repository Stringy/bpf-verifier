(*
  BPF.Range — Signed/unsigned range tracking

  The kernel verifier tracks four bounds for each scalar value:
    - umin_value, umax_value: unsigned 64-bit range [umin, umax]
    - smin_value, smax_value: signed 64-bit range [smin, smax]

  These constrain what concrete values a variable can hold.
  Cross-bound inference tightens one pair from the other when possible
  (e.g. if umax < 2^63 then the value is non-negative, so smin >= 0).

  Conditional branches refine ranges:
    - if (x < 100) → true branch: umax = 99
    - if (x > 0) signed → true branch: smin = 1
*)
module BPF.Range

open BPF.Integers
module U64 = FStar.UInt64

(* Signed 64-bit range bounds as mathematical integers.
   We use int (unbounded) for signed values to avoid modular confusion. *)
let s64_min : int = -(pow2 63)
let s64_max : int = pow2 63 - 1
let u64_max_val : nat = pow2 64 - 1

(* Well-formedness: min <= max for both signed and unsigned *)
let range_wf (umin umax:nat) (smin smax:int) : prop =
  umin <= umax /\
  umax <= u64_max_val /\
  umin <= u64_max_val /\
  smin <= smax /\
  smin >= s64_min /\
  smax <= s64_max

type range = r:(nat & nat & int & int){ let (umin, umax, smin, smax) = r in
  range_wf umin umax smin smax }

let mk_range (umin umax:nat) (smin smax:int)
  : Pure range
    (requires range_wf umin umax smin smax)
    (ensures fun _ -> True)
  = (umin, umax, smin, smax)

let range_umin (r:range) : nat = let (umin, _, _, _) = r in umin
let range_umax (r:range) : nat = let (_, umax, _, _) = r in umax
let range_smin (r:range) : int = let (_, _, smin, _) = r in smin
let range_smax (r:range) : int = let (_, _, _, smax) = r in smax

(* --- Constructors --- *)

(* A known constant value *)
let range_const (v:nat{v <= u64_max_val}) : range =
  let sv = if v >= pow2 63 then v - pow2 64 else v in
  mk_range v v sv sv

(* Fully unknown: any 64-bit value is possible *)
let range_unknown : range =
  mk_range 0 u64_max_val s64_min s64_max

(* Non-negative scalar (common after reading a u32 or after masking) *)
let range_u32 : range =
  mk_range 0 (pow2 32 - 1) 0 (pow2 32 - 1)

(* A single byte read: [0, 255] *)
let range_u8 : range =
  mk_range 0 255 0 255

(* --- Refinement from conditional branches --- *)

(*
  After an unsigned less-than check: if (x < bound)
  True branch: umax = bound - 1
  False branch: umin = bound
*)
let refine_ult_true (r:range) (bound:nat{bound > 0 /\ bound <= u64_max_val})
  : option range =
  let umin' = range_umin r in
  let umax' = if range_umax r >= bound then bound - 1 else range_umax r in
  if umin' > umax' then None  (* contradiction: range is empty *)
  else
    let smin' = range_smin r in
    let smax' = range_smax r in
    (* Cross-inference: if new umax < 2^63, value is non-negative *)
    let smin'' = if umax' < pow2 63 && smin' < 0 then 0 else smin' in
    let smax'' = if umax' < pow2 63 && smax' > umax' then umax' else smax' in
    if smin'' > smax'' then None
    else Some (mk_range umin' umax' smin'' smax'')

let refine_ult_false (r:range) (bound:nat{bound <= u64_max_val})
  : option range =
  let umin' = if range_umin r < bound then bound else range_umin r in
  let umax' = range_umax r in
  if umin' > umax' then None
  else Some (mk_range umin' umax' (range_smin r) (range_smax r))

(*
  After a signed greater-than check: if (x > sbound)
  True branch: smin = sbound + 1
  False branch: smax = sbound
*)
let refine_sgt_true (r:range) (sbound:int{sbound >= s64_min /\ sbound < s64_max})
  : option range =
  let smin' = if range_smin r <= sbound then sbound + 1 else range_smin r in
  let smax' = range_smax r in
  if smin' > smax' then None
  else
    (* Cross-inference: if smin >= 0, value is non-negative, so umin >= smin *)
    let umin' = if smin' >= 0 && range_umin r < smin' then smin' else range_umin r in
    let umax' = range_umax r in
    if umin' > umax' then None
    else Some (mk_range umin' umax' smin' smax')

let refine_sgt_false (r:range) (sbound:int{sbound >= s64_min /\ sbound <= s64_max})
  : option range =
  let smin' = range_smin r in
  let smax' = if range_smax r > sbound then sbound else range_smax r in
  if smin' > smax' then None
  else Some (mk_range (range_umin r) (range_umax r) smin' smax')

(*
  Equality check: if (x == v)
  True branch: range is exactly v
  False branch: original range (we don't narrow on !=, too imprecise)
*)
let refine_eq_true (r:range) (v:nat{v <= u64_max_val}) : option range =
  let umin' = range_umin r in
  let umax' = range_umax r in
  if v < umin' || v > umax' then None  (* v outside current range *)
  else Some (range_const v)

let refine_eq_false (r:range) (_v:nat{_v <= u64_max_val}) : range = r

(* --- Range arithmetic --- *)

(* Join two ranges: the smallest range containing both *)
let range_join (a b:range) : range =
  let umin' = if range_umin a <= range_umin b then range_umin a else range_umin b in
  let umax' = if range_umax a >= range_umax b then range_umax a else range_umax b in
  let smin' = if range_smin a <= range_smin b then range_smin a else range_smin b in
  let smax' = if range_smax a >= range_smax b then range_smax a else range_smax b in
  mk_range umin' umax' smin' smax'

(* --- Queries --- *)

(* Is a concrete value within the range? (unsigned interpretation) *)
let range_contains_u (r:range) (v:nat{v <= u64_max_val}) : bool =
  range_umin r <= v && v <= range_umax r

(* Is the range a single value? *)
let range_is_const (r:range) : bool =
  range_umin r = range_umax r

(* Is the value provably non-negative? *)
let range_is_non_negative (r:range) : bool =
  range_smin r >= 0

(* Is the value provably less than a bound? (useful for bounds checks) *)
let range_provably_lt (r:range) (bound:nat) : bool =
  range_umax r < bound

(* --- Properties --- *)

let range_const_is_const (v:nat{v <= u64_max_val})
  : Lemma (range_is_const (range_const v))
  = ()

let range_const_contains (v:nat{v <= u64_max_val})
  : Lemma (range_contains_u (range_const v) v)
  = ()

let range_join_contains_left (a b:range) (v:nat{v <= u64_max_val})
  : Lemma (requires range_contains_u a v)
          (ensures range_contains_u (range_join a b) v)
  = ()

let range_join_contains_right (a b:range) (v:nat{v <= u64_max_val})
  : Lemma (requires range_contains_u b v)
          (ensures range_contains_u (range_join a b) v)
  = ()
