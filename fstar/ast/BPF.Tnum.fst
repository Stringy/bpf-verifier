(*
  BPF.Tnum — Tristate number abstract domain

  A tnum (tracked number) tracks known bits of a 64-bit value.
  Each bit is in one of three states:
    - Known to be 0: mask bit = 0, value bit = 0
    - Known to be 1: mask bit = 0, value bit = 1
    - Unknown:       mask bit = 1, value bit = 0

  Invariant: mask & value = 0 (no bit is both unknown and known-1)

  This mirrors the kernel's struct tnum from include/linux/tnum.h.
*)
module BPF.Tnum

open BPF.Integers
module U64 = FStar.UInt64
module U32 = FStar.UInt32
module UInt = FStar.UInt

(* The tnum invariant: mask and value have no overlapping bits *)
let tnum_wf (mask value:u64) : prop =
  U64.v (U64.logand mask value) = 0

(* The tnum type with its well-formedness invariant *)
type tnum = p:( u64 & u64 ){ tnum_wf (fst p) (snd p) }

let mk_tnum (mask value:u64)
  : Pure tnum
    (requires tnum_wf mask value)
    (ensures fun _ -> True)
  = (mask, value)

let tnum_mask (t:tnum) : u64 = fst t
let tnum_value (t:tnum) : u64 = snd t

(* Helper: zero AND anything is zero *)
let logand_zero_left (x:u64)
  : Lemma (U64.v (U64.logand 0uL x) = 0)
  = UInt.logand_le (U64.v 0uL) (U64.v x)

(* Helper: anything AND zero is zero *)
let logand_zero_right (x:u64)
  : Lemma (U64.v (U64.logand x 0uL) = 0)
  = UInt.logand_le (U64.v x) (U64.v 0uL);
    UInt.logand_commutative (U64.v x) (U64.v 0uL)

(* --- Constructors --- *)

(* Fully known constant: mask = 0 *)
let tnum_const (v:u64) : tnum =
  logand_zero_left v;
  (0uL, v)

(* Fully unknown: mask = all 1s, value = 0 *)
let tnum_unknown : tnum =
  let m = U64.lognot 0uL in
  logand_zero_right m;
  assert (tnum_wf m 0uL);
  (m, 0uL)

(* Unknown value in range [0, 2^n - 1] — low n bits unknown, rest known-0 *)
let tnum_range (n:nat{n <= 64}) : tnum =
  if n = 0 then tnum_const 0uL
  else if n = 64 then tnum_unknown
  else begin
    let mask = U64.sub_mod (U64.shift_left 1uL (U32.uint_to_t n)) 1uL in
    logand_zero_right mask;
    (mask, 0uL)
  end

(* --- Queries --- *)

(* Is the tnum a known constant? (all bits known) *)
let tnum_is_const (t:tnum) : bool =
  tnum_mask t = 0uL

(* Minimum possible value: unknown bits = 0 *)
let tnum_min (t:tnum) : u64 = tnum_value t

(* Maximum possible value: unknown bits = 1 *)
let tnum_max (t:tnum) : u64 =
  U64.logor (tnum_mask t) (tnum_value t)

(* Can the represented value be zero? *)
let tnum_can_be_zero (t:tnum) : bool =
  tnum_value t = 0uL

(* Number of unknown bits *)
(* For now we just check if any are unknown *)
let tnum_has_unknowns (t:tnum) : bool =
  tnum_mask t <> 0uL

(* --- Intersection / refinement --- *)

(*
  Prove that intersecting two well-formed tnums yields a well-formed tnum.

  Bit-level argument: for each bit i,
    (am & bm)[i] && (av | bv)[i]
    = (am[i] && bm[i]) && (av[i] || bv[i])

  If am[i]=1 and bm[i]=1 (both unknown):
    tnum_wf a means av[i]=0, tnum_wf b means bv[i]=0
    → (true && true) && (false || false) = false
  If am[i]=0 or bm[i]=0:
    → (am[i] && bm[i]) = false → whole expression false

  So the result is 0 for every bit.
*)
#push-options "--z3rlimit 100 --fuel 0 --ifuel 0"
let intersect_wf (am av bm bv:u64)
  : Lemma (requires tnum_wf am av /\ tnum_wf bm bv)
          (ensures tnum_wf (U64.logand am bm) (U64.logor av bv))
  = UInt.nth_lemma #64
      (U64.v (U64.logand (U64.logand am bm) (U64.logor av bv)))
      0
#pop-options

(*
  Intersect two tnums: the result represents only values compatible with both.
  Used when branch conditions provide additional information about a variable.

  Returns None if the tnums are contradictory (the known bits disagree).
*)
let tnum_intersect (a b:tnum) : option tnum =
  let (am, av) = a in
  let (bm, bv) = b in
  (* Bits known in both must agree *)
  let both_known = U64.lognot (U64.logor am bm) in
  let disagree = U64.logand both_known (U64.logxor av bv) in
  if disagree <> 0uL then None
  else begin
    let m = U64.logand am bm in
    let v = U64.logor av bv in
    intersect_wf am av bm bv;
    Some (m, v)
  end

(* --- Properties --- *)

(* A constant tnum has no unknown bits *)
let tnum_const_is_const (v:u64)
  : Lemma (tnum_is_const (tnum_const v))
  = ()

(* The minimum of a constant is itself *)
let tnum_const_min (v:u64)
  : Lemma (tnum_min (tnum_const v) = v)
  = ()

(* The maximum of a constant is itself: logor 0 v = v *)
let tnum_const_max (v:u64)
  : Lemma (tnum_max (tnum_const v) = v)
  = UInt.logor_commutative (U64.v 0uL) (U64.v v);
    UInt.logor_lemma_1 (U64.v v)

(* Unknown tnum can be zero *)
let tnum_unknown_can_be_zero ()
  : Lemma (tnum_can_be_zero tnum_unknown)
  = ()
