(*
  BPF.Integers — Machine integer model for BPF verification

  BPF operates on 64-bit and 32-bit integers with specific semantics:
  - Overflow/underflow wraps (modular arithmetic)
  - Division by zero returns 0 (not UB, not a trap)
  - Modulo by zero leaves the value unchanged (64-bit) or zeroes upper 32 bits (32-bit)
  - Signed division: LLONG_MIN / -1 = LLONG_MIN (no overflow trap)
  - Shift amounts are masked: & 63 for 64-bit, & 31 for 32-bit
  - 32-bit ALU results zero-extend into the full 64-bit register

  We use mathematical integers (F*'s unbounded int/nat) for specifications and
  reasoning, with FStar.UInt64 and FStar.UInt32 for the concrete representations.
*)
module BPF.Integers

open FStar.UInt64
open FStar.UInt32

(* Abbreviations for readability *)
let u64 = FStar.UInt64.t
let u32 = FStar.UInt32.t

let u64_v = FStar.UInt64.v
let u32_v = FStar.UInt32.v

let u64_max : nat = pow2 64 - 1
let u32_max : nat = pow2 32 - 1

(* --- 64-bit arithmetic with BPF semantics --- *)

(* Addition: wraps on overflow *)
let add64 (a b:u64) : u64 = FStar.UInt64.add_mod a b

(* Subtraction: wraps on underflow *)
let sub64 (a b:u64) : u64 = FStar.UInt64.sub_mod a b

(* Multiplication: wraps *)
let mul64 (a b:u64) : u64 = FStar.UInt64.mul_mod a b

(*
  Division by zero: BPF returns 0 (unlike C which is UB).
  We model this explicitly rather than requiring a non-zero divisor.
*)
let div64 (a b:u64) : u64 =
  if b = 0uL then 0uL
  else FStar.UInt64.div a b

(*
  Modulo by zero: BPF leaves the dividend unchanged (64-bit).
*)
let mod64 (a b:u64) : u64 =
  if b = 0uL then a
  else FStar.UInt64.rem a b

(* Bitwise operations *)
let and64 (a b:u64) : u64 = FStar.UInt64.logand a b
let or64 (a b:u64) : u64 = FStar.UInt64.logor a b
let xor64 (a b:u64) : u64 = FStar.UInt64.logxor a b
let not64 (a:u64) : u64 = FStar.UInt64.lognot a

(* Negation: two's complement *)
let neg64 (a:u64) : u64 = sub64 0uL a

(*
  Shift operations: BPF masks the shift amount.
  For 64-bit: shift_amount = shift_amount & 63
  FStar.UInt64.shift_left requires s < 64, which masking guarantees.
*)
let shl64 (a:u64) (s:u64) : u64 =
  let masked = FStar.UInt32.uint_to_t (FStar.UInt64.v s % 64) in
  FStar.UInt64.shift_left a masked

let shr64 (a:u64) (s:u64) : u64 =
  let masked = FStar.UInt32.uint_to_t (FStar.UInt64.v s % 64) in
  FStar.UInt64.shift_right a masked

(* --- 32-bit arithmetic with BPF semantics --- *)
(* 32-bit ALU results zero-extend into 64-bit *)

let add32 (a b:u32) : u32 = FStar.UInt32.add_mod a b
let sub32 (a b:u32) : u32 = FStar.UInt32.sub_mod a b
let mul32 (a b:u32) : u32 = FStar.UInt32.mul_mod a b

let div32 (a b:u32) : u32 =
  if b = 0ul then 0ul
  else FStar.UInt32.div a b

let mod32 (a b:u32) : u32 =
  if b = 0ul then a
  else FStar.UInt32.rem a b

let and32 (a b:u32) : u32 = FStar.UInt32.logand a b
let or32 (a b:u32) : u32 = FStar.UInt32.logor a b
let xor32 (a b:u32) : u32 = FStar.UInt32.logxor a b
let not32 (a:u32) : u32 = FStar.UInt32.lognot a
let neg32 (a:u32) : u32 = sub32 0ul a

let shl32 (a:u32) (s:u32) : u32 =
  let masked = FStar.UInt32.uint_to_t (FStar.UInt32.v s % 32) in
  FStar.UInt32.shift_left a masked

let shr32 (a:u32) (s:u32) : u32 =
  let masked = FStar.UInt32.uint_to_t (FStar.UInt32.v s % 32) in
  FStar.UInt32.shift_right a masked

(* Zero-extend a 32-bit value to 64-bit *)
let zext32_64 (a:u32) : u64 =
  FStar.UInt64.uint_to_t (FStar.UInt32.v a)

(* Truncate a 64-bit value to 32-bit *)
let trunc64_32 (a:u64) : u32 =
  FStar.UInt32.uint_to_t (FStar.UInt64.v a % pow2 32)

(* --- Comparison operations --- *)

(* Unsigned comparisons *)
let gt_u64 (a b:u64) : bool = FStar.UInt64.gt a b
let ge_u64 (a b:u64) : bool = FStar.UInt64.gte a b
let lt_u64 (a b:u64) : bool = FStar.UInt64.lt a b
let le_u64 (a b:u64) : bool = FStar.UInt64.lte a b
let eq_u64 (a b:u64) : bool = a = b
let ne_u64 (a b:u64) : bool = not (a = b)

(*
  Signed comparisons: interpret 64-bit unsigned as signed via two's complement.
  Values >= 2^63 are negative.
*)
let as_signed64 (a:u64) : int =
  let v = FStar.UInt64.v a in
  if v >= pow2 63 then v - pow2 64
  else v

let gt_s64 (a b:u64) : bool = as_signed64 a > as_signed64 b
let ge_s64 (a b:u64) : bool = as_signed64 a >= as_signed64 b
let lt_s64 (a b:u64) : bool = as_signed64 a < as_signed64 b
let le_s64 (a b:u64) : bool = as_signed64 a <= as_signed64 b

(* --- Properties --- *)

(* Division by zero always yields 0 *)
let div64_by_zero (a:u64)
  : Lemma (div64 a 0uL = 0uL)
  = ()

(* Modulo by zero preserves the dividend *)
let mod64_by_zero (a:u64)
  : Lemma (mod64 a 0uL = a)
  = ()

(* Negation is self-inverse *)
let neg64_involutive (a:u64)
  : Lemma (neg64 (neg64 a) = a)
  = ()

(* Zero-extend then truncate is identity *)
let zext_trunc_roundtrip (a:u32)
  : Lemma (trunc64_32 (zext32_64 a) = a)
  = ()
