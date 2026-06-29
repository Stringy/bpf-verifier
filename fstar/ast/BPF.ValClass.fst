(*
  BPF.ValClass — Value classification

  Classifies what a runtime value can be. This is the C-level analogue of
  the kernel verifier's register types (SCALAR_VALUE, PTR_TO_MAP_VALUE, etc.),
  but tracked per variable in a typing context rather than per register.

  Each classification determines:
  - What arithmetic operations are permitted
  - Whether the value can be dereferenced
  - What memory region a pointer refers to and its accessible bounds
*)
module BPF.ValClass

open BPF.Tnum
open BPF.Range
open BPF.AST.Types

(* Unique identifier for a map definition *)
type map_id = nat

(* Unique identifier for a tracked reference (socket, map element, etc.) *)
type ref_id = nat

(* Memory access size *)
type mem_size =
  | Byte      (* 1 byte *)
  | HalfWord  (* 2 bytes *)
  | Word      (* 4 bytes *)
  | DWord     (* 8 bytes *)

let mem_size_bytes (s:mem_size) : nat =
  match s with
  | Byte -> 1
  | HalfWord -> 2
  | Word -> 4
  | DWord -> 8

(* Alignment requirement in bytes *)
type alignment = a:nat{a = 1 \/ a = 2 \/ a = 4 \/ a = 8}

(*
  Value classification — what a variable's value can be at runtime.

  This is an inductive type (not indexed) because the classifications are
  used as data in the variable context, not as type-level indices. The
  verification constraints come from refinements on functions that consume
  these classifications.
*)
noeq
type val_class =
  (* Variable declared but not yet assigned. Reading is rejected. *)
  | Uninit

  (* Numeric value, not a pointer. Carries abstract domain information. *)
  | Scalar : tnum -> range -> val_class

  (* Pointer into the programme context structure.
     offset: byte offset from start of the context struct. *)
  | PtrToCtx : offset:nat -> val_class

  (* Pointer to a local variable's storage.
     var_name: which local variable.
     offset: byte offset within that variable's storage. *)
  | PtrToLocal : var_name:string -> offset:nat -> val_class

  (* Pointer into a map element's value.
     mid: which map.
     offset: byte offset within the element's value. *)
  | PtrToMapValue : mid:map_id -> offset:nat -> val_class

  (* Map lookup result, not yet null-checked.
     No arithmetic or dereference allowed until the null check promotes
     this to PtrToMapValue. *)
  | PtrToMapValueOrNull : mid:map_id -> rid:ref_id -> val_class

  (* Pointer into packet data.
     accessible: number of bytes proven accessible from this pointer. *)
  | PtrToPacket : accessible:nat -> val_class

  (* Packet end marker (skb->data_end).
     Only used for comparison; dereference and arithmetic are forbidden. *)
  | PtrToPacketEnd

  (* Reference-counted socket pointer.
     Must be released before programme exit. *)
  | PtrToSocket : rid:ref_id -> val_class

  (* Socket lookup result, not yet null-checked. *)
  | PtrToSocketOrNull : rid:ref_id -> val_class

(* --- Type compatibility --- *)

(* A val_class is compatible with a c_type if they describe the same
   kind of value. Scalars are compatible with any integer type.
   Pointer classifications are compatible with CPtr or CPtr_or_null.
   This is used to enforce that VarRef produces the correct type and
   that Assign uses a val_class consistent with the expression type. *)
let val_class_compatible (vc:val_class) (t:c_type) : bool =
  match vc, t with
  | Uninit, _ -> false
  | Scalar _ _, CInt _ | Scalar _ _, CUInt _ | Scalar _ _, CBool -> true
  | PtrToCtx _, CPtr _ -> true
  | PtrToLocal _ _, CPtr _ -> true
  | PtrToMapValue _ _, CPtr _ -> true
  | PtrToMapValueOrNull _ _, CPtr_or_null _ -> true
  | PtrToPacket _, CPtr _ -> true
  | PtrToPacketEnd, CPtr _ -> true  (* end marker is still a pointer *)
  | PtrToSocket _, CPtr _ -> true
  | PtrToSocketOrNull _, CPtr_or_null _ -> true
  | _, _ -> false

(* --- Classification queries --- *)

(* Can this value be read? (is it initialised?) *)
let is_readable (vc:val_class) : bool =
  not (Uninit? vc)

(* Is this a scalar (numeric, non-pointer) value? *)
let is_scalar (vc:val_class) : bool =
  Scalar? vc

(* Is this a pointer that can be dereferenced? *)
let is_deref_safe (vc:val_class) : bool =
  match vc with
  | PtrToCtx _ | PtrToLocal _ _ | PtrToMapValue _ _
  | PtrToPacket _ | PtrToSocket _ -> true
  | _ -> false

(* Is this an _OR_NULL pointer that needs a null check? *)
let needs_null_check (vc:val_class) : bool =
  match vc with
  | PtrToMapValueOrNull _ _ | PtrToSocketOrNull _ -> true
  | _ -> false

(* Is this a reference-counted value that must be released? *)
let is_refcounted (vc:val_class) : bool =
  match vc with
  | PtrToSocket _ | PtrToSocketOrNull _ -> true
  | _ -> false

(* Get the ref_id if this is a reference-counted value *)
let get_ref_id (vc:val_class{is_refcounted vc}) : ref_id =
  match vc with
  | PtrToSocket rid -> rid
  | PtrToSocketOrNull rid -> rid

(* Can arithmetic be performed on this value? *)
let allows_arithmetic (vc:val_class) : bool =
  match vc with
  | Scalar _ _ -> true
  | PtrToCtx _ | PtrToLocal _ _ | PtrToMapValue _ _ -> true  (* bounded *)
  | PtrToPacket _ -> true  (* add/sub only *)
  | _ -> false

(* --- Null check promotion --- *)

(*
  After a successful null check (value != NULL), promote _OR_NULL to
  the concrete pointer type.
*)
let promote_after_null_check (vc:val_class{needs_null_check vc}) : val_class =
  match vc with
  | PtrToMapValueOrNull mid _rid -> PtrToMapValue mid 0
  | PtrToSocketOrNull rid -> PtrToSocket rid

(*
  After a failed null check (value == NULL), the value is known to be
  the scalar zero.
*)
let demote_after_null_check (vc:val_class{needs_null_check vc}) : val_class =
  Scalar (tnum_const 0uL) (range_const 0)

(* --- Scalar constructors --- *)

(* A fully known scalar constant *)
let scalar_const (v:nat{v <= pow2 64 - 1}) : val_class =
  Scalar (tnum_const (FStar.UInt64.uint_to_t v)) (range_const v)

(* An unknown scalar (any 64-bit value) *)
let scalar_unknown : val_class =
  Scalar tnum_unknown range_unknown

(* A scalar known to be in [0, 2^32 - 1] (e.g. after reading a u32) *)
let scalar_u32 : val_class =
  Scalar (tnum_range 32) range_u32

(* A scalar known to be in [0, 255] (e.g. after reading a u8) *)
let scalar_u8 : val_class =
  Scalar (tnum_range 8) range_u8

(* --- Join operation for merge points --- *)

(*
  Join two value classifications at a branch merge point.
  The result over-approximates both inputs.
  Returns None if the classifications are incompatible (e.g. one branch
  has a pointer and the other has a scalar for the same variable).
*)
let join_val_class (a b:val_class) : option val_class =
  match a, b with
  (* Both uninit stays uninit *)
  | Uninit, Uninit -> Some Uninit

  (* Both scalars: join their abstract domains.
     Use tnum_unknown as a sound over-approximation. The range join is
     still precise. We can refine the tnum join later with a dedicated
     tnum_join function in BPF.Tnum. *)
  | Scalar _ta ra, Scalar _tb rb ->
    Some (Scalar tnum_unknown (range_join ra rb))

  (* Same pointer type: widen offsets/ranges *)
  | PtrToCtx oa, PtrToCtx ob ->
    if oa = ob then Some (PtrToCtx oa) else None  (* different offsets are incompatible *)

  | PtrToMapValue ma oa, PtrToMapValue mb ob ->
    if ma = mb then
      Some (PtrToMapValue ma (if oa <= ob then oa else ob))  (* take minimum offset *)
    else None

  | PtrToPacket ra, PtrToPacket rb ->
    Some (PtrToPacket (if ra <= rb then ra else rb))  (* take minimum accessible *)

  (* Incompatible: scalar vs pointer, different pointer types, etc. *)
  | _, _ -> None

(* --- Properties --- *)

(* A promoted pointer is always dereferenceable *)
let promoted_is_deref_safe (vc:val_class{needs_null_check vc})
  : Lemma (is_deref_safe (promote_after_null_check vc))
  = ()

(* A demoted pointer is always a scalar *)
let demoted_is_scalar (vc:val_class{needs_null_check vc})
  : Lemma (is_scalar (demote_after_null_check vc))
  = ()

(* A known constant is readable *)
let scalar_const_readable (v:nat{v <= pow2 64 - 1})
  : Lemma (is_readable (scalar_const v))
  = ()

(* Join is commutative for uninit *)
let join_uninit_comm ()
  : Lemma (join_val_class Uninit Uninit == Some Uninit)
  = ()
