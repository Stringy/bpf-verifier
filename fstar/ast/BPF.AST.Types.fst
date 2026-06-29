(*
  BPF.AST.Types — C type system subset relevant to BPF

  Defines the restricted set of C types that appear in BPF programmes.
  BPF C uses a small subset of C: fixed-width integers, pointers, structs,
  void, and bool. No floating point, no unions (as a source-level type),
  no function pointers (modelled separately as helper signatures).

  These types serve as indices on expressions: an expression of type
  `expr (CUInt W32)` is guaranteed to produce a 32-bit unsigned integer.
*)
module BPF.AST.Types

open FStar.Mul

(* Integer width *)
type int_width =
  | W8
  | W16
  | W32
  | W64

let int_width_bytes (w:int_width) : nat =
  match w with
  | W8 -> 1
  | W16 -> 2
  | W32 -> 4
  | W64 -> 8

let int_width_bits (w:int_width) : nat =
  match w with
  | W8 -> 8
  | W16 -> 16
  | W32 -> 32
  | W64 -> 64

(* Struct field: name and type *)
type field_name = string

(* Forward declaration: c_type is mutually recursive with struct_fields *)
noeq
type c_type =
  (* Signed integer of given width *)
  | CInt : int_width -> c_type

  (* Unsigned integer of given width *)
  | CUInt : int_width -> c_type

  (* Boolean (used in conditionals) *)
  | CBool : c_type

  (* Void (used for void pointers, return type of void functions) *)
  | CVoid : c_type

  (* Pointer to a value of type t. Non-null by construction —
     the only way to obtain a CPtr is through dereference of a
     known-valid pointer or promotion from CPtr_or_null via null check. *)
  | CPtr : c_type -> c_type

  (* Pointer that may be null. Returned by map lookups and socket lookups.
     Must be null-checked before dereference. *)
  | CPtr_or_null : c_type -> c_type

  (* Struct with named fields *)
  | CStruct : struct_def -> c_type

  (* Array of fixed size (for stack-allocated arrays, map keys/values) *)
  | CArray : c_type -> nat -> c_type

and struct_def = {
  struct_name : string;
  fields : list (field_name & c_type);
}

(* --- Queries on types --- *)

(* Size of a type in bytes (for memory access checking) *)
let rec type_size (t:c_type) : Tot nat (decreases t) =
  match t with
  | CInt w | CUInt w -> int_width_bytes w
  | CBool -> 1
  | CVoid -> 0
  | CPtr _ | CPtr_or_null _ -> 8  (* BPF pointers are 64-bit *)
  | CStruct sd -> struct_size sd.fields
  | CArray elem n -> n * type_size elem

and struct_size (fields:list (field_name & c_type)) : Tot nat (decreases fields) =
  match fields with
  | [] -> 0
  | (_, ft) :: rest -> type_size ft + struct_size rest

(* Look up a field's type in a struct definition *)
let rec field_type (fields:list (field_name & c_type)) (name:field_name)
  : Tot (option c_type) (decreases fields)
  = match fields with
  | [] -> None
  | (n, t) :: rest ->
    if n = name then Some t
    else field_type rest name

(* Is a field present in a struct? *)
let has_field (sd:struct_def) (name:field_name) : bool =
  Some? (field_type sd.fields name)

(* Get a field's type when we know it exists *)
let get_field_type (sd:struct_def) (name:field_name{has_field sd name}) : c_type =
  Some?.v (field_type sd.fields name)

(* Is a type a pointer (either nullable or non-nullable)? *)
let is_ptr (t:c_type) : bool =
  match t with
  | CPtr _ | CPtr_or_null _ -> true
  | _ -> false

(* Is a type nullable? *)
let is_nullable (t:c_type) : bool =
  CPtr_or_null? t

(* Is a type an integer (signed or unsigned)? *)
let is_integer (t:c_type) : bool =
  match t with
  | CInt _ | CUInt _ -> true
  | _ -> false

(* Is a type numeric (integer or bool)? *)
let is_numeric (t:c_type) : bool =
  match t with
  | CInt _ | CUInt _ | CBool -> true
  | _ -> false

(* Get the pointed-to type for a pointer *)
let pointee_type (t:c_type{is_ptr t}) : c_type =
  match t with
  | CPtr inner -> inner
  | CPtr_or_null inner -> inner

(* --- Common BPF types --- *)

let c_u8  : c_type = CUInt W8
let c_u16 : c_type = CUInt W16
let c_u32 : c_type = CUInt W32
let c_u64 : c_type = CUInt W64

let c_s8  : c_type = CInt W8
let c_s16 : c_type = CInt W16
let c_s32 : c_type = CInt W32
let c_s64 : c_type = CInt W64

(* BPF programmes return int (32-bit signed) *)
let c_bpf_return : c_type = CInt W32

(* --- BPF programme types --- *)

(* Determines what context is passed, which helpers are available,
   and what the return value means. Defined here rather than in
   BPF.AST.Decl so that both BPF.Helpers and BPF.AST.Decl can
   import it without circular dependencies. *)
type bpf_prog_type =
  | ProgSocketFilter
  | ProgXDP
  | ProgKprobe
  | ProgTracepoint
  | ProgPerfEvent
  | ProgCgroupSkb
  | ProgCgroupSock
  | ProgLwtIn
  | ProgLwtOut
  | ProgLwtXmit
  | ProgSchedCls
  | ProgSchedAct
  | ProgRawTracepoint
  | ProgFlowDissector
