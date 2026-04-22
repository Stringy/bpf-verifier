(* BPF.State — the BPF machine state model.

   This module defines the state a BPF programme operates on: registers,
   programme counter, stack, and map pointer tracking.

   Registers hold typed values — either plain scalars (integers) or
   pointers to map values. This mirrors how the kernel's BPF verifier
   tracks register types: it knows whether a register holds a number,
   a pointer to a map value, a frame pointer, etc. We need this
   distinction to verify that programmes null-check map lookup results
   before dereferencing them.

   F* syntax primer for BPF folk:
   - `nat` is a non-negative integer, `int` allows negatives
   - `UInt64.t` is a 64-bit unsigned machine integer (like __u64)
   - The `|` syntax defines a tagged union (like a Rust enum)
   - `option X` is either `Some value` or `None` — used here to signal
     out-of-bounds access or null pointer dereference
*)
module BPF.State

open FStar.Mul
open FStar.UInt64
open FStar.Seq

(* --- Register values ---
   A register can hold:
   - Scalar: a plain 64-bit value (arithmetic result, immediate, etc.)
   - FramePtr: a pointer into the stack frame. Carries an offset from the
     top of the stack (r10). At programme entry r10 = FramePtr 0. The
     compiler often copies r10 to another register and adds a negative
     offset to compute a stack address, e.g. r2 = r10; r2 += -4 produces
     FramePtr (-4). Load/store through a FramePtr uses its offset.
   - MapValuePtr: a pointer to a map value, returned by bpf_map_lookup_elem.
     The nat is a unique ID for this particular lookup result. Dereferencing
     a MapValuePtr reads from the map; dereferencing anything else is UB.
   - Null: the null pointer (map lookup returned "not found")

   This type system prevents dereferencing null — the verifier rejects
   programmes that can reach a load/store through Null or Scalar. *)
type reg_val =
  | Scalar : UInt64.t -> reg_val
  | FramePtr : int -> reg_val
  | MapValuePtr : nat -> reg_val
  | Null : reg_val

let num_regs : nat = 11

type reg_file = s:seq reg_val{Seq.length s = num_regs}

(* Register indices — same as before. *)
let r0  : n:nat{n < num_regs} = 0
let r1  : n:nat{n < num_regs} = 1
let r2  : n:nat{n < num_regs} = 2
let r3  : n:nat{n < num_regs} = 3
let r4  : n:nat{n < num_regs} = 4
let r5  : n:nat{n < num_regs} = 5
let r6  : n:nat{n < num_regs} = 6
let r7  : n:nat{n < num_regs} = 7
let r8  : n:nat{n < num_regs} = 8
let r9  : n:nat{n < num_regs} = 9
let r10 : n:nat{n < num_regs} = 10

type reg_idx = r:nat{r < num_regs}

let get_reg (regs: reg_file) (r: reg_idx) : reg_val =
  Seq.index regs r

let set_reg (regs: reg_file) (r: reg_idx) (v: reg_val) : reg_file =
  Seq.upd regs r v

(* Extract the scalar value from a register, or None if it holds
   a pointer. Used by ALU ops which only operate on scalars. *)
let scalar_val (v: reg_val) : option UInt64.t =
  match v with
  | Scalar n -> Some n
  | _ -> None

(* --- Stack memory ---
   BPF programmes get a 512-byte stack, accessed via the frame pointer
   (r10) plus a negative offset.

   We model the stack as a list of (offset, width, value) slots. A store
   pushes a new slot; a load scans for a matching offset and width.
   This is a word-level model — it doesn't decompose values into
   individual bytes. This keeps Z3 performant at the cost of not
   modelling overlapping accesses at different widths. *)

let stack_size : nat = 512

type mem_width = | W8 | W16 | W32 | W64

let width_bytes (w: mem_width) : nat =
  match w with
  | W8 -> 1
  | W16 -> 2
  | W32 -> 4
  | W64 -> 8

type stack_slot = {
  offset: int;
  width: mem_width;
  value: UInt64.t;
}

type stack_mem = list stack_slot

let stack_offset_valid (offset: int) (w: mem_width) : bool =
  let idx = stack_size + offset in
  idx >= 0 && idx + width_bytes w <= stack_size

let rec stack_read (stack: stack_mem) (offset: int) (w: mem_width) : option UInt64.t =
  match stack with
  | [] -> None
  | slot :: rest ->
    if slot.offset = offset && slot.width = w
    then Some slot.value
    else stack_read rest offset w

let stack_write (stack: stack_mem) (offset: int) (w: mem_width) (v: UInt64.t) : stack_mem =
  { offset = offset; width = w; value = v } :: stack

(* --- Map value memory ---
   When bpf_map_lookup_elem returns a non-null pointer, the programme
   can read the value at that pointer. Each lookup gets a unique ID
   (MapValuePtr id). We track the value at each ID as a symbolic UInt64.

   This is a fully symbolic model — the spec cannot constrain what
   values are in the map. It can only reason about what the programme
   does with whatever it finds. *)
type map_value_mem = list (nat & UInt64.t)

let rec map_value_read (mem: map_value_mem) (id: nat) : option UInt64.t =
  match mem with
  | [] -> None
  | (mid, v) :: rest ->
    if mid = id then Some v
    else map_value_read rest id

(* --- Machine state --- *)
noeq
type bpf_state = {
  regs: reg_file;
  pc: int;
  stack: stack_mem;
  map_values: map_value_mem;
  next_map_id: nat;
}

let state_get_reg (st: bpf_state) (r: reg_idx) : reg_val =
  get_reg st.regs r

let state_set_reg (st: bpf_state) (r: reg_idx) (v: reg_val) : bpf_state =
  { st with regs = set_reg st.regs r v; pc = st.pc + 1 }

let stack_load (st: bpf_state) (offset: int) (w: mem_width) : option UInt64.t =
  if not (stack_offset_valid offset w) then None
  else stack_read st.stack offset w

let stack_store (st: bpf_state) (offset: int) (w: mem_width) (v: UInt64.t) : option bpf_state =
  if not (stack_offset_valid offset w) then None
  else Some { st with stack = stack_write st.stack offset w v; pc = st.pc + 1 }
