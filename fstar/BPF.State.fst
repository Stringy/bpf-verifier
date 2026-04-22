(* BPF.State — the BPF machine state model.

   This module defines the state a BPF programme operates on: registers,
   programme counter, and the 512-byte stack. Every BPF instruction is a
   transition from one bpf_state to another.

   F* syntax primer for BPF folk:
   - `nat` is a non-negative integer, `int` allows negatives
   - `UInt64.t` is a 64-bit unsigned machine integer (like __u64)
   - `{Seq.length s = 11}` is a _refinement type_ — a type with a constraint.
     The value must be a sequence of exactly length 11. F* checks this at
     compile time, not runtime.
   - `option UInt64.t` is either `Some value` or `None` — used here to signal
     out-of-bounds access (similar to returning -EFAULT)
*)
module BPF.State

open FStar.Mul
open FStar.UInt64
open FStar.Seq

(* --- Registers ---
   BPF has 11 registers (r0-r10), all 64-bit. At programme entry:
   - r1 = context pointer (struct __sk_buff*, struct xdp_md*, etc.)
   - r10 = frame pointer (top of the 512-byte stack)
   - r0 = return value (set by the programme before exit)
   - r2-r9 = callee-saved / argument registers *)

let num_regs : nat = 11

(* A register file is a fixed-length sequence of 11 UInt64 values.
   The `{Seq.length s = num_regs}` part is a refinement — F* will
   reject any code that could produce a register file of wrong length. *)
type reg_file = s:seq UInt64.t{Seq.length s = num_regs}

(* Register indices. The type `n:nat{n < num_regs}` means "a natural
   number that is provably less than 11" — so indexing the register
   file with one of these can never be out of bounds. *)
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

let get_reg (regs: reg_file) (r: reg_idx) : UInt64.t =
  Seq.index regs r

let set_reg (regs: reg_file) (r: reg_idx) (v: UInt64.t) : reg_file =
  Seq.upd regs r v

(* --- Stack memory ---
   BPF programmes get a 512-byte stack, accessed via r10 (frame pointer)
   plus a negative offset. For example, [u32](r10 - 4) accesses the
   top 4 bytes of the stack.

   We model the stack as a list of (offset, width, value) slots. A store
   pushes a new slot onto the front; a load scans for a matching offset
   and width. This is a _word-level_ model — it doesn't decompose values
   into individual bytes. This keeps Z3 happy (byte-level reasoning
   causes combinatorial explosion) at the cost of not modelling
   overlapping accesses at different widths.

   For compiler-generated BPF code this is fine — the compiler always
   loads and stores at the same width and alignment it wrote. *)

let stack_size : nat = 512

(* Memory access width — matches the BPF instruction encoding.
   W8 = byte, W16 = half-word, W32 = word, W64 = double-word. *)
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

(* Bounds check: the access must fall entirely within [0, 512).
   Offsets are negative (relative to r10), so we add stack_size
   to convert to a positive index. *)
let stack_offset_valid (offset: int) (w: mem_width) : bool =
  let idx = stack_size + offset in
  idx >= 0 && idx + width_bytes w <= stack_size

(* Load: scan the slot list for a matching offset and width.
   Returns None if no matching store has been done (reading
   uninitialised stack). Most recent store wins because
   stack_write prepends to the list. *)
let rec stack_read (stack: stack_mem) (offset: int) (w: mem_width) : option UInt64.t =
  match stack with
  | [] -> None
  | slot :: rest ->
    if slot.offset = offset && slot.width = w
    then Some slot.value
    else stack_read rest offset w

(* Store: prepend a new slot. Previous values at the same offset
   are shadowed (not removed) — stack_read finds the newest first. *)
let stack_write (stack: stack_mem) (offset: int) (w: mem_width) (v: UInt64.t) : stack_mem =
  { offset = offset; width = w; value = v } :: stack

(* --- Machine state ---
   `noeq` tells F* not to derive decidable equality for this type.
   We don't need == on states, and deriving it for sequences is expensive. *)
noeq
type bpf_state = {
  regs: reg_file;
  pc: nat;
  stack: stack_mem;
}

let state_get_reg (st: bpf_state) (r: reg_idx) : UInt64.t =
  get_reg st.regs r

(* Write a register and advance the programme counter.
   `{ st with regs = ...; pc = ... }` is F* record update syntax —
   like struct copy in C but with specific fields changed. *)
let state_set_reg (st: bpf_state) (r: reg_idx) (v: UInt64.t) : bpf_state =
  { st with regs = set_reg st.regs r v; pc = st.pc + 1 }

(* Stack load/store wrappers that check bounds first. Return None
   (triggering a verification failure) if the access is out of range. *)
let stack_load (st: bpf_state) (offset: int) (w: mem_width) : option UInt64.t =
  if not (stack_offset_valid offset w) then None
  else stack_read st.stack offset w

let stack_store (st: bpf_state) (offset: int) (w: mem_width) (v: UInt64.t) : option bpf_state =
  if not (stack_offset_valid offset w) then None
  else Some { st with stack = stack_write st.stack offset w v; pc = st.pc + 1 }
