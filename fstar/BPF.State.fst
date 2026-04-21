module BPF.State

open FStar.Mul
open FStar.UInt64
open FStar.Seq

let num_regs : nat = 11

type reg_file = s:seq UInt64.t{Seq.length s = num_regs}

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

noeq
type bpf_state = {
  regs: reg_file;
  pc: nat;
  stack: stack_mem;
}

let state_get_reg (st: bpf_state) (r: reg_idx) : UInt64.t =
  get_reg st.regs r

let state_set_reg (st: bpf_state) (r: reg_idx) (v: UInt64.t) : bpf_state =
  { st with regs = set_reg st.regs r v; pc = st.pc + 1 }

let stack_load (st: bpf_state) (offset: int) (w: mem_width) : option UInt64.t =
  if not (stack_offset_valid offset w) then None
  else stack_read st.stack offset w

let stack_store (st: bpf_state) (offset: int) (w: mem_width) (v: UInt64.t) : option bpf_state =
  if not (stack_offset_valid offset w) then None
  else Some { st with stack = stack_write st.stack offset w v; pc = st.pc + 1 }
