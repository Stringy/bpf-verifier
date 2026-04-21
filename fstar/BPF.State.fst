module BPF.State

open FStar.Mul
open FStar.UInt64
open FStar.UInt8
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

type stack_mem = s:seq UInt8.t{Seq.length s = stack_size}

type mem_width = | W8 | W16 | W32 | W64

let width_bytes (w: mem_width) : nat =
  match w with
  | W8 -> 1
  | W16 -> 2
  | W32 -> 4
  | W64 -> 8

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

let read_byte (stack: stack_mem) (idx: nat{idx < stack_size}) : nat =
  UInt8.v (Seq.index stack idx)

let write_byte (stack: stack_mem) (idx: nat{idx < stack_size}) (v: nat{v < 256}) : stack_mem =
  Seq.upd stack idx (UInt8.uint_to_t v)

let load_le8 (stack: stack_mem) (idx: nat{idx < stack_size}) : nat =
  read_byte stack idx

let load_le16 (stack: stack_mem) (idx: nat{idx + 1 < stack_size}) : nat =
  let b0 = read_byte stack idx in
  let b1 = read_byte stack (idx + 1) in
  b0 + b1 * 0x100

let load_le32 (stack: stack_mem) (idx: nat{idx + 3 < stack_size}) : nat =
  let b0 = read_byte stack idx in
  let b1 = read_byte stack (idx + 1) in
  let b2 = read_byte stack (idx + 2) in
  let b3 = read_byte stack (idx + 3) in
  b0 + b1 * 0x100 + b2 * 0x10000 + b3 * 0x1000000

let load_le64 (stack: stack_mem) (idx: nat{idx + 7 < stack_size}) : nat =
  let b0 = read_byte stack idx in
  let b1 = read_byte stack (idx + 1) in
  let b2 = read_byte stack (idx + 2) in
  let b3 = read_byte stack (idx + 3) in
  let b4 = read_byte stack (idx + 4) in
  let b5 = read_byte stack (idx + 5) in
  let b6 = read_byte stack (idx + 6) in
  let b7 = read_byte stack (idx + 7) in
  b0 + b1 * 0x100 + b2 * 0x10000 + b3 * 0x1000000
    + b4 * 0x100000000 + b5 * 0x10000000000
    + b6 * 0x1000000000000 + b7 * 0x100000000000000

let store_le8 (stack: stack_mem) (idx: nat{idx < stack_size}) (n: nat) : stack_mem =
  write_byte stack idx (n % 0x100)

let store_le16 (stack: stack_mem) (idx: nat{idx + 1 < stack_size}) (n: nat) : stack_mem =
  let s = write_byte stack idx (n % 0x100) in
  write_byte s (idx + 1) ((n / 0x100) % 0x100)

let store_le32 (stack: stack_mem) (idx: nat{idx + 3 < stack_size}) (n: nat) : stack_mem =
  let s = write_byte stack idx (n % 0x100) in
  let s = write_byte s (idx + 1) ((n / 0x100) % 0x100) in
  let s = write_byte s (idx + 2) ((n / 0x10000) % 0x100) in
  write_byte s (idx + 3) ((n / 0x1000000) % 0x100)

let store_le64 (stack: stack_mem) (idx: nat{idx + 7 < stack_size}) (n: nat) : stack_mem =
  let s = write_byte stack idx (n % 0x100) in
  let s = write_byte s (idx + 1) ((n / 0x100) % 0x100) in
  let s = write_byte s (idx + 2) ((n / 0x10000) % 0x100) in
  let s = write_byte s (idx + 3) ((n / 0x1000000) % 0x100) in
  let s = write_byte s (idx + 4) ((n / 0x100000000) % 0x100) in
  let s = write_byte s (idx + 5) ((n / 0x10000000000) % 0x100) in
  let s = write_byte s (idx + 6) ((n / 0x1000000000000) % 0x100) in
  write_byte s (idx + 7) ((n / 0x100000000000000) % 0x100)

let stack_load (st: bpf_state) (offset: int) (w: mem_width) : option UInt64.t =
  let idx = stack_size + offset in
  if idx < 0 || idx + width_bytes w > stack_size then None
  else
    let v = match w with
      | W8  -> load_le8  st.stack idx
      | W16 -> load_le16 st.stack idx
      | W32 -> load_le32 st.stack idx
      | W64 -> load_le64 st.stack idx
    in
    if v < pow2 64 then Some (UInt64.uint_to_t v) else None

let stack_store (st: bpf_state) (offset: int) (w: mem_width) (v: UInt64.t) : option bpf_state =
  let idx = stack_size + offset in
  if idx < 0 || idx + width_bytes w > stack_size then None
  else
    let n = UInt64.v v in
    let s = match w with
      | W8  -> store_le8  st.stack idx n
      | W16 -> store_le16 st.stack idx n
      | W32 -> store_le32 st.stack idx n
      | W64 -> store_le64 st.stack idx n
    in
    Some { st with stack = s; pc = st.pc + 1 }
