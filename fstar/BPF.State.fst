module BPF.State

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

type bpf_state = {
  regs: reg_file;
  pc: nat;
}

let mk_state (regs: reg_file) : bpf_state = {
  regs = regs;
  pc = 0;
}

let state_get_reg (st: bpf_state) (r: reg_idx) : UInt64.t =
  get_reg st.regs r

let state_set_reg (st: bpf_state) (r: reg_idx) (v: UInt64.t) : bpf_state =
  { regs = set_reg st.regs r v; pc = st.pc + 1 }
