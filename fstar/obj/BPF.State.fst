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

open FStar.UInt64

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
  | RingBufPtr : nat -> reg_val
  | CtxPtr : int -> reg_val
  | Null : reg_val

let num_regs : nat = 11

type reg_idx = r:nat{r < num_regs}

(* Individual bindings so F* inlines them during normalisation. *)
let r0  : reg_idx = 0
let r1  : reg_idx = 1
let r2  : reg_idx = 2
let r3  : reg_idx = 3
let r4  : reg_idx = 4
let r5  : reg_idx = 5
let r6  : reg_idx = 6
let r7  : reg_idx = 7
let r8  : reg_idx = 8
let r9  : reg_idx = 9
let r10 : reg_idx = 10

(* A register file is a function from register index to value.
   Using a function rather than a sequence lets F*'s normaliser
   resolve get_reg/set_reg instantly — critical for tactic-based
   proofs that normalise the full programme execution. *)
type reg_file = reg_idx -> reg_val

let get_reg (regs: reg_file) (r: reg_idx) : reg_val = regs r

let set_reg (regs: reg_file) (r: reg_idx) (v: reg_val) : reg_file =
  fun i -> if i = r then v else regs i

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

(* --- Ring buffer memory ---
   When bpf_ringbuf_reserve returns a non-null pointer, the programme
   can write event fields at offsets from that pointer. We track these
   writes so the spec can assert what was written.

   Each entry records (ringbuf_id, offset, width, value). The id comes
   from the RingBufPtr allocated by RINGBUF_RESERVE. Stores prepend
   entries; reads scan for the first match — same strategy as stack_mem. *)
type ringbuf_slot = {
  rb_id: nat;
  rb_offset: int;
  rb_width: mem_width;
  rb_value: UInt64.t;
}

type ringbuf_mem = list ringbuf_slot

let rec ringbuf_read (mem: ringbuf_mem) (id: nat) (offset: int) (w: mem_width)
  : option UInt64.t =
  match mem with
  | [] -> None
  | slot :: rest ->
    if slot.rb_id = id && slot.rb_offset = offset && slot.rb_width = w
    then Some slot.rb_value
    else ringbuf_read rest id offset w

(* Read by offset and width only, ignoring the ring buffer ID.
   Useful in specs where the ID is allocated dynamically and
   the user doesn't care which ring buffer slot was used. *)
let rec ringbuf_read_any (mem: ringbuf_mem) (offset: int) (w: mem_width)
  : option UInt64.t =
  match mem with
  | [] -> None
  | slot :: rest ->
    if slot.rb_offset = offset && slot.rb_width = w
    then Some slot.rb_value
    else ringbuf_read_any rest offset w

let ringbuf_write_count (mem: ringbuf_mem) : nat =
  List.Tot.length mem

let ringbuf_write (mem: ringbuf_mem) (id: nat) (offset: int) (w: mem_width) (v: UInt64.t)
  : ringbuf_mem =
  { rb_id = id; rb_offset = offset; rb_width = w; rb_value = v } :: mem

(* --- Machine state --- *)
noeq
type bpf_state = {
  regs: reg_file;
  pc: int;
  stack: stack_mem;
  map_values: map_value_mem;
  ringbuf: ringbuf_mem;
  next_map_id: nat;
  reg_origins: reg_idx -> nat;
}

let state_get_reg (st: bpf_state) (r: reg_idx) : reg_val =
  get_reg st.regs r

let state_set_reg (st: bpf_state) (r: reg_idx) (v: reg_val) : bpf_state =
  let origin = if st.pc >= 0 then st.pc else 0 in
  { st with regs = set_reg st.regs r v;
            pc = st.pc + 1;
            reg_origins = fun i -> if i = r then origin else st.reg_origins i }

let stack_load (st: bpf_state) (offset: int) (w: mem_width) : option UInt64.t =
  if not (stack_offset_valid offset w) then None
  else stack_read st.stack offset w

let stack_store (st: bpf_state) (offset: int) (w: mem_width) (v: UInt64.t) : option bpf_state =
  if not (stack_offset_valid offset w) then None
  else Some { st with stack = stack_write st.stack offset w v; pc = st.pc + 1 }

(* --- BPF helper function IDs ---
   Defined here (rather than in BPF.Semantics) so that BPF.Helpers can
   reference them without creating a circular dependency.
   Each corresponds to a linux kernel BPF helper function. *)
type helper_id =
  | MAP_LOOKUP_ELEM          (* #1  -- look up a key in a BPF map *)
  | MAP_UPDATE_ELEM          (* #2  -- insert or update a key-value pair *)
  | MAP_DELETE_ELEM          (* #3  -- delete a key from a BPF map *)
  | PROBE_READ               (* #4  -- read from kernel/user memory *)
  | KTIME_GET_NS             (* #5  -- monotonic time in nanoseconds *)
  | TRACE_PRINTK             (* #6  -- debug trace output *)
  | GET_PRANDOM_U32          (* #7  -- pseudo-random 32-bit number *)
  | GET_CURRENT_PID_TGID     (* #14 -- current PID and TGID *)
  | GET_CURRENT_UID_GID      (* #15 -- current UID and GID *)
  | GET_CURRENT_COMM         (* #16 -- current task command name *)
  | GET_CURRENT_TASK         (* #35 -- current task_struct pointer *)
  | PROBE_READ_STR           (* #45 -- read null-terminated string from kernel *)
  | PROBE_READ_USER          (* #112 -- read from user-space memory *)
  | PROBE_READ_KERNEL        (* #113 -- read from kernel-space memory *)
  | PROBE_READ_KERNEL_STR    (* #115 -- read null-terminated string from kernel *)
  | KTIME_GET_BOOT_NS        (* #125 -- boot-monotonic time in nanoseconds *)
  | RINGBUF_RESERVE          (* #131 -- reserve space in ring buffer, returns ptr or null *)
  | RINGBUF_SUBMIT           (* #132 -- submit ring buffer entry *)
  | RINGBUF_DISCARD          (* #133 -- discard ring buffer entry *)
  | D_PATH                   (* #147 -- resolve dentry to full path string *)
  | GET_CURRENT_TASK_BTF     (* #158 -- current task_struct as BTF object *)
  | UNKNOWN_HELPER : nat -> helper_id
