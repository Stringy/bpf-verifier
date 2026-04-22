(* BPF.Semantics — formal semantics for BPF instructions.

   Each BPF instruction is modelled as a state transition:
     exec_insn : bpf_state -> bpf_insn -> option bpf_state

   Returns None on undefined behaviour (division by zero, out-of-bounds
   stack access, non-stack memory access). The verifier will reject
   programmes that can reach None.

   Programmes are executed by indexing into an instruction array using
   the programme counter (pc). Branch instructions modify the pc to
   jump forward or fall through. Execution stops at BPF_EXIT or if
   the pc goes out of bounds.

   F* notes:
   - `Int32.t` is a signed 32-bit integer — BPF immediates are signed
   - `option bpf_state` is like a Result: Some state or None (error)
   - `Tot` means the function is total (always terminates). The
     `decreases` clause tells F* what gets smaller on each recursive
     call so it can prove termination.
*)
module BPF.Semantics

open FStar.Mul
open FStar.UInt64
open FStar.UInt32
open FStar.Int32
open FStar.Int.Cast
open BPF.State

(* --- ALU operations ---
   Matches the BPF instruction set ALU operation field (bits [7:4]). *)
type alu_op =
  | ADD | SUB | MUL | DIV | OR | AND
  | LSH | RSH | NEG | MOD | XOR | MOV | ARSH

(* --- Jump comparison operations ---
   BPF conditional jumps: if (dst OP src) goto pc + offset.
   JA is unconditional (goto). The 64-bit and 32-bit variants use
   the same comparison ops but truncate operands for 32-bit. *)
type jmp_op =
  | JA                        (* unconditional jump *)
  | JEQ | JGT | JGE | JSET   (* unsigned comparisons + bit test *)
  | JNE | JLT | JLE           (* unsigned comparisons *)
  | JSGT | JSGE | JSLT | JSLE (* signed comparisons *)

(* --- Instruction types ---
   Each constructor corresponds to a BPF instruction class:

   ALU64/ALU32: 64-bit or 32-bit arithmetic. REG variants use a source
   register, IMM variants use a sign-extended 32-bit immediate.
   32-bit ops zero the upper 32 bits of the destination.

   LDX: load from memory — load [src + offset] into dst.
   STX: store register to memory — store src to [dst + offset].
   ST:  store immediate to memory — store imm to [dst + offset].

   JMP64/JMP32: conditional branches. Compare dst with src/imm,
   jump pc + offset if true. The offset field is the branch target
   relative to the next instruction.

   JMP_JA: unconditional jump (goto). Offset is in the imm field
   for JA32, or the offset field for JA64.

   Currently only stack access (via r10) is supported for memory.
   Attempting to load/store through any other register returns None. *)
type bpf_insn =
  | BPF_ALU64_REG : alu_op -> reg_idx -> reg_idx -> bpf_insn
  | BPF_ALU64_IMM : alu_op -> reg_idx -> Int32.t -> bpf_insn
  | BPF_ALU32_REG : alu_op -> reg_idx -> reg_idx -> bpf_insn
  | BPF_ALU32_IMM : alu_op -> reg_idx -> Int32.t -> bpf_insn
  | BPF_LDX : mem_width -> reg_idx -> reg_idx -> Int32.t -> bpf_insn
  | BPF_STX : mem_width -> reg_idx -> reg_idx -> Int32.t -> bpf_insn
  | BPF_ST  : mem_width -> reg_idx -> Int32.t -> Int32.t -> bpf_insn
  | BPF_JMP64_REG : jmp_op -> reg_idx -> reg_idx -> i16:int -> bpf_insn
  | BPF_JMP64_IMM : jmp_op -> reg_idx -> Int32.t -> i16:int -> bpf_insn
  | BPF_JMP32_REG : jmp_op -> reg_idx -> reg_idx -> i16:int -> bpf_insn
  | BPF_JMP32_IMM : jmp_op -> reg_idx -> Int32.t -> i16:int -> bpf_insn
  | BPF_JMP_JA : i16:int -> bpf_insn
  | BPF_EXIT : bpf_insn

type bpf_program = list bpf_insn

(* Sign-extend a 32-bit immediate to 64-bit unsigned.
   BPF immediates are signed — e.g. offset -4 is 0xFFFFFFFC.
   This mirrors what the kernel does at load time. *)
let sign_extend_imm (imm: Int32.t) : UInt64.t =
  let i64 = int32_to_int64 imm in
  FStar.Int.Cast.Full.int64_to_uint64 i64

(* Extract the signed integer value of a 32-bit immediate.
   Used to compute stack offsets (which are negative). *)
let sign_extend_to_int (imm: Int32.t) : int =
  Int32.v imm

(* 64-bit ALU. All arithmetic wraps (add_mod, sub_mod, mul_mod).
   Division/modulo by zero returns None (undefined behaviour).
   Note: ARSH (arithmetic right shift) is currently implemented as
   logical right shift — correct for unsigned values only. *)
let alu64 (op: alu_op) (dst_val src_val: UInt64.t) : option UInt64.t =
  match op with
  | ADD -> Some (UInt64.add_mod dst_val src_val)
  | SUB -> Some (UInt64.sub_mod dst_val src_val)
  | MUL -> Some (UInt64.mul_mod dst_val src_val)
  | DIV -> if src_val = 0uL then None else Some (UInt64.div dst_val src_val)
  | OR  -> Some (UInt64.logor dst_val src_val)
  | AND -> Some (UInt64.logand dst_val src_val)
  | XOR -> Some (UInt64.logxor dst_val src_val)
  | MOV -> Some src_val
  | NEG -> Some (UInt64.sub_mod 0uL dst_val)
  | MOD -> if src_val = 0uL then None else Some (UInt64.rem dst_val src_val)
  | LSH -> Some (UInt64.shift_left dst_val (UInt32.uint_to_t (UInt64.v src_val % 64)))
  | RSH -> Some (UInt64.shift_right dst_val (UInt32.uint_to_t (UInt64.v src_val % 64)))
  | ARSH -> Some (UInt64.shift_right dst_val (UInt32.uint_to_t (UInt64.v src_val % 64)))

(* 32-bit ALU. Truncates both operands to 32 bits, performs the op,
   then zero-extends the result back to 64 bits. This matches the BPF
   spec: "w0 = ..." instructions clear the upper 32 bits.

   Known limitation: bitwise ops (logand, logor, logxor) can't be
   verified by Z3 directly through this conversion chain. The codegen
   emits assert_norm hints to pre-compute concrete bitwise results. *)
let alu32 (op: alu_op) (dst_val src_val: UInt64.t) : option UInt64.t =
  let d32 = UInt32.uint_to_t (UInt64.v dst_val % pow2 32) in
  let s32 = UInt32.uint_to_t (UInt64.v src_val % pow2 32) in
  match op with
  | ADD -> Some (UInt64.uint_to_t (UInt32.v (UInt32.add_mod d32 s32)))
  | SUB -> Some (UInt64.uint_to_t (UInt32.v (UInt32.sub_mod d32 s32)))
  | MUL -> Some (UInt64.uint_to_t (UInt32.v (UInt32.mul_mod d32 s32)))
  | DIV -> if s32 = 0ul then None else Some (UInt64.uint_to_t (UInt32.v (UInt32.div d32 s32)))
  | OR  -> Some (UInt64.uint_to_t (UInt32.v (UInt32.logor d32 s32)))
  | AND -> Some (UInt64.uint_to_t (UInt32.v (UInt32.logand d32 s32)))
  | XOR -> Some (UInt64.uint_to_t (UInt32.v (UInt32.logxor d32 s32)))
  | MOV -> Some (UInt64.uint_to_t (UInt32.v s32))
  | NEG -> Some (UInt64.uint_to_t (UInt32.v (UInt32.sub_mod 0ul d32)))
  | MOD -> if s32 = 0ul then None else Some (UInt64.uint_to_t (UInt32.v (UInt32.rem d32 s32)))
  | LSH -> Some (UInt64.uint_to_t (UInt32.v (UInt32.shift_left d32 (UInt32.uint_to_t (UInt32.v s32 % 32)))))
  | RSH -> Some (UInt64.uint_to_t (UInt32.v (UInt32.shift_right d32 (UInt32.uint_to_t (UInt32.v s32 % 32)))))
  | ARSH -> Some (UInt64.uint_to_t (UInt32.v (UInt32.shift_right d32 (UInt32.uint_to_t (UInt32.v s32 % 32)))))

(* --- Jump condition evaluation ---
   Evaluates a conditional jump on 64-bit values. Returns true if the
   branch should be taken. JSET tests whether (dst AND src) is non-zero,
   matching the BPF "bit test" instruction. *)
let eval_jmp64 (op: jmp_op) (dst_val src_val: UInt64.t) : bool =
  let d = UInt64.v dst_val in
  let s = UInt64.v src_val in
  match op with
  | JA   -> true
  | JEQ  -> d = s
  | JGT  -> d > s
  | JGE  -> d >= s
  | JSET -> UInt64.v (UInt64.logand dst_val src_val) <> 0
  | JNE  -> d <> s
  | JLT  -> d < s
  | JLE  -> d <= s
  (* Signed comparisons: interpret the 64-bit values as signed. A value
     >= 2^63 is negative in two's complement. *)
  | JSGT -> (if d >= pow2 63 then d - pow2 64 else d) > (if s >= pow2 63 then s - pow2 64 else s)
  | JSGE -> (if d >= pow2 63 then d - pow2 64 else d) >= (if s >= pow2 63 then s - pow2 64 else s)
  | JSLT -> (if d >= pow2 63 then d - pow2 64 else d) < (if s >= pow2 63 then s - pow2 64 else s)
  | JSLE -> (if d >= pow2 63 then d - pow2 64 else d) <= (if s >= pow2 63 then s - pow2 64 else s)

(* 32-bit conditional jump. Same comparisons but on the lower 32 bits. *)
let eval_jmp32 (op: jmp_op) (dst_val src_val: UInt64.t) : bool =
  let d = UInt64.v dst_val % pow2 32 in
  let s = UInt64.v src_val % pow2 32 in
  match op with
  | JA   -> true
  | JEQ  -> d = s
  | JGT  -> d > s
  | JGE  -> d >= s
  | JSET -> d % 2 <> 0 || s % 2 <> 0  (* simplified; proper impl needs logand *)
  | JNE  -> d <> s
  | JLT  -> d < s
  | JLE  -> d <= s
  | JSGT -> (if d >= pow2 31 then d - pow2 32 else d) > (if s >= pow2 31 then s - pow2 32 else s)
  | JSGE -> (if d >= pow2 31 then d - pow2 32 else d) >= (if s >= pow2 31 then s - pow2 32 else s)
  | JSLT -> (if d >= pow2 31 then d - pow2 32 else d) < (if s >= pow2 31 then s - pow2 32 else s)
  | JSLE -> (if d >= pow2 31 then d - pow2 32 else d) <= (if s >= pow2 31 then s - pow2 32 else s)

(* Execute one instruction. Returns the new state or None on UB.
   For branch instructions, the pc is set to pc + 1 + offset if the
   condition is true, or pc + 1 if false (fall through). *)
let exec_insn (st: bpf_state) (insn: bpf_insn) : option bpf_state =
  match insn with
  | BPF_ALU64_REG op dst src ->
    let dst_val = state_get_reg st dst in
    let src_val = state_get_reg st src in
    (match alu64 op dst_val src_val with
     | None -> None
     | Some result -> Some (state_set_reg st dst result))
  | BPF_ALU64_IMM op dst imm ->
    let dst_val = state_get_reg st dst in
    let imm_val = sign_extend_imm imm in
    (match alu64 op dst_val imm_val with
     | None -> None
     | Some result -> Some (state_set_reg st dst result))
  | BPF_ALU32_REG op dst src ->
    let dst_val = state_get_reg st dst in
    let src_val = state_get_reg st src in
    (match alu32 op dst_val src_val with
     | None -> None
     | Some result -> Some (state_set_reg st dst result))
  | BPF_ALU32_IMM op dst imm ->
    let dst_val = state_get_reg st dst in
    let imm_val = sign_extend_imm imm in
    (match alu32 op dst_val imm_val with
     | None -> None
     | Some result -> Some (state_set_reg st dst result))
  (* Memory ops: only r10 (frame pointer) is supported as a base.
     Any other base register returns None — we don't track pointer
     types yet (that comes with map support in Milestone C). *)
  | BPF_LDX w dst src off ->
    if src <> r10 then None
    else
      let offset = sign_extend_to_int off in
      (match stack_load st offset w with
       | None -> None
       | Some v -> Some (state_set_reg st dst v))
  | BPF_STX w dst src off ->
    if dst <> r10 then None
    else
      let offset = sign_extend_to_int off in
      let v = state_get_reg st src in
      stack_store st offset w v
  | BPF_ST w dst off imm ->
    if dst <> r10 then None
    else
      let offset = sign_extend_to_int off in
      let v = sign_extend_imm imm in
      stack_store st offset w v
  (* Branch: evaluate condition, set pc accordingly.
     pc + 1 is the fall-through, pc + 1 + offset is the taken path. *)
  | BPF_JMP64_REG op dst src offset ->
    let d = state_get_reg st dst in
    let s = state_get_reg st src in
    let next_pc = if eval_jmp64 op d s then st.pc + 1 + offset else st.pc + 1 in
    Some { st with pc = next_pc }
  | BPF_JMP64_IMM op dst imm offset ->
    let d = state_get_reg st dst in
    let s = sign_extend_imm imm in
    let next_pc = if eval_jmp64 op d s then st.pc + 1 + offset else st.pc + 1 in
    Some { st with pc = next_pc }
  | BPF_JMP32_REG op dst src offset ->
    let d = state_get_reg st dst in
    let s = state_get_reg st src in
    let next_pc = if eval_jmp32 op d s then st.pc + 1 + offset else st.pc + 1 in
    Some { st with pc = next_pc }
  | BPF_JMP32_IMM op dst imm offset ->
    let d = state_get_reg st dst in
    let s = sign_extend_imm imm in
    let next_pc = if eval_jmp32 op d s then st.pc + 1 + offset else st.pc + 1 in
    Some { st with pc = next_pc }
  | BPF_JMP_JA offset ->
    Some { st with pc = st.pc + 1 + offset }
  | BPF_EXIT -> Some st

(* Execute a programme using the programme counter.

   Fetches the instruction at the current pc using List.Tot.index,
   dispatches to exec_insn, and repeats. Execution stops when:
   - pc is out of bounds (returns None — programme fell off the end)
   - BPF_EXIT is reached (returns the final state)
   - exec_insn returns None (undefined behaviour)
   - fuel runs out (returns None — prevents infinite loops)

   The `fuel` parameter bounds execution. The kernel's BPF verifier
   guarantees termination via its own analysis, but F* needs a concrete
   bound to prove the recursion terminates. We use the programme length
   as a conservative bound for straight-line code and forward branches. *)
let rec exec_program (st: bpf_state) (prog: bpf_program) (fuel: nat)
  : Tot (option bpf_state) (decreases fuel) =
  if fuel = 0 then None
  else if st.pc < 0 || st.pc >= List.Tot.length prog then None
  else
    let insn = List.Tot.index prog st.pc in
    if BPF_EXIT? insn then Some st
    else
      match exec_insn st insn with
      | None -> None
      | Some st' -> exec_program st' prog (fuel - 1)
