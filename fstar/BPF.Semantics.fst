(* BPF.Semantics — formal semantics for BPF instructions.

   Each BPF instruction is modelled as a state transition:
     exec_insn : bpf_state -> bpf_insn -> option bpf_state

   Returns None on undefined behaviour (division by zero, out-of-bounds
   stack access, null pointer dereference, type mismatch). The verifier
   rejects programmes that can reach None.

   Registers hold typed values (Scalar, FramePtr, MapValuePtr, Null).
   ALU ops require scalar operands. Memory loads through FramePtr access
   the stack; loads through MapValuePtr access map values; loads through
   Scalar or Null are UB.

   F* notes:
   - `Int32.t` is a signed 32-bit integer — BPF immediates are signed
   - `option bpf_state` is like a Result: Some state or None (error)
   - `Tot` means the function is total (always terminates)
*)
module BPF.Semantics

open FStar.Mul
open FStar.UInt64
open FStar.UInt32
open FStar.Int32
open FStar.Int.Cast
open BPF.State

type alu_op =
  | ADD | SUB | MUL | DIV | OR | AND
  | LSH | RSH | NEG | MOD | XOR | MOV | ARSH

type jmp_op =
  | JA
  | JEQ | JGT | JGE | JSET
  | JNE | JLT | JLE
  | JSGT | JSGE | JSLT | JSLE

(* BPF helper function IDs. Only map_lookup_elem is modelled so far. *)
type helper_id =
  | MAP_LOOKUP_ELEM  (* helper #1 *)
  | UNKNOWN_HELPER : nat -> helper_id

type bpf_insn =
  | BPF_ALU64_REG : alu_op -> reg_idx -> reg_idx -> bpf_insn
  | BPF_ALU64_IMM : alu_op -> reg_idx -> Int32.t -> bpf_insn
  | BPF_ALU32_REG : alu_op -> reg_idx -> reg_idx -> bpf_insn
  | BPF_ALU32_IMM : alu_op -> reg_idx -> Int32.t -> bpf_insn
  | BPF_LDX : mem_width -> reg_idx -> reg_idx -> Int32.t -> bpf_insn
  | BPF_STX : mem_width -> reg_idx -> reg_idx -> Int32.t -> bpf_insn
  | BPF_ST  : mem_width -> reg_idx -> Int32.t -> Int32.t -> bpf_insn
  | BPF_LD_IMM64 : reg_idx -> UInt64.t -> bpf_insn
  | BPF_JMP64_REG : jmp_op -> reg_idx -> reg_idx -> i16:int -> bpf_insn
  | BPF_JMP64_IMM : jmp_op -> reg_idx -> Int32.t -> i16:int -> bpf_insn
  | BPF_JMP32_REG : jmp_op -> reg_idx -> reg_idx -> i16:int -> bpf_insn
  | BPF_JMP32_IMM : jmp_op -> reg_idx -> Int32.t -> i16:int -> bpf_insn
  | BPF_JMP_JA : i16:int -> bpf_insn
  | BPF_CALL : helper_id -> bpf_insn
  | BPF_EXIT : bpf_insn

type bpf_program = list bpf_insn

let sign_extend_imm (imm: Int32.t) : UInt64.t =
  let i64 = int32_to_int64 imm in
  FStar.Int.Cast.Full.int64_to_uint64 i64

let sign_extend_to_int (imm: Int32.t) : int =
  Int32.v imm

(* 64-bit ALU — operates on scalar values only.
   All arithmetic wraps. Division/modulo by zero is UB. *)
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

(* 32-bit ALU — truncates to 32 bits, zero-extends result to 64. *)
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

(* Jump condition evaluation on 64-bit values. *)
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
  | JSGT -> (if d >= pow2 63 then d - pow2 64 else d) > (if s >= pow2 63 then s - pow2 64 else s)
  | JSGE -> (if d >= pow2 63 then d - pow2 64 else d) >= (if s >= pow2 63 then s - pow2 64 else s)
  | JSLT -> (if d >= pow2 63 then d - pow2 64 else d) < (if s >= pow2 63 then s - pow2 64 else s)
  | JSLE -> (if d >= pow2 63 then d - pow2 64 else d) <= (if s >= pow2 63 then s - pow2 64 else s)

let eval_jmp32 (op: jmp_op) (dst_val src_val: UInt64.t) : bool =
  let d = UInt64.v dst_val % pow2 32 in
  let s = UInt64.v src_val % pow2 32 in
  match op with
  | JA   -> true
  | JEQ  -> d = s
  | JGT  -> d > s
  | JGE  -> d >= s
  | JSET -> d % 2 <> 0 || s % 2 <> 0
  | JNE  -> d <> s
  | JLT  -> d < s
  | JLE  -> d <= s
  | JSGT -> (if d >= pow2 31 then d - pow2 32 else d) > (if s >= pow2 31 then s - pow2 32 else s)
  | JSGE -> (if d >= pow2 31 then d - pow2 32 else d) >= (if s >= pow2 31 then s - pow2 32 else s)
  | JSLT -> (if d >= pow2 31 then d - pow2 32 else d) < (if s >= pow2 31 then s - pow2 32 else s)
  | JSLE -> (if d >= pow2 31 then d - pow2 32 else d) <= (if s >= pow2 31 then s - pow2 32 else s)

(* Evaluate a jump condition on typed register values. For comparisons
   against 0 (null checks), we handle the pointer cases: MapValuePtr
   and FramePtr are non-zero, Null is zero. For all other comparisons,
   both operands must be scalars. *)
let reg_val_for_jmp (v: reg_val) : option UInt64.t =
  match v with
  | Scalar n -> Some n
  | Null -> Some 0uL
  | MapValuePtr _ -> None
  | FramePtr -> None

(* Check if a register value is "truthy" for branch purposes.
   Non-null pointers are truthy, null is falsy, scalars compare normally. *)
let reg_val_is_zero (v: reg_val) : option bool =
  match v with
  | Scalar n -> Some (n = 0uL)
  | Null -> Some true
  | MapValuePtr _ -> Some false
  | FramePtr -> Some false

(* Execute one instruction. Returns the new state or None on UB.

   ALU ops extract scalar values — performing arithmetic on a pointer is UB.
   MOV with immediate always produces a Scalar.

   Memory loads dispatch on the base register type:
   - FramePtr -> stack access (as before)
   - MapValuePtr -> read from map value memory
   - Scalar/Null -> UB (invalid pointer dereference)

   BPF_CALL for MAP_LOOKUP_ELEM: r0 gets either MapValuePtr (found) or
   Null (not found). The choice is non-deterministic — the verifier must
   prove the spec holds in both cases. We model this by giving back a
   fresh MapValuePtr; the programme must null-check before use. *)
let exec_insn (st: bpf_state) (insn: bpf_insn) : option bpf_state =
  match insn with
  | BPF_ALU64_REG op dst src ->
    (match scalar_val (state_get_reg st dst), scalar_val (state_get_reg st src) with
     | Some dv, Some sv ->
       (match alu64 op dv sv with
        | None -> None
        | Some result -> Some (state_set_reg st dst (Scalar result)))
     | _, _ -> None)
  | BPF_ALU64_IMM op dst imm ->
    (match scalar_val (state_get_reg st dst) with
     | Some dv ->
       let iv = sign_extend_imm imm in
       (match alu64 op dv iv with
        | None -> None
        | Some result -> Some (state_set_reg st dst (Scalar result)))
     | None ->
       if op = MOV then Some (state_set_reg st dst (Scalar (sign_extend_imm imm)))
       else None)
  | BPF_ALU32_REG op dst src ->
    (match scalar_val (state_get_reg st dst), scalar_val (state_get_reg st src) with
     | Some dv, Some sv ->
       (match alu32 op dv sv with
        | None -> None
        | Some result -> Some (state_set_reg st dst (Scalar result)))
     | _, _ -> None)
  | BPF_ALU32_IMM op dst imm ->
    (match scalar_val (state_get_reg st dst) with
     | Some dv ->
       let iv = sign_extend_imm imm in
       (match alu32 op dv iv with
        | None -> None
        | Some result -> Some (state_set_reg st dst (Scalar result)))
     | None ->
       if op = MOV then Some (state_set_reg st dst (Scalar (sign_extend_imm imm)))
       else None)
  | BPF_LD_IMM64 dst imm ->
    Some (state_set_reg st dst (Scalar imm))
  | BPF_LDX w dst src off ->
    let base = state_get_reg st src in
    (match base with
     | FramePtr ->
       let offset = sign_extend_to_int off in
       (match stack_load st offset w with
        | None -> None
        | Some v -> Some (state_set_reg st dst (Scalar v)))
     | MapValuePtr id ->
       (match map_value_read st.map_values id with
        | None -> None
        | Some v -> Some (state_set_reg st dst (Scalar v)))
     | Null -> None
     | Scalar _ -> None)
  | BPF_STX w dst src off ->
    let base = state_get_reg st dst in
    (match base with
     | FramePtr ->
       let offset = sign_extend_to_int off in
       (match scalar_val (state_get_reg st src) with
        | Some v -> stack_store st offset w v
        | None -> None)
     | _ -> None)
  | BPF_ST w dst off imm ->
    let base = state_get_reg st dst in
    (match base with
     | FramePtr ->
       let offset = sign_extend_to_int off in
       let v = sign_extend_imm imm in
       stack_store st offset w v
     | _ -> None)
  | BPF_JMP64_REG op dst src offset ->
    (match reg_val_for_jmp (state_get_reg st dst), reg_val_for_jmp (state_get_reg st src) with
     | Some d, Some s ->
       let next_pc = if eval_jmp64 op d s then st.pc + 1 + offset else st.pc + 1 in
       Some { st with pc = next_pc }
     | _, _ -> None)
  | BPF_JMP64_IMM op dst imm offset ->
    if op = JEQ || op = JNE then
      (match reg_val_is_zero (state_get_reg st dst) with
       | Some is_zero ->
         let imm_val = sign_extend_imm imm in
         let cond = (match op with
           | JEQ -> if UInt64.v imm_val = 0 then is_zero else not is_zero
           | JNE -> if UInt64.v imm_val = 0 then not is_zero else is_zero
           | _ -> false) in
         let next_pc = if cond then st.pc + 1 + offset else st.pc + 1 in
         Some { st with pc = next_pc }
       | None -> None)
    else
      (match scalar_val (state_get_reg st dst) with
       | Some d ->
         let s = sign_extend_imm imm in
         let next_pc = if eval_jmp64 op d s then st.pc + 1 + offset else st.pc + 1 in
         Some { st with pc = next_pc }
       | None -> None)
  | BPF_JMP32_REG op dst src offset ->
    (match scalar_val (state_get_reg st dst), scalar_val (state_get_reg st src) with
     | Some d, Some s ->
       let next_pc = if eval_jmp32 op d s then st.pc + 1 + offset else st.pc + 1 in
       Some { st with pc = next_pc }
     | _, _ -> None)
  | BPF_JMP32_IMM op dst imm offset ->
    (match scalar_val (state_get_reg st dst) with
     | Some d ->
       let s = sign_extend_imm imm in
       let next_pc = if eval_jmp32 op d s then st.pc + 1 + offset else st.pc + 1 in
       Some { st with pc = next_pc }
     | None -> None)
  | BPF_JMP_JA offset ->
    Some { st with pc = st.pc + 1 + offset }
  (* BPF_CALL: helper function call.
     MAP_LOOKUP_ELEM: r1 = map, r2 = key pointer. Returns a MapValuePtr
     or Null in r0. We allocate a fresh map ID and associate it with a
     symbolic value. The programme must branch on r0 before dereferencing.

     The map value is added to map_values so that a subsequent LDX through
     the MapValuePtr can read it. The value is unconstrained — the spec
     cannot assume any particular map contents. *)
  | BPF_CALL MAP_LOOKUP_ELEM ->
    let id = st.next_map_id in
    Some { st with
      regs = set_reg st.regs r0 (MapValuePtr id);
      pc = st.pc + 1;
      next_map_id = id + 1 }
  | BPF_CALL (UNKNOWN_HELPER _) -> None
  | BPF_EXIT -> Some st

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
