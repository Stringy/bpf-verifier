module BPF.Semantics

open FStar.UInt64
open FStar.UInt32
open FStar.Int32
open FStar.Int.Cast
open BPF.State

type alu_op =
  | ADD | SUB | MUL | DIV | OR | AND
  | LSH | RSH | NEG | MOD | XOR | MOV | ARSH

type bpf_insn =
  | BPF_ALU64_REG : alu_op -> reg_idx -> reg_idx -> bpf_insn
  | BPF_ALU64_IMM : alu_op -> reg_idx -> Int32.t -> bpf_insn
  | BPF_ALU32_REG : alu_op -> reg_idx -> reg_idx -> bpf_insn
  | BPF_ALU32_IMM : alu_op -> reg_idx -> Int32.t -> bpf_insn
  | BPF_EXIT : bpf_insn

type bpf_program = list bpf_insn

let sign_extend_imm (imm: Int32.t) : UInt64.t =
  let i64 = int32_to_int64 imm in
  FStar.Int.Cast.Full.int64_to_uint64 i64

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

let alu32 (op: alu_op) (dst_val src_val: UInt64.t) : option UInt64.t =
  let d32 = UInt32.uint_to_t (UInt64.v dst_val % pow2 32) in
  let s32 = UInt32.uint_to_t (UInt64.v src_val % pow2 32) in
  let result_32 : option UInt32.t = match op with
    | ADD -> Some (UInt32.add_mod d32 s32)
    | SUB -> Some (UInt32.sub_mod d32 s32)
    | MUL -> Some (UInt32.mul_mod d32 s32)
    | DIV -> if s32 = 0ul then None else Some (UInt32.div d32 s32)
    | OR  -> Some (UInt32.logor d32 s32)
    | AND -> Some (UInt32.logand d32 s32)
    | XOR -> Some (UInt32.logxor d32 s32)
    | MOV -> Some s32
    | NEG -> Some (UInt32.sub_mod 0ul d32)
    | MOD -> if s32 = 0ul then None else Some (UInt32.rem d32 s32)
    | LSH -> Some (UInt32.shift_left d32 (UInt32.uint_to_t (UInt32.v s32 % 32)))
    | RSH -> Some (UInt32.shift_right d32 (UInt32.uint_to_t (UInt32.v s32 % 32)))
    | ARSH -> Some (UInt32.shift_right d32 (UInt32.uint_to_t (UInt32.v s32 % 32)))
  in
  match result_32 with
  | None -> None
  | Some r -> Some (UInt64.uint_to_t (UInt32.v r))

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
  | BPF_EXIT -> Some st

let rec exec_program (st: bpf_state) (prog: bpf_program)
  : Tot (option bpf_state) (decreases (List.Tot.length prog)) =
  match prog with
  | [] -> Some st
  | BPF_EXIT :: _ -> Some st
  | insn :: rest ->
    match exec_insn st insn with
    | None -> None
    | Some st' -> exec_program st' rest
