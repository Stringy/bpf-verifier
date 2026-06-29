(*
  BPF.AST.Decl — Top-level declarations

  A BPF object file contains:
  - Map definitions (specifying type, key size, value size, max entries)
  - Programme functions (with a section attribute indicating the programme type)
  - Global variables (rarely, but possible)

  A well-formed BPF programme is a collection of map definitions plus
  one or more programme functions, each of which is a verified statement
  that transforms an initial context (with the programme's ctx parameter)
  to an exit context (empty, via Return).
*)
module BPF.AST.Decl

open BPF.AST.Types
open BPF.AST.Expr
open BPF.AST.Stmt
open BPF.VarCtx
open BPF.ValClass

(* --- Map definitions --- *)

(* BPF map types (a subset — the most common ones) *)
type bpf_map_type =
  | MapHash
  | MapArray
  | MapPerCPUHash
  | MapPerCPUArray
  | MapLRUHash
  | MapLRUPerCPUHash
  | MapRingBuf
  | MapPerfEventArray

(* A map definition: corresponds to a struct bpf_map_def or BTF-defined map *)
noeq
type map_def = {
  map_name      : string;
  map_type      : bpf_map_type;
  map_key_type  : c_type;
  map_val_type  : c_type;
  map_max_entries : pos;
}

(* --- Programme type context mapping --- *)

(* The context structure type for a given programme type.
   Each programme type receives a different context struct. *)
let prog_ctx_type (pt:bpf_prog_type) : struct_def =
  match pt with
  | ProgSocketFilter -> { struct_name = "__sk_buff";
                           fields = [("len", c_u32);
                                     ("protocol", c_u32);
                                     ("data", c_u32);
                                     ("data_end", c_u32)] }
  | ProgXDP -> { struct_name = "xdp_md";
                  fields = [("data", c_u32);
                            ("data_end", c_u32);
                            ("data_meta", c_u32);
                            ("ingress_ifindex", c_u32);
                            ("rx_queue_index", c_u32)] }
  | ProgKprobe -> { struct_name = "pt_regs";
                     fields = [("di", c_u64); ("si", c_u64);
                               ("dx", c_u64); ("cx", c_u64);
                               ("r8", c_u64); ("r9", c_u64);
                               ("ax", c_u64); ("sp", c_u64);
                               ("ip", c_u64)] }
  (* Other programme types get a minimal context for now *)
  | _ -> { struct_name = "bpf_ctx"; fields = [] }

(* Valid return value range for each programme type *)
let valid_return_range (pt:bpf_prog_type) : option (nat & nat) =
  match pt with
  | ProgXDP -> Some (0, 4)  (* XDP_ABORTED=0 through XDP_REDIRECT=4 *)
  | ProgSocketFilter -> None  (* any int: 0=drop, >0=trim *)
  | ProgCgroupSkb -> Some (0, 1)  (* 0=deny, 1=allow *)
  | _ -> None  (* no range restriction *)

(* --- Programme function --- *)

(*
  A verified BPF programme function.

  The programme takes a context pointer as its single argument.
  The initial variable context has one variable: "ctx" with classification
  PtrToCtx. The function body is a statement that transforms this context
  to the empty context (via Return).

  The type indices enforce:
  - The body starts with the correct initial context
  - The body ends with Return (output context is [])
  - All variables referenced in the body are in scope
  - No null-unsafe dereferences
  - All references released before Return
*)
noeq
type bpf_prog = {
  prog_name : string;
  prog_type : bpf_prog_type;
  prog_maps : list map_def;
  prog_body : stmt prog_type (initial_ctx prog_type) [];
}

(* The initial variable context for a programme: just "ctx" as PtrToCtx *)
and initial_ctx (pt:bpf_prog_type) : var_ctx =
  [("ctx", PtrToCtx 0)]

(* --- Full BPF object --- *)

(* A complete BPF object file: maps + programmes *)
noeq
type bpf_object = {
  obj_maps : list map_def;
  obj_progs : list bpf_prog;
}
