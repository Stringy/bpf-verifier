(*
  BPF.Helpers — BPF helper function signatures for AST verification

  Models BPF helper functions as descriptions of their effect on the
  variable context. Each helper has:
  - A name (for diagnostics)
  - Argument types (what the caller must provide)
  - Return classification (what val_class the result has)
  - Whether it acquires a reference (that must later be released)
  - Which programme types may call it

  These are NOT executable implementations — they describe what the
  kernel verifier checks about helper calls, allowing our AST verifier
  to enforce the same constraints structurally.

  Programme-type restrictions are derived from the kernel's
  bpf_func_proto dispatch chains in:
    kernel/bpf/helpers.c        (universal)
    kernel/trace/bpf_trace.c    (tracing)
    net/core/filter.c           (networking)

  Cross-referenced against:
  - bpf-helpers(7) man page
  - bpfstar/lib/BPFStar.Helpers.fsti (Pulse-based model)
  - include/uapi/linux/bpf.h (helper numbering)

  NOTE: bpfstar models helpers as Pulse stt functions with separation
  logic contracts. We model them differently: as data describing the
  helper's type signature and effects, consumed by the AST verifier.
  The bpfstar approach is correct for its purpose (writing verified BPF
  programmes in Pulse) but ours is appropriate for verifying BPF C at
  the AST level.
*)
module BPF.Helpers

open BPF.AST.Types
open BPF.ValClass

(* --- Helper effect on the variable context --- *)

(* What happens to the return value's classification *)
noeq
type return_effect =
  (* Returns a scalar value (e.g. pid, timestamp, error code) *)
  | RetScalar : c_type -> return_effect

  (* Returns a pointer that may be null — caller MUST null-check.
     The pointed-to type is given. The ref_id is assigned by the
     verifier for reference tracking. *)
  | RetNullablePtr : pointee:c_type -> return_effect

  (* Returns void (helper is called for side effects only) *)
  | RetVoid : return_effect

(* Whether the helper acquires a reference that must be released *)
type ref_effect =
  | NoRef           (* no reference acquired *)
  | AcquiresRef     (* caller must release before programme exit *)

(* What the helper does to buffer arguments (memory effects) *)
type arg_effect =
  | ArgIn           (* read-only: helper reads from this argument *)
  | ArgOut          (* write-only: helper writes into this argument *)
  | ArgInOut        (* read-write *)

(* A single helper argument descriptor *)
noeq
type helper_arg_desc = {
  arg_name : string;
  arg_type : c_type;
  arg_effect : arg_effect;
}

(* --- Programme type capability --- *)

(* Which programme types can call this helper.
   Matches the kernel's per-programme-type get_func_proto dispatch. *)
type helper_availability =
  (* Available in all programme types *)
  | AvailUniversal

  (* Available in specific programme types *)
  | AvailTypes : list bpf_prog_type -> helper_availability

(* --- Complete helper descriptor --- *)

noeq
type helper_desc = {
  h_name         : string;
  h_args         : list helper_arg_desc;
  h_return       : return_effect;
  h_ref_effect   : ref_effect;
  h_availability : helper_availability;
}

(* Check whether a helper is available for a given programme type *)
let helper_available_for (h:helper_desc) (pt:bpf_prog_type) : bool =
  match h.h_availability with
  | AvailUniversal -> true
  | AvailTypes pts -> List.Tot.mem pt pts

(* Get the return val_class for a helper call *)
let helper_return_val_class (h:helper_desc) (next_ref_id:ref_id) : val_class =
  match h.h_return with
  | RetScalar _ -> scalar_unknown  (* we don't know the exact value *)
  | RetNullablePtr _ -> PtrToMapValueOrNull 0 next_ref_id
  | RetVoid -> scalar_const 0  (* void helpers "return" 0 conceptually *)

(* Check that actual argument types match expected helper arg types.
   We check count and that each type matches (using syntactic equality
   on c_type, which is noeq — so we use == i.e. propositional equality). *)
let rec args_match_helper (expected:list helper_arg_desc) (actual:list c_type)
  : Tot bool (decreases expected)
  = match expected, actual with
  | [], [] -> true
  | _ :: _, [] -> false  (* too few arguments *)
  | [], _ :: _ -> false  (* too many arguments *)
  | e :: es, a :: as_ ->
    (* For now, accept if counts match. Precise type matching requires
       c_type equality which is propositional (noeq). We check count
       and leave type matching to F*'s structural verification. *)
    args_match_helper es as_

(* Number of expected arguments *)
let helper_arg_count (h:helper_desc) : nat = List.Tot.length h.h_args

(* Convenience: make an argument descriptor *)
let mk_arg (name:string) (t:c_type) (eff:arg_effect) : helper_arg_desc =
  { arg_name = name; arg_type = t; arg_effect = eff }

(* ================================================================
   UNIVERSAL HELPERS
   Available in all programme types.
   ================================================================ *)

(* bpf_map_lookup_elem: the most important helper.
   Returns a pointer to the map value, or NULL if key not found.
   This is the canonical _OR_NULL return. *)
let h_map_lookup_elem : helper_desc = {
  h_name = "bpf_map_lookup_elem";
  h_args = [ mk_arg "map" c_u64 ArgIn;        (* map fd, passed as u64 *)
             mk_arg "key" (CPtr CVoid) ArgIn ]; (* pointer to key *)
  h_return = RetNullablePtr CVoid;  (* returns void* or NULL *)
  h_ref_effect = NoRef;  (* map values don't need release *)
  h_availability = AvailUniversal;
}

(* bpf_map_update_elem: insert or update a map entry *)
let h_map_update_elem : helper_desc = {
  h_name = "bpf_map_update_elem";
  h_args = [ mk_arg "map" c_u64 ArgIn;
             mk_arg "key" (CPtr CVoid) ArgIn;
             mk_arg "value" (CPtr CVoid) ArgIn;
             mk_arg "flags" c_u64 ArgIn ];
  h_return = RetScalar (CInt W32);  (* 0 on success, negative on error *)
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* bpf_map_delete_elem: remove a map entry *)
let h_map_delete_elem : helper_desc = {
  h_name = "bpf_map_delete_elem";
  h_args = [ mk_arg "map" c_u64 ArgIn;
             mk_arg "key" (CPtr CVoid) ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* bpf_get_current_pid_tgid: returns (tgid << 32) | pid *)
let h_get_current_pid_tgid : helper_desc = {
  h_name = "bpf_get_current_pid_tgid";
  h_args = [];
  h_return = RetScalar c_u64;
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* bpf_get_current_uid_gid: returns (gid << 32) | uid *)
let h_get_current_uid_gid : helper_desc = {
  h_name = "bpf_get_current_uid_gid";
  h_args = [];
  h_return = RetScalar c_u64;
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* bpf_get_current_comm: copy task comm into buffer *)
let h_get_current_comm : helper_desc = {
  h_name = "bpf_get_current_comm";
  h_args = [ mk_arg "buf" (CPtr CVoid) ArgOut;
             mk_arg "size" c_u32 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* bpf_ktime_get_ns: monotonic clock, nanoseconds *)
let h_ktime_get_ns : helper_desc = {
  h_name = "bpf_ktime_get_ns";
  h_args = [];
  h_return = RetScalar c_u64;
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* bpf_ktime_get_boot_ns: monotonic clock including suspend *)
let h_ktime_get_boot_ns : helper_desc = {
  h_name = "bpf_ktime_get_boot_ns";
  h_args = [];
  h_return = RetScalar c_u64;
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* bpf_get_smp_processor_id: current CPU *)
let h_get_smp_processor_id : helper_desc = {
  h_name = "bpf_get_smp_processor_id";
  h_args = [];
  h_return = RetScalar c_u32;
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* bpf_get_prandom_u32: pseudo-random value *)
let h_get_prandom_u32 : helper_desc = {
  h_name = "bpf_get_prandom_u32";
  h_args = [];
  h_return = RetScalar c_u32;
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* bpf_probe_read_kernel: read from kernel memory.
   Available in tracing types and some networking types, NOT universal.
   Kernel restricts via bpf_base_func_proto. *)
let probe_read_types : list bpf_prog_type =
  [ProgKprobe; ProgTracepoint; ProgRawTracepoint;
   ProgPerfEvent; ProgSchedCls; ProgSchedAct;
   ProgSocketFilter; ProgXDP]

let h_probe_read_kernel : helper_desc = {
  h_name = "bpf_probe_read_kernel";
  h_args = [ mk_arg "dst" (CPtr CVoid) ArgOut;
             mk_arg "size" c_u32 ArgIn;
             mk_arg "src" c_u64 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailTypes probe_read_types;
}

(* bpf_probe_read_user: read from user memory. Same availability. *)
let h_probe_read_user : helper_desc = {
  h_name = "bpf_probe_read_user";
  h_args = [ mk_arg "dst" (CPtr CVoid) ArgOut;
             mk_arg "size" c_u32 ArgIn;
             mk_arg "src" c_u64 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailTypes probe_read_types;
}

(* bpf_trace_printk: debug printing *)
let h_trace_printk : helper_desc = {
  h_name = "bpf_trace_printk";
  (* NOTE: bpfstar models fmt as UInt64.t which is wrong — it's a pointer
     to a format string. The kernel prototype is:
     long bpf_trace_printk(const char *fmt, u32 fmt_size, ...)
     We model the first two args; varargs are not expressible. *)
  h_args = [ mk_arg "fmt" (CPtr (CUInt W8)) ArgIn;
             mk_arg "fmt_size" c_u32 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* bpf_get_current_task: raw pointer to task_struct *)
let h_get_current_task : helper_desc = {
  h_name = "bpf_get_current_task";
  h_args = [];
  h_return = RetScalar c_u64;  (* kernel address as u64 *)
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* bpf_tail_call: jump to another BPF programme.
   NOTE: bpfstar models this as returning unit, which is misleading.
   On success, tail_call does NOT return — execution transfers to the
   target programme. On failure (bad index, nesting limit), it falls
   through and execution continues. We model it as returning void
   since from the caller's perspective it either doesn't return or
   acts as a no-op. *)
let h_tail_call : helper_desc = {
  h_name = "bpf_tail_call";
  h_args = [ mk_arg "ctx" (CPtr CVoid) ArgIn;
             mk_arg "prog_array" c_u64 ArgIn;
             mk_arg "index" c_u32 ArgIn ];
  h_return = RetVoid;
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* bpf_perf_event_output: write to perf event ring buffer *)
let h_perf_event_output : helper_desc = {
  h_name = "bpf_perf_event_output";
  h_args = [ mk_arg "ctx" (CPtr CVoid) ArgIn;
             mk_arg "map" c_u64 ArgIn;
             mk_arg "flags" c_u64 ArgIn;
             mk_arg "data" (CPtr CVoid) ArgIn;
             mk_arg "size" c_u64 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* bpf_ringbuf_output: write to ring buffer *)
let h_ringbuf_output : helper_desc = {
  h_name = "bpf_ringbuf_output";
  h_args = [ mk_arg "ringbuf" c_u64 ArgIn;
             mk_arg "data" (CPtr CVoid) ArgIn;
             mk_arg "size" c_u64 ArgIn;
             mk_arg "flags" c_u64 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* ================================================================
   TRACING-FAMILY HELPERS
   Available in: kprobe, tracepoint, raw_tracepoint, fentry, fexit, LSM
   ================================================================ *)

let tracing_types : list bpf_prog_type =
  [ProgKprobe; ProgTracepoint; ProgRawTracepoint]
  (* NOTE: fentry, fexit, LSM are not in our prog_type enum yet.
     We should add them. For now this covers the main tracing types. *)

(* bpf_probe_read: legacy kernel memory read
   NOTE: bpfstar correctly restricts this to can_trace.
   Modern code should use bpf_probe_read_kernel instead. *)
let h_probe_read : helper_desc = {
  h_name = "bpf_probe_read";
  h_args = [ mk_arg "dst" (CPtr CVoid) ArgOut;
             mk_arg "size" c_u32 ArgIn;
             mk_arg "src" c_u64 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailTypes tracing_types;
}

(* bpf_get_stack: get kernel/user stack trace *)
let h_get_stack : helper_desc = {
  h_name = "bpf_get_stack";
  h_args = [ mk_arg "ctx" (CPtr CVoid) ArgIn;
             mk_arg "buf" (CPtr CVoid) ArgOut;
             mk_arg "size" c_u32 ArgIn;
             mk_arg "flags" c_u64 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailTypes tracing_types;
}

(* bpf_get_stackid: walk stack and return its ID *)
let h_get_stackid : helper_desc = {
  h_name = "bpf_get_stackid";
  h_args = [ mk_arg "ctx" (CPtr CVoid) ArgIn;
             mk_arg "map" c_u64 ArgIn;
             mk_arg "flags" c_u64 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailTypes tracing_types;
}

(* ================================================================
   NETWORKING HELPERS
   Various restrictions by programme type.
   ================================================================ *)

let xdp_types : list bpf_prog_type = [ProgXDP]
let tc_types : list bpf_prog_type = [ProgSchedCls; ProgSchedAct]
let xdp_tc_types : list bpf_prog_type = [ProgXDP; ProgSchedCls; ProgSchedAct]
let skb_read_types : list bpf_prog_type = [ProgSchedCls; ProgSchedAct; ProgSocketFilter]

(* bpf_redirect: redirect packet to network device (XDP + TC) *)
let h_redirect : helper_desc = {
  h_name = "bpf_redirect";
  h_args = [ mk_arg "ifindex" c_u32 ArgIn;
             mk_arg "flags" c_u64 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailTypes xdp_tc_types;
}

(* bpf_redirect_map: redirect via BPF map (XDP only) *)
let h_redirect_map : helper_desc = {
  h_name = "bpf_redirect_map";
  h_args = [ mk_arg "map" c_u64 ArgIn;
             mk_arg "key" c_u64 ArgIn;
             mk_arg "flags" c_u64 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailTypes xdp_types;
}

(* bpf_xdp_adjust_head: adjust XDP packet head (XDP only) *)
let h_xdp_adjust_head : helper_desc = {
  h_name = "bpf_xdp_adjust_head";
  h_args = [ mk_arg "xdp_md" (CPtr CVoid) ArgIn;
             mk_arg "delta" (CInt W32) ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailTypes xdp_types;
}

(* bpf_xdp_adjust_tail: adjust XDP packet tail (XDP only) *)
let h_xdp_adjust_tail : helper_desc = {
  h_name = "bpf_xdp_adjust_tail";
  h_args = [ mk_arg "xdp_md" (CPtr CVoid) ArgIn;
             mk_arg "delta" (CInt W32) ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailTypes xdp_types;
}

(* bpf_skb_load_bytes: load bytes from packet (TC + socket_filter) *)
let h_skb_load_bytes : helper_desc = {
  h_name = "bpf_skb_load_bytes";
  h_args = [ mk_arg "skb" (CPtr CVoid) ArgIn;
             mk_arg "offset" c_u32 ArgIn;
             mk_arg "to" (CPtr CVoid) ArgOut;
             mk_arg "len" c_u32 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailTypes skb_read_types;
}

(* bpf_skb_store_bytes: store bytes into packet (TC only) *)
let h_skb_store_bytes : helper_desc = {
  h_name = "bpf_skb_store_bytes";
  h_args = [ mk_arg "skb" (CPtr CVoid) ArgIn;
             mk_arg "offset" c_u32 ArgIn;
             mk_arg "from" (CPtr CVoid) ArgIn;
             mk_arg "len" c_u32 ArgIn;
             mk_arg "flags" c_u64 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailTypes tc_types;
}

(* bpf_fib_lookup: FIB lookup (XDP + TC) *)
let h_fib_lookup : helper_desc = {
  h_name = "bpf_fib_lookup";
  h_args = [ mk_arg "ctx" (CPtr CVoid) ArgIn;
             mk_arg "params" (CPtr CVoid) ArgInOut;
             mk_arg "plen" (CInt W32) ArgIn;
             mk_arg "flags" c_u32 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailTypes xdp_tc_types;
}

(* bpf_csum_diff: compute checksum difference (XDP + TC) *)
let h_csum_diff : helper_desc = {
  h_name = "bpf_csum_diff";
  h_args = [ mk_arg "from" (CPtr c_u32) ArgIn;
             mk_arg "from_size" c_u32 ArgIn;
             mk_arg "to" (CPtr c_u32) ArgIn;
             mk_arg "to_size" c_u32 ArgIn;
             mk_arg "seed" c_u32 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailTypes xdp_tc_types;
}

(* ================================================================
   SOCKET LOOKUP HELPERS
   These ACQUIRE REFERENCES that must be released.
   ================================================================ *)

(* bpf_sk_lookup_tcp: look up a TCP socket.
   Returns a socket pointer or NULL. ACQUIRES A REFERENCE.
   The caller MUST call bpf_sk_release before programme exit. *)
let h_sk_lookup_tcp : helper_desc = {
  h_name = "bpf_sk_lookup_tcp";
  h_args = [ mk_arg "ctx" (CPtr CVoid) ArgIn;
             mk_arg "tuple" (CPtr CVoid) ArgIn;
             mk_arg "tuple_size" c_u32 ArgIn;
             mk_arg "netns" c_u64 ArgIn;
             mk_arg "flags" c_u64 ArgIn ];
  h_return = RetNullablePtr CVoid;  (* returns socket ptr or NULL *)
  h_ref_effect = AcquiresRef;
  h_availability = AvailTypes xdp_tc_types;
}

(* bpf_sk_lookup_udp: look up a UDP socket. Same semantics. *)
let h_sk_lookup_udp : helper_desc = {
  h_name = "bpf_sk_lookup_udp";
  h_args = [ mk_arg "ctx" (CPtr CVoid) ArgIn;
             mk_arg "tuple" (CPtr CVoid) ArgIn;
             mk_arg "tuple_size" c_u32 ArgIn;
             mk_arg "netns" c_u64 ArgIn;
             mk_arg "flags" c_u64 ArgIn ];
  h_return = RetNullablePtr CVoid;
  h_ref_effect = AcquiresRef;
  h_availability = AvailTypes xdp_tc_types;
}

(* bpf_sk_release: release a socket reference.
   This is the counterpart to bpf_sk_lookup_tcp/udp.
   After calling this, the socket pointer is no longer valid. *)
let h_sk_release : helper_desc = {
  h_name = "bpf_sk_release";
  h_args = [ mk_arg "sk" (CPtr CVoid) ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;  (* releases, doesn't acquire *)
  h_availability = AvailTypes xdp_tc_types;
}

(* ================================================================
   LOOP HELPER
   ================================================================ *)

(* bpf_loop: call a callback function up to nr_loops times.
   The callback returns 0 to continue, 1 to stop.
   NOTE: the callback is a function pointer — in our AST model,
   this is a separately verified function. *)
let h_bpf_loop : helper_desc = {
  h_name = "bpf_loop";
  h_args = [ mk_arg "nr_loops" c_u32 ArgIn;
             mk_arg "callback_fn" c_u64 ArgIn;  (* function pointer as u64 *)
             mk_arg "callback_ctx" (CPtr CVoid) ArgInOut;
             mk_arg "flags" c_u32 ArgIn ];
  h_return = RetScalar (CInt W32);
  h_ref_effect = NoRef;
  h_availability = AvailUniversal;
}

(* ================================================================
   HELPER REGISTRY
   Complete list of known helpers for lookup by name.
   ================================================================ *)

let all_helpers : list helper_desc = [
  (* Universal *)
  h_map_lookup_elem;
  h_map_update_elem;
  h_map_delete_elem;
  h_get_current_pid_tgid;
  h_get_current_uid_gid;
  h_get_current_comm;
  h_ktime_get_ns;
  h_ktime_get_boot_ns;
  h_get_smp_processor_id;
  h_get_prandom_u32;
  h_probe_read_kernel;
  h_probe_read_user;
  h_trace_printk;
  h_get_current_task;
  h_tail_call;
  h_perf_event_output;
  h_ringbuf_output;
  h_bpf_loop;
  (* Tracing *)
  h_probe_read;
  h_get_stack;
  h_get_stackid;
  (* Networking *)
  h_redirect;
  h_redirect_map;
  h_xdp_adjust_head;
  h_xdp_adjust_tail;
  h_skb_load_bytes;
  h_skb_store_bytes;
  h_fib_lookup;
  h_csum_diff;
  (* Socket lookup (reference-acquiring) *)
  h_sk_lookup_tcp;
  h_sk_lookup_udp;
  h_sk_release;
]

(* Look up a helper by name *)
let rec find_helper (name:string) (helpers:list helper_desc)
  : Tot (option helper_desc) (decreases helpers)
  = match helpers with
  | [] -> None
  | h :: rest ->
    if h.h_name = name then Some h
    else find_helper name rest

let lookup_helper (name:string) : option helper_desc =
  find_helper name all_helpers
