module RingBufExact

open FStar.UInt64
open BPF.State
open BPF.Spec
open Fields

(* Intent: prove the programme writes *exactly* two fields to the
   ring buffer — type=7 and flags=0xFF — and nothing else.
   If reserve fails, returns 1 with no writes.

   event_type and event_flags are auto-generated from DWARF. *)
let spec : bpf_spec =
  with_pre (fun init_st -> ringbuf_write_count init_st.ringbuf == 0)
    (post_only (fun final_st ->
      (state_get_reg final_st r0 == Scalar 0uL /\
       ringbuf_write_count final_st.ringbuf == 2 /\
       event_type final_st.ringbuf == Some 7uL /\
       event_flags final_st.ringbuf == Some 255uL) \/
      (state_get_reg final_st r0 == Scalar 1uL /\
       ringbuf_write_count final_st.ringbuf == 0)
    ))
