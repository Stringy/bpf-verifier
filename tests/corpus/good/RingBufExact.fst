module RingBufExact

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Intent: prove the programme writes *exactly* two fields to the
   ring buffer — type=7 at offset 0 and flags=0xFF at offset 4 —
   and nothing else. If reserve fails, returns 1 with no writes.

   The precondition requires an empty initial ring buffer so we
   can assert the exact count of writes. *)
let spec : bpf_spec =
  with_pre (fun init_st -> ringbuf_length init_st.ringbuf == 0)
    (post_only (fun final_st ->
      (state_get_reg final_st r0 == Scalar 0uL /\
       ringbuf_length final_st.ringbuf == 2 /\
       ringbuf_read_any final_st.ringbuf 0 W32 == Some 7uL /\
       ringbuf_read_any final_st.ringbuf 4 W32 == Some 255uL) \/
      (state_get_reg final_st r0 == Scalar 1uL /\
       ringbuf_length final_st.ringbuf == 0)
    ))
