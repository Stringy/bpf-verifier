module RingBufEvent

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Intent: reserve a ring buffer slot, write a two-field event
   (type=7, flags=0xFF), submit, return 0. If reserve fails, return 1.

   The spec verifies the event contents: on the success path,
   the ring buffer contains 7 at offset 0 and 255 at offset 4. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    (state_get_reg final_st r0 == Scalar 0uL /\
     ringbuf_read_any final_st.ringbuf 0 W32 == Some 7uL /\
     ringbuf_read_any final_st.ringbuf 4 W32 == Some 255uL) \/
    state_get_reg final_st r0 == Scalar 1uL
  )
