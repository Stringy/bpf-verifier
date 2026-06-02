module RingBufWrongField

open FStar.UInt64
open BPF.State
open BPF.Spec

(* The programme writes flags=0xAA but the spec expects 0xFF.
   Verification should fail on the NonNull path. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    (state_get_reg final_st r0 == Scalar 0uL /\
     ringbuf_read_any final_st.ringbuf 0 W32 == Some 7uL /\
     ringbuf_read_any final_st.ringbuf 4 W32 == Some 255uL) \/
    state_get_reg final_st r0 == Scalar 1uL
  )
