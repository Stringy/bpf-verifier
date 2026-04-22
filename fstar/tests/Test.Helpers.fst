(* Test the helper registry returns correct specs for all known helpers. *)
module Test.Helpers

open FStar.UInt64
open FStar.Int32
open BPF.State
open BPF.Helpers

(* All known helpers have specs in the registry *)
let registry_test : squash (Some? (get_helper_spec MAP_LOOKUP_ELEM) /\
                            Some? (get_helper_spec MAP_UPDATE_ELEM) /\
                            Some? (get_helper_spec MAP_DELETE_ELEM) /\
                            Some? (get_helper_spec PROBE_READ) /\
                            Some? (get_helper_spec KTIME_GET_NS) /\
                            Some? (get_helper_spec GET_PRANDOM_U32) /\
                            None? (get_helper_spec (UNKNOWN_HELPER 99))) =
  assert_norm (Some? (get_helper_spec MAP_LOOKUP_ELEM) /\
               Some? (get_helper_spec MAP_UPDATE_ELEM) /\
               Some? (get_helper_spec MAP_DELETE_ELEM) /\
               Some? (get_helper_spec PROBE_READ) /\
               Some? (get_helper_spec KTIME_GET_NS) /\
               Some? (get_helper_spec GET_PRANDOM_U32) /\
               None? (get_helper_spec (UNKNOWN_HELPER 99)))

(* MAP_LOOKUP_ELEM returns a map pointer *)
let map_lookup_ret : squash ((Some?.v (get_helper_spec MAP_LOOKUP_ELEM)).ret_type = RetMapPtr) =
  assert_norm ((Some?.v (get_helper_spec MAP_LOOKUP_ELEM)).ret_type = RetMapPtr)

(* KTIME_GET_NS returns a scalar *)
let ktime_ret : squash ((Some?.v (get_helper_spec KTIME_GET_NS)).ret_type = RetScalar) =
  assert_norm ((Some?.v (get_helper_spec KTIME_GET_NS)).ret_type = RetScalar)

(* MAP_UPDATE_ELEM returns error code with WriteMapValue effect *)
let map_update_spec : squash ((Some?.v (get_helper_spec MAP_UPDATE_ELEM)).ret_type = RetErrorCode /\
                               (Some?.v (get_helper_spec MAP_UPDATE_ELEM)).side_effect = WriteMapValue) =
  assert_norm ((Some?.v (get_helper_spec MAP_UPDATE_ELEM)).ret_type = RetErrorCode /\
               (Some?.v (get_helper_spec MAP_UPDATE_ELEM)).side_effect = WriteMapValue)
