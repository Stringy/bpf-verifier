#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperReturn {
    Scalar,
    MapPtr,
    ErrorCode,
}

#[derive(Debug, Clone, Copy)]
pub struct HelperSpec {
    pub id: i32,
    pub name: &'static str,
    pub ret_type: HelperReturn,
}

const HELPERS: &[HelperSpec] = &[
    HelperSpec { id: 1,   name: "MAP_LOOKUP_ELEM",      ret_type: HelperReturn::MapPtr },
    HelperSpec { id: 2,   name: "MAP_UPDATE_ELEM",       ret_type: HelperReturn::ErrorCode },
    HelperSpec { id: 3,   name: "MAP_DELETE_ELEM",       ret_type: HelperReturn::ErrorCode },
    HelperSpec { id: 4,   name: "PROBE_READ",            ret_type: HelperReturn::ErrorCode },
    HelperSpec { id: 5,   name: "KTIME_GET_NS",          ret_type: HelperReturn::Scalar },
    HelperSpec { id: 6,   name: "TRACE_PRINTK",          ret_type: HelperReturn::ErrorCode },
    HelperSpec { id: 7,   name: "GET_PRANDOM_U32",       ret_type: HelperReturn::Scalar },
    HelperSpec { id: 14,  name: "GET_CURRENT_PID_TGID",  ret_type: HelperReturn::Scalar },
    HelperSpec { id: 15,  name: "GET_CURRENT_UID_GID",   ret_type: HelperReturn::Scalar },
    HelperSpec { id: 16,  name: "GET_CURRENT_COMM",      ret_type: HelperReturn::ErrorCode },
    HelperSpec { id: 35,  name: "GET_CURRENT_TASK",      ret_type: HelperReturn::Scalar },
    HelperSpec { id: 45,  name: "PROBE_READ_STR",        ret_type: HelperReturn::ErrorCode },
    HelperSpec { id: 112, name: "PROBE_READ_USER",       ret_type: HelperReturn::ErrorCode },
    HelperSpec { id: 113, name: "PROBE_READ_KERNEL",     ret_type: HelperReturn::ErrorCode },
    HelperSpec { id: 115, name: "PROBE_READ_KERNEL_STR", ret_type: HelperReturn::ErrorCode },
    HelperSpec { id: 125, name: "KTIME_GET_BOOT_NS",     ret_type: HelperReturn::Scalar },
    HelperSpec { id: 131, name: "RINGBUF_RESERVE",       ret_type: HelperReturn::MapPtr },
    HelperSpec { id: 132, name: "RINGBUF_SUBMIT",        ret_type: HelperReturn::ErrorCode },
    HelperSpec { id: 133, name: "RINGBUF_DISCARD",       ret_type: HelperReturn::ErrorCode },
    HelperSpec { id: 147, name: "D_PATH",                ret_type: HelperReturn::ErrorCode },
    HelperSpec { id: 158, name: "GET_CURRENT_TASK_BTF",  ret_type: HelperReturn::Scalar },
];

pub fn get_helper(id: i32) -> Option<&'static HelperSpec> {
    HELPERS.iter().find(|h| h.id == id)
}

pub fn returns_map_ptr(id: i32) -> bool {
    get_helper(id).is_some_and(|h| h.ret_type == HelperReturn::MapPtr)
}
