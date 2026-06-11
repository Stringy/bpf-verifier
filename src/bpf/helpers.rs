#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperReturn {
    Scalar,
    MapPtr,
    RingBufPtr,
    ErrorCode,
    /// Returns a kernel pointer (e.g. bpf_get_current_task_btf).
    KernelPtr,
}

/// Expected type for a helper argument register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgType {
    /// Any value (scalar or pointer) -- not checked.
    Any,
    /// Must be a scalar (not a pointer).
    Scalar,
    /// Must be a pointer to stack memory of known size.
    PtrToStack,
    /// Must be a pointer to a map (LD_IMM64 map fd -- we accept any scalar
    /// since map fds are loaded as immediates).
    MapPtr,
    /// Must be a pointer to map key (stack pointer).
    PtrToMapKey,
    /// Must be a pointer to map value (stack pointer or map value pointer).
    PtrToMapValue,
    /// Must be a scalar (the size argument for probe_read etc.).
    Size,
    /// Must be a pointer to a ring buffer reservation.
    PtrToRingBuf,
    /// Flags argument (scalar).
    Flags,
    /// Must be a pointer to any writable memory (stack, map value, ringbuf).
    PtrToMem,
    /// Must be a pointer to readable memory (stack, map value, rodata/data).
    PtrToReadonlyMem,
}

impl ArgType {
    pub fn description(&self) -> &'static str {
        match self {
            ArgType::Any => "any",
            ArgType::Scalar => "scalar",
            ArgType::PtrToStack => "pointer to stack",
            ArgType::MapPtr => "map pointer",
            ArgType::PtrToMapKey => "pointer to map key",
            ArgType::PtrToMapValue => "pointer to map value",
            ArgType::Size => "size (scalar)",
            ArgType::PtrToRingBuf => "pointer to ring buffer",
            ArgType::Flags => "flags (scalar)",
            ArgType::PtrToMem => "pointer to memory",
            ArgType::PtrToReadonlyMem => "pointer to readable memory",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HelperSpec {
    pub id: i32,
    pub name: &'static str,
    pub ret_type: HelperReturn,
    /// Expected types for arguments r1-r5. `None` means the argument is unused.
    pub args: [Option<ArgType>; 5],
}

const HELPERS: &[HelperSpec] = &[
    HelperSpec {
        id: 1, name: "MAP_LOOKUP_ELEM", ret_type: HelperReturn::MapPtr,
        args: [Some(ArgType::MapPtr), Some(ArgType::PtrToMapKey), None, None, None],
    },
    HelperSpec {
        id: 2, name: "MAP_UPDATE_ELEM", ret_type: HelperReturn::ErrorCode,
        args: [Some(ArgType::MapPtr), Some(ArgType::PtrToMapKey), Some(ArgType::PtrToMapValue), Some(ArgType::Flags), None],
    },
    HelperSpec {
        id: 3, name: "MAP_DELETE_ELEM", ret_type: HelperReturn::ErrorCode,
        args: [Some(ArgType::MapPtr), Some(ArgType::PtrToMapKey), None, None, None],
    },
    HelperSpec {
        id: 4, name: "PROBE_READ", ret_type: HelperReturn::ErrorCode,
        args: [Some(ArgType::PtrToMem), Some(ArgType::Size), Some(ArgType::Scalar), None, None],
    },
    HelperSpec {
        id: 5, name: "KTIME_GET_NS", ret_type: HelperReturn::Scalar,
        args: [None, None, None, None, None],
    },
    HelperSpec {
        id: 6, name: "TRACE_PRINTK", ret_type: HelperReturn::ErrorCode,
        args: [Some(ArgType::PtrToReadonlyMem), Some(ArgType::Size), None, None, None],
    },
    HelperSpec {
        id: 7, name: "GET_PRANDOM_U32", ret_type: HelperReturn::Scalar,
        args: [None, None, None, None, None],
    },
    HelperSpec {
        id: 14, name: "GET_CURRENT_PID_TGID", ret_type: HelperReturn::Scalar,
        args: [None, None, None, None, None],
    },
    HelperSpec {
        id: 15, name: "GET_CURRENT_UID_GID", ret_type: HelperReturn::Scalar,
        args: [None, None, None, None, None],
    },
    HelperSpec {
        id: 16, name: "GET_CURRENT_COMM", ret_type: HelperReturn::ErrorCode,
        args: [Some(ArgType::PtrToMem), Some(ArgType::Size), None, None, None],
    },
    HelperSpec {
        id: 35, name: "GET_CURRENT_TASK", ret_type: HelperReturn::KernelPtr,
        args: [None, None, None, None, None],
    },
    HelperSpec {
        id: 45, name: "PROBE_READ_STR", ret_type: HelperReturn::ErrorCode,
        args: [Some(ArgType::PtrToMem), Some(ArgType::Size), Some(ArgType::Any), None, None],
    },
    HelperSpec {
        id: 112, name: "PROBE_READ_USER", ret_type: HelperReturn::ErrorCode,
        args: [Some(ArgType::PtrToMem), Some(ArgType::Size), Some(ArgType::Scalar), None, None],
    },
    HelperSpec {
        id: 113, name: "PROBE_READ_KERNEL", ret_type: HelperReturn::ErrorCode,
        args: [Some(ArgType::PtrToMem), Some(ArgType::Size), Some(ArgType::Scalar), None, None],
    },
    HelperSpec {
        id: 115, name: "PROBE_READ_KERNEL_STR", ret_type: HelperReturn::ErrorCode,
        args: [Some(ArgType::PtrToMem), Some(ArgType::Size), Some(ArgType::Scalar), None, None],
    },
    HelperSpec {
        id: 125, name: "KTIME_GET_BOOT_NS", ret_type: HelperReturn::Scalar,
        args: [None, None, None, None, None],
    },
    HelperSpec {
        id: 131, name: "RINGBUF_RESERVE", ret_type: HelperReturn::RingBufPtr,
        args: [Some(ArgType::MapPtr), Some(ArgType::Size), Some(ArgType::Flags), None, None],
    },
    HelperSpec {
        id: 132, name: "RINGBUF_SUBMIT", ret_type: HelperReturn::ErrorCode,
        args: [Some(ArgType::PtrToRingBuf), Some(ArgType::Flags), None, None, None],
    },
    HelperSpec {
        id: 133, name: "RINGBUF_DISCARD", ret_type: HelperReturn::ErrorCode,
        args: [Some(ArgType::PtrToRingBuf), Some(ArgType::Flags), None, None, None],
    },
    HelperSpec {
        id: 147, name: "D_PATH", ret_type: HelperReturn::ErrorCode,
        args: [Some(ArgType::Scalar), Some(ArgType::PtrToMem), Some(ArgType::Size), None, None],
    },
    HelperSpec {
        id: 158, name: "GET_CURRENT_TASK_BTF", ret_type: HelperReturn::KernelPtr,
        args: [None, None, None, None, None],
    },
    HelperSpec {
        id: 181, name: "LOOP", ret_type: HelperReturn::Scalar,
        args: [Some(ArgType::Scalar), Some(ArgType::Any), Some(ArgType::Any), Some(ArgType::Flags), None],
    },
];

pub fn get_helper(id: i32) -> Option<&'static HelperSpec> {
    HELPERS.iter().find(|h| h.id == id)
}

pub fn returns_nullable_ptr(id: i32) -> bool {
    get_helper(id).is_some_and(|h| {
        matches!(h.ret_type, HelperReturn::MapPtr | HelperReturn::RingBufPtr)
    })
}

pub fn returns_map_ptr(id: i32) -> bool {
    get_helper(id).is_some_and(|h| matches!(h.ret_type, HelperReturn::MapPtr))
}
