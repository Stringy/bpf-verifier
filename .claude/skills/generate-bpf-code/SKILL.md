---
name: generate-bpf-code
description: Generate a BPF C programme from an F* spec file. Reads the spec's Intent comment to understand what to build, writes a .bpf.c file that should satisfy the spec when verified.
---

# Generate BPF C Programme from Spec

You are generating a BPF C programme that satisfies a formal F* specification. The spec file contains both a formal property (what the verifier checks) and an Intent comment (what the programme should do).

## Your job

1. Read the spec `.fst` file the user points you at
2. Parse the **Intent comment** to understand what kind of programme to write
3. Parse the **formal spec** to understand what property must hold
4. Write a `.bpf.c` file that implements the **full intent**
5. If any part of the intent might not be supported by the verifier, **flag it to the user** — don't silently drop it

## Critical rule: implement the full intent

**Never silently skip parts of the intent.** If the intent says "print the filename", the code must read the filename and print it. If you think something might not compile or might hit verifier limits:

- **Write the code anyway** — implement what the intent asks for
- **Flag the concern** — tell the user specifically what might be problematic and why
- **Ask if needed** — if there are genuinely multiple approaches, ask the user which they prefer

Do NOT substitute a simpler programme that only satisfies the formal property while ignoring the business logic.

## BPF C programme structure

Use standard BPF includes — **do not hand-roll helper declarations or type definitions**.

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("<section_name>")
int <function_name>(<typed_ctx_parameter>) {
    // programme body
    return <value>;
}

char LICENSE[] SEC("license") = "GPL";
```

### Headers

- `vmlinux.h` — arch-dispatch header in `include/` that selects `vmlinux/x86_64.h` or `vmlinux/aarch64.h` based on `__TARGET_ARCH_*` defines. Provides all kernel struct definitions (`struct file`, `struct task_struct`, etc.)
- `bpf/bpf_helpers.h` — BPF helper function declarations, `SEC()` macro, map definition macros
- `bpf/bpf_tracing.h` — tracing-specific macros (`BPF_PROG`, `PT_REGS_*`)
- `bpf/bpf_core_read.h` — CO-RE read helpers (`BPF_CORE_READ`, `bpf_core_read`)

Only include headers that are actually needed.

### Context parameter types

Use the correct typed context for the programme type, not `void *ctx`:

- LSM: `int BPF_PROG(func_name, struct file *file, ...)` or the raw typed args
- Tracepoints: `void *ctx` or the tracepoint struct
- Kprobes: `struct pt_regs *ctx`
- XDP: `struct xdp_md *ctx`

### Section names

Derive from the intent — must match libbpf auto-attach conventions:

- LSM: `SEC("lsm/file_open")`, `SEC("lsm/bprm_check_security")`
- Tracepoints: `SEC("tp/raw_syscalls/sys_enter")`
- Kprobes: `SEC("kprobe/do_sys_openat2")`
- XDP: `SEC("xdp")`
- Test-only: `SEC("test")`

### Reading kernel data

Use CO-RE helpers to read kernel struct fields:

```c
// Read a field from a kernel struct pointer
const char *name = BPF_CORE_READ(file, f_path.dentry, d_name.name);

// Read into a local buffer
char buf[64];
bpf_probe_read_kernel_str(buf, sizeof(buf), name);
```

### Important constraints

- Compile with: `clang -target bpf -O2 -g -Wall -Werror -D__TARGET_ARCH_x86_64 -I include -c prog.bpf.c -o prog.bpf.o`
- The `-D__TARGET_ARCH_x86_64` flag is required — `include/vmlinux.h` is an arch-dispatch header that selects the correct kernel type definitions based on this define
- The `-I include` flag (relative to the repo root) is required so clang can find `vmlinux.h` and its arch-specific sub-headers
- The `-g` flag is required for DWARF debug info (used for source locations and struct field accessors)
- Always null-check `bpf_map_lookup_elem` results before dereferencing
- The programme must terminate — no unbounded loops
- Stack limit is 512 bytes — be careful with large local buffers

## Process

1. Read the spec file the user provides
2. Extract the Intent comment and the formal property
3. Determine the programme type, helpers, kernel struct access needed
4. Write the `.bpf.c` file implementing the **complete intent** — place it next to the spec file with the same base name
5. Flag any concerns about verifier support, compilation, or kernel struct access
6. Tell the user how to compile and verify (run from the repo root):
   ```
   clang -target bpf -O2 -g -Wall -Werror -D__TARGET_ARCH_x86_64 -I include -c <name>.bpf.c -o <name>.bpf.o
   cargo run -- verify <name>.bpf.o --spec <section>:<name>.fst
   ```

## Code style

### Comments

Default to writing no comments. BPF programmes are short — well-named variables and functions speak for themselves. Only comment when the **why** is non-obvious:

- A workaround for a kernel verifier limitation
- A non-obvious size or alignment constraint
- Why a particular helper was chosen over an alternative

Never comment what the code does — `pid = pid_tgid >> 32` doesn't need `// extract pid`. Never reference the spec, the current task, or ticket numbers in code comments.

### Simplicity

Write the minimum code the intent requires. Don't add:
- Error counters or debug maps not mentioned in the intent
- Configurable constants that could just be literals
- Helper wrappers or abstractions around single call sites
- Fallback paths for scenarios that can't happen in context

Three similar lines are better than a premature abstraction. BPF programmes should be flat and obvious.

### Variable naming

Use short, conventional BPF names: `evt` for event pointers, `pid` / `tgid` / `pid_tgid` for process IDs, `ctx` for context pointers. Match the naming conventions in kernel BPF samples and libbpf-bootstrap.

## BPF best practices

### Stack (512-byte hard limit)

The BPF stack is 512 bytes total, shared across call depth. Count your locals carefully.

- **Small events** (< ~200 bytes): allocate on stack, copy into ringbuf/perf buffer
- **Large events** (> ~200 bytes): reserve directly from ringbuf (`bpf_ringbuf_reserve`) and write fields in-place — avoids stack copies entirely
- **Scratch space**: if you need a large temporary buffer, use a single-entry `BPF_MAP_TYPE_PERCPU_ARRAY` — BPF programmes are never preempted, so a per-CPU slot is safe

### Ring buffer vs perf buffer

Default to ring buffer (kernel 5.8+). It has better memory efficiency, preserves event ordering across CPUs, and the reserve/submit API avoids unnecessary copies.

```c
/* Reserve directly — no stack copy needed */
struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
if (!evt)
    return 0;
evt->pid = pid;
bpf_ringbuf_submit(evt, 0);
```

Size the ring buffer as a power of 2, minimum page-aligned (4096). For high-throughput programmes, 1MB (`1 << 20`) is a reasonable starting point.

If `bpf_ringbuf_reserve` fails (buffer full), handle it gracefully — return the appropriate value for the programme type (0 for LSM, `XDP_PASS` for XDP). Don't leave partially initialised state.

### CO-RE and portability

Always use CO-RE helpers for kernel struct access. Never hard-code struct offsets — they change between kernel versions.

```c
/* Good: CO-RE relocated at load time */
const char *name = BPF_CORE_READ(file, f_path.dentry, d_name.name);

/* Bad: hard-coded offset, breaks on different kernels */
const char *name = *(const char **)((void *)file + 32);
```

- Use `BPF_CORE_READ` for chained pointer dereferences (one read per pointer hop)
- Use `bpf_probe_read_kernel_str` to copy kernel strings into local buffers
- Use `bpf_probe_read_user_str` for user-space strings — never mix kernel/user variants
- Use `bpf_core_field_exists()` when a field may not exist on all target kernels

### Null checks

Always null-check results from:
- `bpf_map_lookup_elem` — returns NULL if key not found
- `bpf_ringbuf_reserve` — returns NULL if buffer full
- Any pointer-returning helper

The kernel BPF verifier rejects programmes that dereference unchecked pointers. Structure code so the null check is immediately visible:

```c
struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
if (!evt)
    return 0;
/* safe to use evt from here */
```

### Return values by programme type

- **LSM**: return 0 to allow, non-zero to deny. Observational programmes always return 0.
- **XDP**: `XDP_PASS` (continue), `XDP_DROP` (discard), `XDP_REDIRECT`, `XDP_TX`, `XDP_ABORTED` (error)
- **Tracepoints / kprobes**: return value is typically ignored; return 0 by convention
- **Test programmes** (`SEC("test")`): return whatever the spec requires

### Verifier-friendly patterns

- Keep control flow simple and linear where possible
- Use bounded loops only — the kernel verifier must prove termination
- Prefer `bpf_loop()` (kernel 5.17+) for iteration over manual counted loops
- Avoid deep call chains — each level costs stack and verification complexity
- If a programme grows complex, consider tail calls to partition logic

### Map definitions

Use the BTF-style map definition macros:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");
```

For counters and statistics, prefer `BPF_MAP_TYPE_PERCPU_ARRAY` to avoid lock contention.

### Licensing

BPF programmes using GPL-only helpers (most of them, including all LSM and tracing helpers) must declare a GPL-compatible licence:

```c
char LICENSE[] SEC("license") = "GPL";
```

This is not optional — the kernel refuses to load programmes that use GPL helpers without the licence declaration.

## Key principle

**The spec captures as much of the intent as the spec language can express.** Your code must implement the **full intent**, not just satisfy the formal property. The verifier checks the spec — but the spec is meant to match the intent, so satisfying the spec should mean implementing the intent correctly.
