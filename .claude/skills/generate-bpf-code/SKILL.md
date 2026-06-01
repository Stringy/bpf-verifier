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

- `vmlinux.h` — kernel type definitions (generated from BTF). Provides all kernel struct definitions (`struct file`, `struct task_struct`, etc.)
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

- Compile with: `clang -target bpf -O2 -g -c prog.bpf.c -o prog.bpf.o`
- The `-g` flag is required for source locations in error messages
- Always null-check `bpf_map_lookup_elem` results before dereferencing
- The programme must terminate — no unbounded loops
- Stack limit is 512 bytes — be careful with large local buffers

## Process

1. Read the spec file the user provides
2. Extract the Intent comment and the formal property
3. Determine the programme type, helpers, kernel struct access needed
4. Write the `.bpf.c` file implementing the **complete intent** — place it next to the spec file with the same base name
5. Flag any concerns about verifier support, compilation, or kernel struct access
6. Tell the user how to compile and verify:
   ```
   clang -target bpf -O2 -g -c <name>.bpf.c -o <name>.bpf.o
   cargo run -- verify <name>.bpf.o --spec <section>:<name>.fst
   ```

## Key principle

**The spec captures as much of the intent as the spec language can express.** Your code must implement the **full intent**, not just satisfy the formal property. The verifier checks the spec — but the spec is meant to match the intent, so satisfying the spec should mean implementing the intent correctly.
