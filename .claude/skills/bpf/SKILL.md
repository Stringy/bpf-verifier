---
name: bpf
description: Generate a verified BPF programme from a natural language description. Produces an F* spec, then BPF C code, then compiles and verifies.
---

# Verified BPF Programme from Description

Generate a formally verified BPF programme from a natural language description.

## Steps — follow in order, never skip or reorder

### Step 1: Generate the spec FIRST

You MUST generate the F* spec before writing any C code. The spec comes first — this is the entire point of spec-first verification.

Invoke the generate-spec skill:
```
Skill("generate-spec", args="<user's description>")
```

Wait for the spec to be written to disk. The generate-spec skill will ask the user "Does this spec capture your intent?" — **do not proceed to step 2 until the user confirms.**

If the user wants changes to the spec, revise it before moving on. The spec is a contract — getting it right before generating code avoids wasted work.

### Step 2: Generate the C code from the spec

Only after the spec file exists **and the user has confirmed it**, invoke the code generation skill pointing at it:
```
Skill("generate-bpf-code", args="<path to the .fst file from step 1>")
```

### Step 3: Compile

```
clang -target bpf -O2 -g -Wall -Werror -D__TARGET_ARCH_x86_64 -I include -c <name>.bpf.c -o <name>.bpf.o
```

The project's `vmlinux.h` is an arch-dispatch header in `include/` — you must pass `-I include` (relative to the repo root) and `-D__TARGET_ARCH_x86_64` so clang finds the correct kernel type definitions.

If compilation fails, fix the C code and retry. Do not modify the spec to work around compilation issues.

### Step 4: Verify

```
cargo run -- verify <name>.bpf.o --spec <section>:<name>.fst
```

### Step 5: Report

- If verification passes: report success
- If verification fails: show the error, explain what went wrong, suggest whether the fix belongs in the code or the spec

## Rules

- **Spec always comes first.** Never write C code before the spec exists. Never skip the spec step.
- **If the user provides a filename or path**, pass it through to both skills.
- **If any step fails**, stop and report clearly. Don't silently continue.
