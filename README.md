# bpf-verifier

Formally verify BPF programmes against F* specifications.

The kernel's BPF verifier checks safety — no out-of-bounds access, no null dereferences. This tool checks *correctness*: given a spec that says what a programme should do, it proves the programme does it.

## Quick start

### With Docker (recommended)

No local toolchain needed. Build the image once:

```
make image
```

Run the test suite:

```
docker run --rm bpf-verifier
```

Verify your own programme (mount the current directory into the container):

```
docker run --rm -v $(pwd):/workspace bpf-verifier \
  cargo run -- object verify my_prog.bpf.o --spec "tp/raw_syscalls/sys_enter:MySpec.fst"
```

Interactive shell:

```
docker run --rm -it -v $(pwd):/workspace bpf-verifier bash
```

### Without Docker

You need:

- **Rust** (stable, edition 2024 — requires >= 1.85)
- **F\*** (`fstar.exe` on `$PATH`) — see [F\* installation](https://github.com/FStarLang/FStar/blob/master/INSTALL.md)
- **Z3** (>= 4.13.3 on `$PATH`) — F\*'s `get_fstar_z3.sh` script handles this
- **clang** with BPF target support (for compiling BPF C programmes)

Build the F\* cache and run tests:

```
make test
```

## Usage

The tool has two verification modes: **object-level** (operates on compiled `.bpf.o` files) and **AST-level** (operates on C source).

### Object-level verification

#### Verify a programme against a spec

```
bpf-verifier object verify prog.bpf.o --spec "section_name:Spec.fst"
```

The `--spec` argument pairs a programme section with a spec file. The section name is the ELF section containing the BPF programme (e.g. `tp/raw_syscalls/sys_enter`, `test`, `xdp`).

#### Crash-safety only (no spec)

Without `--spec`, the verifier checks that the programme can't crash — no null dereferences, no out-of-bounds stack access, no type confusion:

```
bpf-verifier object verify prog.bpf.o
```

#### Safety check (pure Rust, no F\*)

The `check` subcommand runs a kernel-verifier-style abstract interpretation entirely in Rust — no F\* or Z3 required:

```
bpf-verifier object check prog.bpf.o
```

#### Multiple sections

BPF objects can contain multiple programme sections. Pair different specs with different sections:

```
bpf-verifier object verify prog.bpf.o \
  --spec "tp/raw_syscalls/sys_enter:EnterSpec.fst" \
  --spec "tp/raw_syscalls/sys_exit:ExitSpec.fst"
```

Or verify a single section:

```
bpf-verifier object verify prog.bpf.o --section tp/raw_syscalls/sys_enter
```

#### Inspect generated F\*

Dump the verification module without running F\*:

```
bpf-verifier object codegen prog.bpf.o
```

### AST-level verification

AST-level verification works on C source rather than compiled objects. It uses Clang's JSON AST dump to parse the programme, converts it to F\* AST constructor applications, and verifies the result with F\*.

#### Simple programmes

For programmes with no special include paths or defines:

```
bpf-verifier ast verify prog.bpf.c
bpf-verifier ast codegen prog.bpf.c
```

#### Real-world programmes (compile_commands.json)

Real BPF programmes need specific clang flags — include paths for libbpf headers, architecture defines, project-local headers. If your build system generates a `compile_commands.json` (CMake does this with `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`; for other build systems use [Bear](https://github.com/rizsotto/Bear)), you can point at it:

```
bpf-verifier ast verify src/bpf/main.c \
  --compile-commands build/compile_commands.json
```

The tool finds the compile command for your source file and replays it with AST dump flags injected.

#### Pre-generated JSON AST

For full control, generate the Clang JSON AST yourself and pass it in:

```
clang -target bpf -D__TARGET_ARCH_x86_64 -I include \
  -Xclang -ast-dump=json -fsyntax-only prog.bpf.c > ast.json

bpf-verifier ast verify prog.bpf.c --ast-json ast.json
```

This is useful when your build has complex flags, cross-compilation requirements, or when you want to cache the AST. Use `-` to read from stdin:

```
clang <your flags> -Xclang -ast-dump=json -fsyntax-only prog.bpf.c \
  | bpf-verifier ast verify prog.bpf.c --ast-json -
```

## Writing specs

A spec is an F\* module that defines `spec : bpf_spec` using combinators from `BPF.Spec`:

```fstar
module MySpec

open FStar.UInt64
open BPF.State
open BPF.Spec

let spec : bpf_spec = returns_value 0uL
```

Available combinators:

| Combinator | What it checks |
|---|---|
| `returns_value v` | r0 == v at exit |
| `post_only (fun st -> ...)` | arbitrary postcondition on final state |
| `with_pre (fun st -> ...) spec` | spec holds when precondition is true |
| `ringbuf_written (fun rb -> ...)` | ring buffer contents |
| `returns_and_writes v (fun rb -> ...)` | return value + ring buffer |
| `ringbuf_writes_exactly n (fun rb -> ...)` | exactly n writes + ring buffer predicate |

Ring buffer fields can be checked by offset and width:

```fstar
ringbuf_read_any rb 0 W32 == Some 42uL    (* u32 at offset 0 is 42 *)
Some? (ringbuf_read_any rb 4 W32)          (* something was written at offset 4 *)
```

When the BPF programme defines structs for ring buffer events, DWARF-derived field accessors are generated automatically (e.g. `syscall_event_pid rb` instead of `ringbuf_read_any rb 0 W32`).

### Examples

The test corpus has working examples at every complexity level:

| Spec | What it demonstrates |
|---|---|
| `ReturnConst` | Simplest — asserts a return value |
| `StackLocal` | Stack load/store |
| `MapLookup` | Crash-safety with a map lookup and null check |
| `BranchResult` | Disjunctive spec (map lookup success or failure) |
| `RingBufExact` | Ring buffer writes with exact field and count checks |

See `tests/corpus/good/` for correct specs and `tests/corpus/bad/` for deliberately wrong ones.

## Project structure

```
src/                    Rust — ELF parsing, analysis, codegen, diagnostics
fstar/obj/              F* — BPF state model, semantics, proof infrastructure (object-level)
fstar/ast/              F* — AST types, expression/statement verification (AST-level)
templates/verify.fst    Askama template for generated verification modules
tests/corpus/           BPF C programmes + matching F* specs
include/vmlinux/        Kernel type definitions for BPF compilation
```

## Compiling BPF programmes

To compile a BPF C programme for object-level verification:

```
clang -target bpf -O2 -g -Wall -Werror \
  -D__TARGET_ARCH_x86_64 -I include \
  -c prog.bpf.c -o prog.bpf.o
```

The `-g` flag is required — the verifier uses DWARF debug info to generate struct field accessors and map error messages back to C source lines.

## Status

Research project. Handles straight-line code, forward and backward branches, stack operations at all widths, BPF map lookups, ring buffer writes, and 21 BPF helper functions. See the test corpus for the full set of supported patterns.
