# bpf-verifier

Formally verify BPF programmes against F*/Pulse specifications. Given a compiled BPF object file and an F* spec, the verifier proves that the programme satisfies the spec — or reports a counterexample.

The kernel's built-in BPF verifier checks safety (no out-of-bounds access, no null dereferences, etc.) but says nothing about what a programme *does*. This tool lets you write a formal specification of the intended behaviour and machine-check it.

## How it works

1. Parse BPF instructions from an ELF object file
2. Generate an F* verification module via code generation
3. Run F* (with tactics + Z3) to typecheck the proof
4. Report pass or fail

The generated F* code models the full BPF machine state — registers, stack, map values — and symbolically executes the programme. Safety properties (stack bounds, type safety, null safety) are checked as independent layers that don't require Z3.

## Requirements

- Rust (2024 edition)
- [F*](https://github.com/FStarLang/FStar) (`fstar.exe` on `$PATH`)
- `clang` with BPF target support (for compiling test programmes)

## Usage

### Verify a programme against a spec

```
bpf-verifier verify prog.bpf.o --spec Spec.fst
```

### Crash-safety verification (no spec needed)

When `--spec` is omitted, the verifier checks that the programme can't crash — no null pointer dereferences, no out-of-bounds stack access, no type confusion:

```
bpf-verifier verify prog.bpf.o
```

### Inspect generated F*

Dump the generated verification module without running F*:

```
bpf-verifier codegen prog.bpf.o
```

### Multi-programme objects

BPF object files can contain multiple programme sections. By default all sections are verified. To target a specific section:

```
bpf-verifier verify prog.bpf.o --section tracepoint/syscalls/sys_enter_open
```

Pair different specs with different sections:

```
bpf-verifier verify prog.bpf.o \
  --spec "tracepoint/syscalls/sys_enter_open:OpenSpec.fst" \
  --spec "tracepoint/syscalls/sys_exit_open:ExitSpec.fst"
```

## Writing specs

Specs are F* modules that define a `spec : bpf_spec` value using combinators from `BPF.Spec`.

**"This programme returns 42":**

```fstar
module StackLocal

open FStar.UInt64
open BPF.State
open BPF.Spec

let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 42uL
  )
```

**"This programme doesn't crash"** (map lookup with null check):

```fstar
module MapLookup

open BPF.State
open BPF.Spec

let spec : bpf_spec =
  post_only (fun _ -> True)
```

A spec that claims the wrong return value will fail verification — the verifier catches the mismatch:

```fstar
module WrongReturn

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Claims the programme returns 1, but it actually returns 0. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 1uL
  )
```

## Running tests

```
cargo test
```

The test suite compiles a corpus of BPF C programmes with `clang`, verifies them against their specs, and checks that correct specs pass and incorrect specs fail.

## Status

This is a research project. It handles straight-line code, forward and backward branches, stack operations at all widths, BPF map lookups, and 21 BPF helper functions. See the test corpus in `tests/corpus/` for the full set of supported patterns.
