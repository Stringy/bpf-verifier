# Architecture

This document explains how the verifier works. It's meant for someone who knows BPF and Rust but hasn't seen F* before. If you're looking for usage, see README.md.

## The short version

You give it a compiled BPF object and an F* spec. It parses the BPF instructions, generates an F* module that symbolically executes them, and asks F* to prove that every possible execution satisfies the spec. If it can't, it tells you why.

The kernel verifier checks safety. This checks correctness.

## Verification pipeline

```
  .bpf.o ──► ELF parser ──► instructions + DWARF source locs
                                    │
                                    ├──► stack bounds analysis (Rust)
                                    ├──► dataflow analysis (Rust)
                                    │
                                    ▼
                              F* code generation ◄── .fst spec
                                    │
                                    ▼
                               fstar.exe
                                    │
                              ┌─────┴─────┐
                              ▼           ▼
                             PASS        FAIL ──► diagnostic
```

Each step earns its place:

1. **ELF parsing** (`src/elf/parser.rs`) — pulls BPF instructions from ELF sections, extracts DWARF source locations so error messages can point at C lines.

2. **Stack bounds analysis** (`src/analysis/stack_bounds.rs`) — Rust-side abstract interpretation. Tracks pointer types through registers, checks every stack access is in bounds. Emits a per-instruction witness that F* validates with `assert_norm`. This is fast because F* just checks each step, it doesn't have to discover anything.

3. **Dataflow analysis** (`src/analysis/dataflow.rs`) — enumerates execution paths through the programme. Helpers like `map_lookup_elem` and `ringbuf_reserve` return nullable pointers, which means the programme can take different paths depending on whether the pointer is null. Rather than asking F* to explore all paths simultaneously (which blows up exponentially), the Rust side enumerates them and generates one proof per path. Each path is deterministic, so F* normalises it instantly.

4. **F* code generation** (`src/codegen/fstar.rs`, `templates/verify.fst`) — assembles a verification module from the instructions, analysis results, and spec. The generated module contains the programme as a list of F* constructors, witness steps for safety, and the functional correctness proof obligation.

5. **F* verification** (`src/verify/runner.rs`) — shells out to `fstar.exe`. The generated module imports a stack of verification infrastructure that lives in `fstar/`.

6. **Diagnostics** (`src/verify/diagnostic.rs`) — if F* reports a failure, parses the output (JSON errors + proof state dumps), identifies which layer failed, and renders a source-annotated error using ariadne.

## The F* side

The `fstar/` directory contains the verification framework. It models the BPF machine and provides the proof infrastructure. Dependency order follows the Makefile.

### State model (`BPF.State.fst`)

Registers hold typed values — not just integers. A register is one of:
- `Scalar` — a 64-bit value
- `FramePtr` — pointer into the stack, with an offset
- `MapValuePtr` — pointer to a map value, with a unique ID
- `RingBufPtr` — pointer to a reserved ring buffer slot
- `CtxPtr` — pointer to the programme context (first argument)
- `Null` — null pointer

This type system is what makes safety proofs possible. You can't dereference a `Scalar` or a `Null` because the semantics returns `None` (undefined behaviour) when you try.

Stack memory is a list of `(offset, width, value)` slots. Stores prepend; loads scan for a match. Ring buffer memory works the same way.

### Semantics (`BPF.Semantics.fst`)

`exec_insn` takes a state and an instruction and returns `option bpf_state`. `Some` means the instruction executed; `None` means undefined behaviour. `exec_program` loops with fuel.

ALU ops require scalar operands (except `MOV` which copies anything, and `ADD`/`SUB` which can adjust pointer offsets). Memory ops dispatch on the base register's type. Jumps evaluate conditions and update the PC.

### Helpers (`BPF.Helpers.fst`)

Each BPF helper gets a `helper_spec` — what it reads, what it returns, what side effects it has. `exec_helper` applies the spec: sets r0, advances the PC, and for `ReadIntoPtr` helpers writes a placeholder to the stack so subsequent reads don't fail.

The registry covers 21 helpers. Unknown helpers are UB.

### Spec combinators (`BPF.Spec.fst`)

A spec is a precondition and a postcondition on the BPF state. Users compose specs from combinators rather than writing raw F* propositions:

```fstar
returns_value 0uL                           (* r0 == 0 *)
post_only (fun st -> ... )                  (* any postcondition *)
ringbuf_written (fun rb -> ... )            (* assert ring buffer contents *)
returns_and_writes 0uL (fun rb -> ... )     (* both *)
```

### Verification proposition (`BPF.Verify.fst`)

`program_satisfies` is the core claim: for all initial states satisfying the precondition, if the programme terminates normally, the final state satisfies the postcondition. The `None` case (UB) maps to `True` — UB is caught by the safety layers, not the functional proof.

### Safety layers

Three independent checkers, each a decidable boolean function that F* normalises to `true` on concrete programmes:

- **Stack bounds** (`BPF.Check.StackBounds.fst`) — every stack access is within the 512-byte frame. The Rust side pre-computes a witness; F* just validates it.
- **Type safety** (`BPF.Check.TypeSafety.fst`) — ALU ops use scalars, memory ops use appropriate pointers.
- **Null safety** (`BPF.Check.NullSafety.fst`) — map value pointers are null-checked before dereference.

### Path executor (`BPF.Exec.Path.fst`)

For programmes with nullable helper calls, `exec_program_path` takes a schedule — a list of `NonNull`/`AsNull` choices consumed at each nullable helper call. This makes execution deterministic per-path, which is what lets F* normalise it without blowing up.

### Tactics (`BPF.Tactic.fst`, `BPF.Tactic.Layered.fst`)

F* tactics control how proofs are discharged. The key ones:

- `bpf_auto_pure` — full normalisation. Works when there's no branching.
- `bpf_auto_map` — selective normalisation that keeps `option` opaque. For non-deterministic programmes.
- `bpf_auto_chunked` — normalises one basic block at a time. For larger programmes.
- `type_check_tac`, `null_check_tac` — normalise the decidable checkers to `true`.

All use `nbe` (normalisation by evaluation) for speed.

## Why it's structured this way

The first version normalised everything in F*. F* evaluated the full programme symbolically and Z3 checked the result. This worked for small programmes but blew up with helper calls because each nullable helper doubles the number of paths.

The fix was to move work from F* to Rust. The Rust side does analysis that would be expensive for F* (path enumeration, abstract interpretation) and feeds F* small, tractable proof obligations. F* validates rather than discovers.

This is the pattern throughout: Rust computes, F* checks. The stack bounds analysis computes a witness in Rust and F* validates each step. The dataflow analysis enumerates paths in Rust and F* proves each one independently. The safety checkers are decidable functions that F* just normalises to `true`.

## The generated module

The template (`templates/verify.fst`) produces a module that looks like this:

```fstar
let program : bpf_program = [ ... instructions ... ]

(* Stack bounds — Rust-computed witness, F* validates *)
let _ = assert_norm (Some? (check_insn_sb ...))   (* one per instruction *)

(* Type safety *)
let ts_proof = _ by (type_check_tac ())

(* Null safety — only if the programme has nullable helpers *)
let ns_proof = _ by (null_check_tac ())

(* Functional correctness — one proof per path *)
let proof_path_0 = _ by (norm [...]; smt ())       (* all helpers succeed *)
let proof_path_1 = _ by (norm [...]; smt ())       (* first helper returns null *)

let proof : squash (program_satisfies program spec) = admit ()
```

The `admit()` at the bottom is a gap — each path is independently proved, but the formal bridge to `program_satisfies` isn't formalised yet. The path proofs are the real work.

## Test corpus

`tests/corpus/good/` — programmes with correct specs. Verification should pass.
`tests/corpus/bad/` — programmes with deliberately wrong specs. Verification should fail.

Each test is a `.bpf.c` + `.fst` pair. `build.rs` compiles the C to BPF objects; `tests/corpus.rs` runs the verifier on each pair.

## Adding a new helper

1. Add the helper ID to `helper_id` in `BPF.State.fst`
2. Add a `helper_spec` entry in `BPF.Helpers.fst` (`get_helper_spec`)
3. Add a `HelperSpec` entry in `src/bpf/helpers.rs`
4. If it returns a nullable pointer, the dataflow analysis handles it automatically
5. If it has a `ReadIntoPtr` effect, `apply_helper_effect` handles the stack write

## Adding a new spec combinator

1. Add the combinator to `BPF.Spec.fst`
2. Update the generate-spec skill if you want the AI to use it
3. Add a corpus test exercising it
