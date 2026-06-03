---
name: generate-spec
description: Generate an F* formal specification from a natural language description of a BPF programme. Produces a .fst file that the bpf-verifier can check against compiled BPF code.
---

# Generate BPF Spec from Natural Language

You are generating a formal F* specification for a BPF programme. The spec captures **what** the programme should do — not how. It will be verified against compiled BPF code by the bpf-verifier tool.

## Your job

1. Read the user's natural language description of what a BPF programme should do
2. Identify what properties can be formally specified with the available spec language
3. Generate a valid `.fst` spec file that captures **as much business logic as possible**
4. Explain to the user what the spec captures and what it doesn't — be honest about limitations

## Spec philosophy: maximise business logic coverage

**Never settle for a trivially simple spec when the spec language can express more.** A spec that only says "returns 0" when the programme also writes structured data to a ring buffer is leaving value on the table.

Even when exact values are nondeterministic (PID from `bpf_get_current_pid_tgid()`, filename from kernel structs), you can still specify **structural correctness**:
- **That a write occurred** at the correct offset and width: `Some? (ringbuf_read_any rb 0 W32)`
- **The write count** — no extra writes, no missing writes: `ringbuf_writes_exactly n`
- **Known constant values** at their expected offsets: `ringbuf_read_any rb 0 W32 == Some 7uL`
- **Both success and failure paths** for fallible operations like `bpf_ringbuf_reserve`

Think of it as a ladder of specificity — always climb as high as the spec language allows:

1. ~~`post_only (fun _ -> True)`~~ — "doesn't crash" — almost never the right choice for a spec
2. `returns_value 0uL` — captures the return value but ignores side effects
3. Return value + write count + structural writes — **this is the target for most programmes**
4. Return value + exact write count + exact values — the gold standard, when values are known

If you find yourself writing a spec at level 1 or 2, stop and ask: can the ring buffer contents, write counts, or field offsets be specified? Almost always yes.

## Important constraints

**Be honest about what the spec language can and cannot express.** The current spec language reasons about:
- The return value in r0 (what the programme returns)
- Register state at programme exit
- Whether the programme crashes (null safety, stack safety, type safety)
- Ring buffer contents (what values are written at which offsets)
- Ring buffer write counts (exactly how many writes occurred)

It does NOT yet reason about:
- Packet contents or network data
- Map contents (what values are stored in hash/array maps)
- Interactions with kernel data structures beyond what helpers expose
- Multiple programme invocations or state across calls

When the user describes something the spec language can't express, say so clearly and suggest what subset CAN be specified. Don't generate a spec that claims to verify something it doesn't.

## The spec language

### Module boilerplate

Every spec file needs this structure:

```fstar
module <ModuleName>

open FStar.UInt64
open BPF.State
open BPF.Spec

(* Intent: <natural language description of what the programme does and why>
   This comment is read by the code generator to produce a matching BPF C
   implementation. It should capture the business logic, not the formal property. *)
let spec : bpf_spec =
  <spec body>
```

The module name must match the filename (without `.fst`).

**The Intent comment is required.** It should capture:
- What kind of BPF programme this is (tracepoint, XDP, kprobe, etc.)
- What the programme does in plain English
- Any BPF-specific details (which hook point, what helpers it uses, etc.)

This comment is the bridge between the formal spec and the code generator — the spec captures the verifiable property, the intent comment captures the context needed to write the implementation.

### Available combinators

**`returns_value v`** — the programme returns exactly this value in r0.
```fstar
let spec = returns_value 42uL
```

**`post_only (fun final_st -> <predicate>)`** — the predicate holds on the final state.
```fstar
(* Programme returns 0 or 1 *)
let spec = post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 0uL \/
    state_get_reg final_st r0 == Scalar 1uL
  )
```

**`with_pre (fun init_st -> <predicate>) <spec>`** — the spec only needs to hold when the precondition is true on the initial state.
```fstar
(* If r1 starts non-zero, programme returns 1 *)
let spec = with_pre
    (fun init_st -> state_get_reg init_st r1 <> Scalar 0uL)
    (returns_value 1uL)
```

**`ringbuf_written (fun rb -> <predicate>)`** — the predicate holds on the ring buffer contents at programme exit. Use `ringbuf_read_any` to check specific fields by offset and width.
```fstar
(* Ring buffer contains 42 at offset 0 (u32) *)
let spec = ringbuf_written (fun rb ->
    ringbuf_read_any rb 0 W32 == Some 42uL
  )
```

**`returns_and_writes v (fun rb -> <predicate>)`** — combined: returns a value AND ring buffer satisfies a predicate.
```fstar
(* Returns 0 and writes type=7, flags=0xFF to the ring buffer *)
let spec = returns_and_writes 0uL (fun rb ->
    ringbuf_read_any rb 0 W32 == Some 7uL /\
    ringbuf_read_any rb 4 W32 == Some 255uL
  )
```

**`ringbuf_writes_exactly n (fun rb -> <predicate>)`** — asserts the ring buffer contains exactly `n` writes AND the predicate holds. Proves no extra writes occurred.
```fstar
(* Exactly 2 writes: type=7 at offset 0, flags=0xFF at offset 4 *)
let spec = ringbuf_writes_exactly 2 (fun rb ->
    ringbuf_read_any rb 0 W32 == Some 7uL /\
    ringbuf_read_any rb 4 W32 == Some 255uL
  )
```

### Ring buffer state functions

- `ringbuf_read_any rb offset width` — read a value from the ring buffer at the given offset and width, ignoring ring buffer ID. Returns `option UInt64.t` (`Some v` if found, `None` if not). This is the most common way to check ring buffer contents in specs.
- `ringbuf_read rb id offset width` — read a value from a specific ring buffer ID (rarely needed).
- `ringbuf_write_count rb` — returns the number of writes recorded in the ring buffer.
- Width values: `W8`, `W16`, `W32`, `W64` (1, 2, 4, 8 bytes respectively).

### DWARF struct field accessors

When the BPF programme defines a struct for ring buffer events, the verifier auto-generates F* accessor functions from DWARF debug info. For a struct like:

```c
struct event {
    unsigned int type;    // offset 0, 4 bytes
    unsigned int flags;   // offset 4, 4 bytes
};
```

The verifier generates a `Fields` module with:
```fstar
let event_type (rb: ringbuf_mem) : option UInt64.t = ringbuf_read_any rb 0 W32
let event_flags (rb: ringbuf_mem) : option UInt64.t = ringbuf_read_any rb 4 W32
```

To use these in your spec, add `open Fields` and reference them by name:
```fstar
open Fields

let spec : bpf_spec =
  ringbuf_writes_exactly 2 (fun rb ->
    event_type rb == Some 7uL /\
    event_flags rb == Some 255uL
  )
```

The accessor names follow the pattern `<struct_name>_<field_name>`. Only user-defined structs get accessors (not kernel structs from vmlinux.h).

### Handling nondeterministic ring buffer reserve

`bpf_ringbuf_reserve` can fail (returns NULL when the ring buffer is full). Specs must account for both paths using a disjunction:

```fstar
(* Success: returns 0 and writes the event
   Failure: returns 1 and writes nothing *)
let spec =
  with_pre (fun init_st -> ringbuf_write_count init_st.ringbuf == 0)
    (post_only (fun final_st ->
      (state_get_reg final_st r0 == Scalar 0uL /\
       ringbuf_write_count final_st.ringbuf == 2 /\
       ringbuf_read_any final_st.ringbuf 0 W32 == Some 7uL /\
       ringbuf_read_any final_st.ringbuf 4 W32 == Some 255uL) \/
      (state_get_reg final_st r0 == Scalar 1uL /\
       ringbuf_write_count final_st.ringbuf == 0)
    ))
```

The `with_pre` asserting `ringbuf_write_count == 0` ensures we're reasoning from a clean initial state.

### Types and values

- `Scalar v` — a 64-bit integer value (like `Scalar 42uL`)
- `FramePtr n` — a stack pointer with offset n
- `MapValuePtr n` — a pointer to a map value
- `RingBufPtr n` — a pointer to a ring buffer reservation
- `Null` — null pointer (failed map lookup or ring buffer reserve)
- `state_get_reg st rN` — read register N from state (r0-r10)
- `r0` is the return value register
- `r1`-`r5` are argument registers (r1 = ctx pointer for programme entry)
- `r10` is the frame pointer (read-only)

### Logical connectives

- `/\` — AND (both must hold)
- `\/` — OR (at least one must hold)
- `==>` — implies
- `==` — equality
- `<>` — inequality
- `True` — trivially true (use for "programme doesn't crash" specs)

### Safety properties (verified automatically)

These are checked independently of the functional spec — you don't need to specify them:
- **Null safety**: map lookup results are null-checked before use
- **Type safety**: operations use correct register types
- **Stack bounds**: stack accesses are within the 512-byte frame

### Nondeterministic helpers

Some BPF helpers return unpredictable values:
- `bpf_ktime_get_ns()` — timestamp, could be anything
- `bpf_get_prandom_u32()` — random number
- `bpf_map_lookup_elem()` — could be null (key not found) or a valid pointer
- `bpf_ringbuf_reserve()` — could be null (ring buffer full) or a valid `RingBufPtr`
- `bpf_get_current_pid_tgid()` — returns a runtime value, not predictable at verification time

When a programme's behaviour depends on these, the spec must account for all possible outcomes using a disjunction. **But nondeterministic values do NOT mean you give up on specifying ring buffer writes.** You can still verify structural correctness:

```fstar
(* The value is nondeterministic but we can still prove the write
   happened at the right offset and width *)
Some? (ringbuf_read_any final_st.ringbuf 0 W32)
```

Use `Some?` (the F* option discriminator) to assert a write occurred without constraining the value. This proves the programme wrote *something* at the correct offset with the correct width — catching bugs like writing to the wrong offset, using the wrong width, or forgetting to write a field entirely.

Reserve `post_only (fun _ -> True)` for programmes with genuinely no observable output — no return value constraint, no ring buffer writes, no map effects. This should be rare.

## Examples

### "A programme that always returns 0"
```fstar
module AlwaysZero
open FStar.UInt64
open BPF.State
open BPF.Spec

let spec : bpf_spec = returns_value 0uL
```

### "A programme that looks up a map value and returns it, or returns -1 if not found"
```fstar
module SafeMapLookup
open BPF.State
open BPF.Spec

(* We can't specify the exact return value because the map contents
   are unknown. But we CAN verify it doesn't crash — the null check
   is proven by the null safety layer. *)
let spec : bpf_spec = post_only (fun _ -> True)
```

### "A programme that returns 1 if a map lookup succeeds, 0 if it fails"
```fstar
module MapCheck
open FStar.UInt64
open BPF.State
open BPF.Spec

let spec : bpf_spec =
  post_only (fun final_st ->
    state_get_reg final_st r0 == Scalar 0uL \/
    state_get_reg final_st r0 == Scalar 1uL
  )
```

### "A programme that computes x + y where x=10 and y=32"
```fstar
module AddValues
open FStar.UInt64
open BPF.State
open BPF.Spec

let spec : bpf_spec = returns_value 42uL
```

### "A programme that writes a two-field event to a ring buffer"
```fstar
module RingBufEvent
open FStar.UInt64
open BPF.State
open BPF.Spec

(* Intent: reserve a ring buffer slot, write a two-field event
   (type=7, flags=0xFF), submit, return 0. If reserve fails, return 1. *)
let spec : bpf_spec =
  post_only (fun final_st ->
    (state_get_reg final_st r0 == Scalar 0uL /\
     ringbuf_read_any final_st.ringbuf 0 W32 == Some 7uL /\
     ringbuf_read_any final_st.ringbuf 4 W32 == Some 255uL) \/
    state_get_reg final_st r0 == Scalar 1uL
  )
```

### "A programme that writes exactly two fields to a ring buffer and nothing else"
```fstar
module RingBufExact
open FStar.UInt64
open BPF.State
open BPF.Spec
open Fields

(* Intent: prove the programme writes *exactly* two fields to the
   ring buffer — type=7 and flags=0xFF — and nothing else.
   If reserve fails, returns 1 with no writes.

   event_type and event_flags are auto-generated from DWARF. *)
let spec : bpf_spec =
  with_pre (fun init_st -> ringbuf_write_count init_st.ringbuf == 0)
    (post_only (fun final_st ->
      (state_get_reg final_st r0 == Scalar 0uL /\
       ringbuf_write_count final_st.ringbuf == 2 /\
       event_type final_st.ringbuf == Some 7uL /\
       event_flags final_st.ringbuf == Some 255uL) \/
      (state_get_reg final_st r0 == Scalar 1uL /\
       ringbuf_write_count final_st.ringbuf == 0)
    ))
```

### "An LSM hook that writes nondeterministic data to a ring buffer"
```fstar
module LsmFileOpen
open FStar.UInt64
open BPF.State
open BPF.Spec
open Fields

(* Intent: LSM file_open hook that captures PID and filename.
   The values are nondeterministic but the struct layout is not —
   we verify the right fields are written at the right offsets.

   event_pid is auto-generated from DWARF for:
   struct event { __u32 pid; char filename[256]; }; *)
let spec : bpf_spec =
  with_pre (fun init_st -> ringbuf_write_count init_st.ringbuf == 0)
    (post_only (fun final_st ->
      state_get_reg final_st r0 == Scalar 0uL /\
      ((* Reserve succeeded: pid field was written *)
       ringbuf_write_count final_st.ringbuf > 0 /\
       Some? (event_pid final_st.ringbuf)) \/
      ((* Reserve failed: no writes *)
       ringbuf_write_count final_st.ringbuf == 0)
    ))
```

This pattern captures three things the trivial `returns_value 0uL` spec would miss:
- The PID field is written at the correct offset and width (not some other field)
- The ring buffer reserve failure path produces no writes (no leaked partial events)
- The write count is consistent with the path taken

## Process

1. Parse the user's description
2. Identify **all** observable properties — return value, ring buffer structure (fields, offsets, widths), write counts, success/failure paths
3. For each property, determine if the value is deterministic (specify exactly) or nondeterministic (specify structurally with `Some?`)
4. Choose a module name based on the description (PascalCase, e.g. `SysEnterZero`)
5. Write the spec using the combinator that captures the **most business logic** — prefer `ringbuf_writes_exactly` or `returns_and_writes` over bare `returns_value` when ring buffer writes are involved
6. Add a comment explaining what the spec verifies in plain English
7. **Write the `.fst` file** using the Write tool. If the user specified a filename or path, use that. Otherwise write to the `scratch/` directory with a name derived from the module name (e.g. `scratch/SysEnterZero.fst`). The filename (without `.fst`) must match the module name.
8. Tell the user what the spec covers and what it can't cover — but frame gaps as limitations to address, not excuses for a weak spec
9. **Ask the user: "Does this spec capture your intent?"** — wait for confirmation before proceeding. The spec is a contract; the user should agree it says what they mean before code is generated against it.

## When you hit a wall

If the user's description requires expressing something the spec language can't handle, say so and identify specifically what new combinator or capability would be needed. Common gaps:

- **"The programme should write X to a hash/array map"** → needs map-effect specs (not yet implemented). Note: ring buffer writes CAN be specified — use `ringbuf_written` or `ringbuf_writes_exactly`.
- **"The programme should only forward packets matching rule R"** → needs packet-content predicates (not yet implemented)
- **"The programme should rate-limit to N events/sec"** → needs cross-invocation state (fundamentally out of scope for single-programme verification)
- **"The programme should read field X from a kernel struct and write it to the ring buffer"** → the exact value is nondeterministic, but you can and SHOULD still specify the structural property: that a write occurs at the correct offset and width using `Some? (ringbuf_read_any rb <offset> <width>)`. Combined with `ringbuf_writes_exactly`, this proves the programme writes the right fields in the right order to the right places — catching offset miscalculations, wrong widths, missing fields, and extra writes. Don't fall back to a trivial spec just because the value isn't known.

These gaps are useful — they drive the next round of spec language development.
