---
name: generate-spec
description: Generate an F* formal specification from a natural language description of a BPF programme. Produces a .fst file that the bpf-verifier can check against compiled BPF code.
---

# Generate BPF Spec from Natural Language

You are generating a formal F* specification for a BPF programme. The spec captures **what** the programme should do — not how. It will be verified against compiled BPF code by the bpf-verifier tool.

## Your job

1. Read the user's natural language description of what a BPF programme should do
2. Identify what properties can be formally specified with the available spec language
3. Generate a valid `.fst` spec file
4. Explain to the user what the spec captures and what it doesn't — be honest about limitations

## Important constraints

**Be honest about what the spec language can and cannot express.** The current spec language reasons about:
- The return value in r0 (what the programme returns)
- Register state at programme exit
- Whether the programme crashes (null safety, stack safety, type safety)

It does NOT yet reason about:
- Packet contents or network data
- Map contents (what values are stored in maps)
- Side effects (what the programme writes to maps, ring buffers, etc.)
- Interactions with kernel data structures
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

### Types and values

- `Scalar v` — a 64-bit integer value (like `Scalar 42uL`)
- `FramePtr n` — a stack pointer with offset n
- `MapValuePtr n` — a pointer to a map value
- `Null` — null pointer (failed map lookup)
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

When a programme's behaviour depends on these, the spec must account for all possible outcomes. Use `post_only (fun _ -> True)` if the only guarantee is "doesn't crash", or a disjunction if there are bounded possible return values.

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

## Process

1. Parse the user's description
2. Identify the observable properties (return value, crash safety)
3. Determine if the behaviour is deterministic or depends on nondeterministic inputs
4. Choose a module name based on the description (PascalCase, e.g. `SysEnterZero`)
5. Write the spec using the simplest combinator that captures the intent
6. Add a comment explaining what the spec verifies in plain English
7. **Write the `.fst` file** using the Write tool. If the user specified a filename or path, use that. Otherwise write to the `scratch/` directory with a name derived from the module name (e.g. `scratch/SysEnterZero.fst`). The filename (without `.fst`) must match the module name.
8. Tell the user what the spec covers and what it can't cover

## When you hit a wall

If the user's description requires expressing something the spec language can't handle, say so and identify specifically what new combinator or capability would be needed. Common gaps:

- **"The programme should write X to the map"** → needs map-effect specs (not yet implemented)
- **"The programme should only forward packets matching rule R"** → needs packet-content predicates (not yet implemented)
- **"The programme should rate-limit to N events/sec"** → needs cross-invocation state (fundamentally out of scope for single-programme verification)

These gaps are useful — they drive the next round of spec language development.
