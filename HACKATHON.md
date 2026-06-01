# Hackathon: Formal Verification of AI-Generated Code

## The Problem

AI models write plausible code. They also write plausible *wrong* code. The
current trust model is: human reads the output, spots the bugs, fixes them.
This doesn't scale — the whole point of AI-assisted development is that
humans shouldn't have to read every line. But if you can't read every line,
how do you know it's correct?

Tests help, but AI-generated tests have the same problem: if the model
misunderstands the requirement, it writes code that's wrong *and* tests
that pass. The tests and the code agree with each other but disagree with
reality.

Formal verification offers a different approach. Instead of checking that
code does what *it* says it does (tests), you check that code does what
*you* said it should do (a specification). If the spec is right and the
proof passes, the code is correct by construction. If the proof fails,
you get a concrete counterexample showing exactly where the code diverges
from the spec.

## The Insight: Spec-First, Not Code-First

The key idea for this hackathon project is **generating the specification
from the user's intent before generating the code**.

If you generate the spec from the code, you're just testing that the AI
is self-consistent. The spec mirrors the code's bugs. But if you generate
the spec from the intent and the code independently, you're testing that
the AI understood the requirement. The spec and the code become two
independent channels from the same source (the user's natural language
description), and the verifier checks that they agree.

```
                    ┌──────────────────┐
                    │  User's intent   │
                    │  (natural lang)  │
                    └────────┬─────────┘
                             │
                 ┌───────────┴───────────┐
                 │                       │
                 ▼                       ▼
        ┌────────────────┐     ┌─────────────────┐
        │ Generate spec  │     │  Generate code   │
        │ (from intent)  │     │  (from intent)   │
        └───────┬────────┘     └────────┬─────────┘
                │                       │
                │               ┌───────┴────────┐
                │               │    Compile      │
                │               └───────┬─────────┘
                │                       │
                ▼                       ▼
        ┌───────────────────────────────────────┐
        │         Formal Verifier (F*)          │
        │                                       │
        │  Does the compiled code satisfy the   │
        │  spec derived from user intent?       │
        └───────────────────┬───────────────────┘
                            │
                  ┌─────────┴──────────┐
                  │                    │
                  ▼                    ▼
            ┌──────────┐        ┌───────────┐
            │   Pass   │        │   Fail    │
            │          │        │           │
            │ Code and │        │ Counter-  │
            │ intent   │        │ example:  │
            │ agree    │        │ where do  │
            │          │        │ they      │
            │          │        │ diverge?  │
            └──────────┘        └───────────┘
```

When they disagree, there are two possibilities:

1. **The code is wrong** — the AI misimplemented the intent. The spec
   (derived from intent) is correct, so the counterexample shows the bug.
2. **The spec is wrong** — the AI misunderstood the intent. The code might
   be fine, but the spec doesn't match what the user actually wanted.

In both cases, the human has something concrete to look at. And crucially,
reading a 5-line spec to check "does this match what I asked for?" is far
easier than auditing 200 lines of generated code.

## What Exists Today

This repo (`bpf-verifier`) is a working formal verification tool for BPF
programmes. It:

1. Parses BPF instructions from compiled ELF object files
2. Generates an F* verification module via code generation
3. Runs F* (with tactics + Z3) to typecheck the proof
4. Reports pass or fail with diagnostics

It models the full BPF machine state (registers, stack, maps) and supports
straight-line code, branches, loops, stack operations, map lookups, and 21
BPF helper functions.

The test corpus has 28 "good" programmes (correct code + correct spec) and
9 "bad" programmes (correct code + deliberately wrong spec), demonstrating
both verification success and meaningful failure.

### Spec language

Specs are F* modules using combinators from `BPF.Spec`:

```fstar
(* "The programme returns 42" *)
let spec = returns_value 42ul

(* "The programme returns 42 given that r1 starts non-null" *)
let spec = with_pre (fun st -> state_get_reg st r1 <> Scalar 0uL)
                    (returns_value 42ul)

(* "Either the programme returns 0 or returns 1" *)
let spec = post_only (fun st ->
  state_get_reg st r0 == Scalar 0uL \/
  state_get_reg st r0 == Scalar 1uL)
```

These are concise, readable, and auditable — a non-F*-expert can look at
`returns_value 42ul` and decide whether that matches their intent.

## What We're Building

### The AI-in-the-Loop Workflow

The hackathon project adds a workflow where the AI generates both the spec
and the code from a natural language description, and the verifier checks
their agreement.

#### Step 1: Intent → Spec (before any code)

The AI reads the user's description and generates an F* spec. This happens
*first*, before any implementation. The spec captures *what* the programme
should do, not *how*.

Example — user says: "Write a BPF programme that returns 1 if the first
argument (r1) is greater than 100, otherwise returns 0."

AI generates:

```fstar
module UserSpec
open BPF.Spec
open BPF.State
open FStar.UInt64

let spec = post_only (fun st ->
  let r1_val = state_get_reg st r1 in
  let r0_val = state_get_reg st r0 in
  match r1_val with
  | Scalar v ->
    if gt v 100uL
    then r0_val == Scalar 1uL
    else r0_val == Scalar 0uL
  | _ -> True)
```

The user reviews this — 10 lines, no BPF knowledge needed, just "does this
say what I meant?"

#### Step 2: Intent → Code (independently)

The AI generates the BPF C implementation. It might use different
approaches (branches, conditional moves, arithmetic tricks) but the
observable behaviour should match the spec.

```c
SEC("xdp")
int check_threshold(struct xdp_md *ctx) {
    __u64 val = ctx->data;  // simplified for demo
    if (val > 100)
        return 1;
    return 0;
}
```

#### Step 3: Compile + Verify

```
$ clang -target bpf -O2 -c check.bpf.c -o check.bpf.o
$ bpf-verifier verify check.bpf.o --spec UserSpec.fst
```

If the proof passes: the code does what the spec says, and the spec says
what the user meant. Confidence is high.

If the proof fails: the verifier reports a counterexample — a concrete
initial state where the code and spec disagree. The AI can use this to
figure out which side is wrong and iterate.

#### Step 4: Iterate on Failure

When verification fails, the AI has three options:

1. **Fix the code** — the spec is right, the code has a bug. Use the
   counterexample to identify and fix the issue.
2. **Fix the spec** — the spec misunderstood the intent. Ask the user to
   clarify, update the spec, re-verify.
3. **Refine both** — the intent was ambiguous. The disagreement reveals
   the ambiguity, which the user resolves.

### Demo Scenarios

#### Scenario A: Happy Path

Intent: "Return the sum of r1 and r2"

- AI generates spec: `returns_value (add r1_init r2_init)`
- AI generates code: `return r1 + r2;`
- Verification passes.
- Human reads spec, confirms it matches intent.

#### Scenario B: Spec Catches a Code Bug

Intent: "Return 1 if r1 > 100, else 0"

- AI generates spec correctly (as above)
- AI generates code with an off-by-one: `if (val >= 100)` instead of
  `if (val > 100)`
- Verification fails with counterexample: `r1 = 100, expected r0 = 0,
  got r0 = 1`
- The bug is caught before any human reads the code.

#### Scenario C: Human Catches a Spec Bug

Intent: "Return 1 if the value is large" (ambiguous)

- AI generates spec: `if gt v 1000uL then ...` (interprets "large" as
  >1000)
- AI generates code: `if (val > 1000) return 1;` (consistent with its
  own interpretation)
- Verification passes — but the user meant >100, not >1000.
- User reads the spec, spots the misunderstanding, corrects it.
- Re-verification now fails against the code, exposing the real bug.

This scenario is important: it shows that even when the AI is
self-consistent, the spec gives the human a concise, readable artefact to
audit. The trust boundary moves from "read all the code" to "read the
spec."

#### Scenario D: Ambiguity Exposed

Intent: "Handle the map lookup result safely"

- AI generates spec: programme returns 0 on lookup failure
- AI generates code: programme returns -1 on lookup failure
- Verification fails — not because either is "wrong" in isolation, but
  because the intent was ambiguous about what "safely" means.
- The disagreement surfaces a design decision the user needs to make.

## Implementation Plan

### What needs building

1. **Prompt engineering for spec generation** — the AI needs guidance on
   how to write F* specs from natural language. This is a skill/prompt
   concern, not a tool concern. The spec combinators (`returns_value`,
   `post_only`, `with_pre`) are simple enough that a well-prompted model
   can generate them.

2. **Counterexample reporting** — the verifier currently reports pass/fail
   but the failure diagnostics could be more concrete. Improve the output
   to show the specific initial state and expected-vs-actual values when
   Z3 finds a counterexample.

3. **End-to-end demo script** — a scripted workflow that takes natural
   language, generates spec, generates code, compiles, verifies, and
   shows the result. For the hackathon demo, this can be a guided
   conversation rather than a fully automated pipeline.

4. **Additional spec combinators** — the existing combinators cover return
   values and register state. Might need combinators for map side-effects
   (e.g. "the programme writes value V to map M at key K") to support
   more interesting demos.

### What already works

- F* verification pipeline: parse → codegen → verify → report
- Spec language with combinators
- 28 passing test cases and 9 failing test cases
- Stack, branches, loops, map operations, helper functions
- Diagnostic output on verification failure

### Hackathon schedule

#### Day 1: Spec Generation + Better Diagnostics

- [ ] Write prompts/examples that teach the AI to generate F* specs from
  natural language descriptions
- [ ] Test spec generation on the existing corpus — can the AI produce
  specs that match the hand-written ones?
- [ ] Improve counterexample reporting in verification failures
- [ ] Add any missing spec combinators needed for the demo scenarios

#### Day 2: End-to-End Demo

- [ ] Build the full workflow: intent → spec → code → compile → verify
- [ ] Prepare demo scenarios A-D with working examples
- [ ] Handle the iteration loop: verification failure → AI fixes → re-verify
- [ ] Test with people unfamiliar with F* — can they read and audit the specs?

#### Day 3: Presentation

- [ ] Live demo showing all four scenarios
- [ ] Prepare slides on the broader concept: spec-first verification as
  a trust mechanism for AI-generated code
- [ ] Discussion: where else could this pattern apply? (not just BPF)

## The Bigger Picture

This hackathon project demonstrates a general pattern for trusting
AI-generated code:

1. **Separate intent from implementation** — generate the spec and the
   code independently from the same natural language source
2. **Verify agreement mechanically** — use formal verification to check
   that spec and code agree, rather than relying on human code review
3. **Make the trust boundary readable** — the spec is the thing the human
   audits, and it should be far simpler than the code

This pattern isn't limited to BPF. It could apply to:

- **Policy evaluation logic** — generate a policy and a formal spec of
  what it should match; verify they agree
- **Data transformations** — spec says "output has these properties";
  code does the transformation; verifier checks
- **Protocol implementations** — spec describes the state machine; code
  implements it; verifier checks conformance
- **Configuration generation** — spec describes invariants (no port
  conflicts, no circular dependencies); generated config is checked
  against them

The BPF domain is a good vehicle for the demo because the programmes are
small, the specs are concise, the tooling exists in this repo, and the
kernel's own verifier provides a familiar reference point. But the idea
— spec-first verification as a trust layer for AI output — is the real
contribution.

## Success Criteria

The demo is successful if:

1. The audience understands the spec-first workflow without needing to
   know F*
2. At least one demo shows the verifier catching a real AI-generated bug
   that would have passed conventional testing
3. At least one demo shows a spec that a non-expert can read and audit
   in under 30 seconds
4. The audience leaves thinking about where else this pattern could apply
   in their own work
