//! Kernel-style BPF verifier in pure Rust.
//!
//! This module implements the safety checks that the Linux kernel's BPF
//! verifier performs, without requiring root access or loading the programme.
//! It walks all reachable paths through a BPF programme and checks:
//!
//! - **Register types**: scalars, pointers (frame, ctx, map value, ring buffer),
//!   null, and uninitialised -- with proper tracking through moves and ALU ops.
//! - **Scalar ranges**: tnum (tracked number) bit-level precision plus
//!   signed/unsigned bounds, refined at every branch.
//! - **Memory safety**: every load/store must be within the proven bounds of
//!   the pointer's backing object (stack, map value, ctx, ring buffer).
//! - **Null safety**: map_lookup_elem and ringbuf_reserve return nullable
//!   pointers; the programme must null-check before dereferencing.
//! - **Stack initialisation**: reads from the 512-byte stack frame are only
//!   allowed after the slot has been written.
//! - **Helper validation**: only known helpers are callable; return types
//!   are tracked; caller-saved registers are clobbered.
//! - **Pointer arithmetic**: only add/sub of scalars to pointers is allowed;
//!   multiplying, shifting, or negating pointers is rejected.
//! - **Pointer leak prevention**: pointers cannot be returned in r0 at exit
//!   (would leak kernel addresses to userspace).
//! - **Termination**: bounded loops are verified via widening-based fixed-point
//!   iteration; truly unbounded loops are rejected.
//! - **ELF relocations**: LD_IMM64 instructions with relocations are typed
//!   as map fds or data pointers rather than raw scalars.

pub mod check;
pub mod error;
pub mod state;

pub use check::{check, CheckResult};
pub use error::{format_errors, VerifyError};
