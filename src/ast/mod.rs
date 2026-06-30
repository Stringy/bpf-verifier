//! AST-level BPF verification.
//!
//! Converts Clang JSON AST output into F* AST constructor applications
//! that the F* type system verifies. If the generated module typechecks,
//! the programme satisfies the structural safety properties encoded in
//! the indexed inductive types.

pub mod clang_ast;
pub mod convert;
pub mod emit;
pub mod emit_surface;
pub mod fstar_ast;
pub mod load;
