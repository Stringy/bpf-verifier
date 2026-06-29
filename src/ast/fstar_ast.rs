//! F* AST intermediate representation.
//!
//! These types mirror the F* modules BPF.AST.Types, BPF.AST.Expr,
//! BPF.AST.Stmt, and BPF.AST.Decl. The converter builds these from
//! the Clang AST, and the emitter writes them out as F* source.

use std::fmt;

/// C type subset (mirrors BPF.AST.Types.c_type)
#[derive(Debug, Clone, PartialEq)]
pub enum CType {
    CInt(IntWidth),
    CUInt(IntWidth),
    CBool,
    CVoid,
    CPtr(Box<CType>),
    CPtrOrNull(Box<CType>),
    CStruct(StructDef),
    CArray(Box<CType>, usize),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IntWidth {
    W8,
    W16,
    W32,
    W64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<(String, CType)>,
}

/// Binary operators (mirrors BPF.AST.Expr.binop)
#[derive(Debug, Clone, Copy)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitAnd,
    BitOr,
    BitXor,
    ShiftL,
    ShiftR,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    LAnd,
    LOr,
}

/// Unary operators (mirrors BPF.AST.Expr.unaryop)
#[derive(Debug, Clone, Copy)]
pub enum UnaryOp {
    Neg,
    BitNot,
    LNot,
}

/// Expression (mirrors BPF.AST.Expr.expr, but unindexed — indices are
/// computed during F* emission)
#[derive(Debug, Clone)]
pub enum Expr {
    IntLit(i64, IntWidth),
    UIntLit(u64, IntWidth),
    BoolLit(bool),
    VarRef(String, CType),
    BinOp(BinOp, Box<Expr>, Box<Expr>),
    UnaryOp(UnaryOp, Box<Expr>),
    Deref(Box<Expr>),
    AddrOf(Box<Expr>),
    FieldAccess(Box<Expr>, String),
    Cast(Box<Expr>, CType),
    Call(String, Vec<Expr>),
    /// Ternary: cond ? then : else
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
}

/// Statement (mirrors BPF.AST.Stmt.stmt, but unindexed)
#[derive(Debug, Clone)]
pub enum Stmt {
    /// Variable declaration with optional initialiser
    Declare(String, CType, Option<Expr>),
    /// Assignment: var = expr
    Assign(String, Expr),
    /// If/else
    If(Expr, Vec<Stmt>, Vec<Stmt>),
    /// Return
    Return(Option<Expr>),
    /// Expression statement (e.g. function call as statement)
    ExprStmt(Expr),
    /// Compound (block)
    Compound(Vec<Stmt>),
}

/// Map definition (mirrors BPF.AST.Decl.map_def)
#[derive(Debug, Clone)]
pub struct MapDef {
    pub name: String,
    pub map_type: String,
    pub key_type: CType,
    pub value_type: CType,
    pub max_entries: usize,
}

/// A BPF programme function
#[derive(Debug, Clone)]
pub struct BpfProg {
    pub name: String,
    pub section: String,
    pub param_name: String,
    pub param_type: CType,
    pub return_type: CType,
    pub body: Vec<Stmt>,
}

/// Top-level BPF object
#[derive(Debug)]
pub struct BpfObject {
    pub source_file: String,
    pub maps: Vec<MapDef>,
    pub progs: Vec<BpfProg>,
}

// --- Display for F* emission helpers ---

impl fmt::Display for IntWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntWidth::W8 => write!(f, "W8"),
            IntWidth::W16 => write!(f, "W16"),
            IntWidth::W32 => write!(f, "W32"),
            IntWidth::W64 => write!(f, "W64"),
        }
    }
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BinOp::Add => write!(f, "Add"),
            BinOp::Sub => write!(f, "Sub"),
            BinOp::Mul => write!(f, "Mul"),
            BinOp::Div => write!(f, "Div"),
            BinOp::Mod => write!(f, "Mod"),
            BinOp::BitAnd => write!(f, "BitAnd"),
            BinOp::BitOr => write!(f, "BitOr"),
            BinOp::BitXor => write!(f, "BitXor"),
            BinOp::ShiftL => write!(f, "ShiftL"),
            BinOp::ShiftR => write!(f, "ShiftR"),
            BinOp::Eq => write!(f, "Eq"),
            BinOp::Ne => write!(f, "Ne"),
            BinOp::Lt => write!(f, "Lt"),
            BinOp::Le => write!(f, "Le"),
            BinOp::Gt => write!(f, "Gt"),
            BinOp::Ge => write!(f, "Ge"),
            BinOp::LAnd => write!(f, "LAnd"),
            BinOp::LOr => write!(f, "LOr"),
        }
    }
}

impl fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnaryOp::Neg => write!(f, "Neg"),
            UnaryOp::BitNot => write!(f, "BitNot"),
            UnaryOp::LNot => write!(f, "LNot"),
        }
    }
}
