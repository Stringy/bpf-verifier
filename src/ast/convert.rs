//! Clang AST → F* AST conversion.
//!
//! Walks the Clang JSON AST and builds our intermediate F* AST
//! representation. Handles:
//! - Type mapping (C types → BPF.AST.Types.c_type)
//! - Expression conversion (Clang exprs → our Expr)
//! - Statement conversion (Clang stmts → our Stmt)
//! - Top-level declaration extraction (functions, maps)

use anyhow::{anyhow, bail, Context, Result};

use super::clang_ast::Node;
use super::fstar_ast::*;

/// Convert a Clang translation unit into a BpfObject.
///
/// `source_file` is used to filter declarations. We use a tracking approach:
/// Clang only emits the `file` field when it changes. We track the last-seen
/// file and use it to determine which declarations are from the user's source
/// versus system headers.
pub fn convert_translation_unit(root: &Node, source_file: &str) -> Result<BpfObject> {
    if root.kind != "TranslationUnitDecl" {
        bail!("Expected TranslationUnitDecl, got {}", root.kind);
    }

    let mut maps = Vec::new();
    let mut progs = Vec::new();
    let mut current_file = String::new();

    for node in &root.inner {
        // Skip implicit/builtin declarations
        if node.is_implicit.unwrap_or(false) {
            continue;
        }

        // Track the current file: Clang only emits `file` when it changes
        if let Some(loc) = &node.loc {
            if let Some(file) = &loc.file {
                current_file = file.clone();
            } else if let Some(exp) = &loc.expansion_loc {
                if let Some(file) = &exp.file {
                    current_file = file.clone();
                }
            }
        }

        // Only process declarations from the user's source file
        let is_user_source = current_file.contains(source_file)
            || current_file.is_empty();

        if !is_user_source {
            continue;
        }

        match node.kind.as_str() {
            "FunctionDecl" => {
                if let Some(name) = &node.name {
                    if let Some(prog) = convert_function(node)
                        .with_context(|| format!("converting function '{}'", name))?
                    {
                        progs.push(prog);
                    }
                }
            }
            "VarDecl" => {
                if let Some(name) = &node.name {
                    if let Some(map) = convert_map_def(node)
                        .with_context(|| format!("converting variable '{}'", name))?
                    {
                        maps.push(map);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(BpfObject {
        source_file: source_file.to_string(),
        maps,
        progs,
    })
}

/// Parse a C type string from Clang into our CType.
pub fn parse_c_type(type_str: &str) -> Result<CType> {
    let s = type_str.trim();

    // Handle const qualifier by stripping it
    let s = s.strip_prefix("const ").unwrap_or(s);
    let s = s.strip_suffix(" const").unwrap_or(s);

    // Pointer types
    if let Some(inner) = s.strip_suffix('*') {
        let inner = inner.trim();
        let inner_type = parse_c_type(inner)?;
        return Ok(CType::CPtr(Box::new(inner_type)));
    }

    // Basic types
    match s {
        "void" => Ok(CType::CVoid),
        "_Bool" | "bool" => Ok(CType::CBool),

        // Unsigned
        "unsigned char" | "__u8" | "uint8_t" | "u8" => Ok(CType::CUInt(IntWidth::W8)),
        "unsigned short" | "__u16" | "uint16_t" | "u16" => Ok(CType::CUInt(IntWidth::W16)),
        "unsigned int" | "__u32" | "uint32_t" | "u32" => Ok(CType::CUInt(IntWidth::W32)),
        "unsigned long" | "unsigned long long" | "__u64" | "uint64_t" | "u64" => {
            Ok(CType::CUInt(IntWidth::W64))
        }

        // Signed
        "signed char" | "__s8" | "int8_t" | "s8" => Ok(CType::CInt(IntWidth::W8)),
        "short" | "__s16" | "int16_t" | "s16" => Ok(CType::CInt(IntWidth::W16)),
        "int" | "__s32" | "int32_t" | "s32" => Ok(CType::CInt(IntWidth::W32)),
        "long" | "long long" | "__s64" | "int64_t" | "s64" => Ok(CType::CInt(IntWidth::W64)),

        // Struct types
        s if s.starts_with("struct ") => {
            let struct_name = s.strip_prefix("struct ").unwrap().trim();
            Ok(CType::CStruct(StructDef {
                name: struct_name.to_string(),
                fields: vec![], // Fields populated elsewhere if needed
            }))
        }

        _ => Err(anyhow!("unrecognised C type: '{}'", s)),
    }
}

/// Convert a FunctionDecl into a BpfProg, if it has a SEC() attribute.
fn convert_function(node: &Node) -> Result<Option<BpfProg>> {
    let name = node.name.as_deref().unwrap_or("?");

    // Find section attribute — Clang stores it in the `section_name` field
    let section = node
        .inner
        .iter()
        .find(|n| n.kind == "SectionAttr")
        .and_then(|n| n.section_name.as_deref());

    // Skip functions without SEC() — they're not BPF programme entry points
    let section = match section {
        Some(s) => s.to_string(),
        None => return Ok(None),
    };

    // Skip license and other non-programme sections
    if section == "license" || section == ".maps" {
        return Ok(None);
    }

    // Get return type
    let return_type = node
        .qual_type()
        .and_then(|t| {
            // Function type is "int (struct __sk_buff *)" — extract return type
            t.split('(').next().map(|r| r.trim())
        })
        .map(parse_c_type)
        .transpose()?
        .unwrap_or(CType::CInt(IntWidth::W32));

    // Get parameter
    let param = node.first_child_of_kind("ParmVarDecl");
    let param_name = param
        .and_then(|p| p.name.as_deref())
        .unwrap_or("ctx")
        .to_string();
    let param_type = param
        .and_then(|p| p.qual_type())
        .map(parse_c_type)
        .transpose()?
        .unwrap_or(CType::CPtr(Box::new(CType::CVoid)));

    // Get body (CompoundStmt)
    let body_node = node.first_child_of_kind("CompoundStmt");
    let body = match body_node {
        Some(compound) => convert_compound_stmt(compound)?,
        None => vec![],
    };

    Ok(Some(BpfProg {
        name: name.to_string(),
        section,
        param_name,
        param_type,
        return_type,
        body,
    }))
}

/// Convert a VarDecl into a MapDef, if it's a map (SEC(".maps") or
/// annotated struct with __uint/__type fields).
fn convert_map_def(node: &Node) -> Result<Option<MapDef>> {
    let name = node.name.as_deref().unwrap_or("?");

    // Check if this has a .maps section attribute
    let is_map_section = node.inner.iter().any(|n| {
        n.kind == "SectionAttr"
            && n.section_name.as_deref() == Some(".maps")
    });

    if !is_map_section {
        return Ok(None);
    }

    // For now, emit a placeholder map def. Full BTF-style map parsing
    // would require understanding the __uint/__type macros which are
    // expanded by the preprocessor into struct fields.
    Ok(Some(MapDef {
        name: name.to_string(),
        map_type: "BPF_MAP_TYPE_HASH".to_string(),
        key_type: CType::CUInt(IntWidth::W32),
        value_type: CType::CUInt(IntWidth::W64),
        max_entries: 1024,
    }))
}

/// Convert a CompoundStmt's children into a list of Stmts.
fn convert_compound_stmt(node: &Node) -> Result<Vec<Stmt>> {
    let mut stmts = Vec::new();
    for child in &node.inner {
        stmts.push(convert_stmt(child)?);
    }
    Ok(stmts)
}

/// Convert a single Clang statement node into our Stmt.
fn convert_stmt(node: &Node) -> Result<Stmt> {
    match node.kind.as_str() {
        "DeclStmt" => {
            // Variable declaration
            if let Some(var_decl) = node.first_child_of_kind("VarDecl") {
                let name = var_decl.name.as_deref().unwrap_or("?").to_string();
                let ty = var_decl
                    .qual_type()
                    .map(parse_c_type)
                    .transpose()?
                    .unwrap_or(CType::CInt(IntWidth::W32));
                let init = if var_decl.inner.is_empty() {
                    None
                } else {
                    // The initialiser is typically the last inner node
                    // (after type nodes)
                    var_decl
                        .inner
                        .iter()
                        .filter(|n| !n.kind.ends_with("Type") && n.kind != "BuiltinType")
                        .last()
                        .map(convert_expr)
                        .transpose()?
                };
                Ok(Stmt::Declare(name, ty, init))
            } else {
                bail!("DeclStmt without VarDecl")
            }
        }

        "ReturnStmt" => {
            let expr = node.inner.first().map(convert_expr).transpose()?;
            Ok(Stmt::Return(expr))
        }

        "IfStmt" => {
            let children: Vec<&Node> = node.inner.iter().collect();
            if children.len() < 2 {
                bail!("IfStmt with fewer than 2 children");
            }

            let cond = convert_expr(children[0])?;
            let then_branch = convert_stmt(children[1])?;
            let else_branch = if children.len() > 2 {
                convert_stmt(children[2])?
            } else {
                Stmt::Compound(vec![])
            };

            let then_stmts = match then_branch {
                Stmt::Compound(s) => s,
                s => vec![s],
            };
            let else_stmts = match else_branch {
                Stmt::Compound(s) => s,
                s => vec![s],
            };

            Ok(Stmt::If(cond, then_stmts, else_stmts))
        }

        "CompoundStmt" => {
            let stmts = convert_compound_stmt(node)?;
            Ok(Stmt::Compound(stmts))
        }

        // Expression statement (e.g. function call as a statement)
        _ => {
            let expr = convert_expr(node)?;
            Ok(Stmt::ExprStmt(expr))
        }
    }
}

/// Convert a Clang expression node into our Expr.
fn convert_expr(node: &Node) -> Result<Expr> {
    match node.kind.as_str() {
        "IntegerLiteral" => {
            let val: i64 = node
                .value
                .as_deref()
                .ok_or_else(|| anyhow!("IntegerLiteral without value"))?
                .parse()
                .context("parsing integer literal")?;
            let type_str = node.qual_type().unwrap_or("int");
            let width = type_to_int_width(type_str);
            // Respect Clang's type: unsigned types → UIntLit, signed → IntLit
            let is_unsigned = type_str.contains("unsigned") || type_str.starts_with("__u")
                || type_str.starts_with("uint");
            if is_unsigned {
                Ok(Expr::UIntLit(val as u64, width))
            } else {
                Ok(Expr::IntLit(val, width))
            }
        }

        "DeclRefExpr" => {
            let name = node
                .ref_name()
                .ok_or_else(|| anyhow!("DeclRefExpr without referenced decl"))?
                .to_string();
            let ty = node
                .qual_type()
                .map(parse_c_type)
                .transpose()?
                .unwrap_or(CType::CInt(IntWidth::W32));
            Ok(Expr::VarRef(name, ty))
        }

        "BinaryOperator" => {
            let op = node
                .opcode
                .as_deref()
                .ok_or_else(|| anyhow!("BinaryOperator without opcode"))?;
            let op = parse_binop(op)?;
            if node.inner.len() < 2 {
                bail!("BinaryOperator with fewer than 2 children");
            }
            let lhs = convert_expr(&node.inner[0])?;
            let rhs = convert_expr(&node.inner[1])?;
            Ok(Expr::BinOp(op, Box::new(lhs), Box::new(rhs)))
        }

        "UnaryOperator" => {
            let op = node
                .opcode
                .as_deref()
                .ok_or_else(|| anyhow!("UnaryOperator without opcode"))?;
            if node.inner.is_empty() {
                bail!("UnaryOperator with no children");
            }
            match op {
                "*" => {
                    // Pointer dereference
                    let inner = convert_expr(&node.inner[0])?;
                    Ok(Expr::Deref(Box::new(inner)))
                }
                "&" => {
                    let inner = convert_expr(&node.inner[0])?;
                    Ok(Expr::AddrOf(Box::new(inner)))
                }
                "-" => {
                    let inner = convert_expr(&node.inner[0])?;
                    Ok(Expr::UnaryOp(UnaryOp::Neg, Box::new(inner)))
                }
                "~" => {
                    let inner = convert_expr(&node.inner[0])?;
                    Ok(Expr::UnaryOp(UnaryOp::BitNot, Box::new(inner)))
                }
                "!" => {
                    let inner = convert_expr(&node.inner[0])?;
                    Ok(Expr::UnaryOp(UnaryOp::LNot, Box::new(inner)))
                }
                _ => Err(anyhow!("unrecognised unary operator: '{}'", op)),
            }
        }

        "CallExpr" => {
            // First child is the function expression (usually a DeclRefExpr
            // wrapped in an ImplicitCastExpr)
            if node.inner.is_empty() {
                bail!("CallExpr with no children");
            }
            let func_name = extract_call_name(&node.inner[0])
                .unwrap_or_else(|| "<unknown>".to_string());
            let args: Result<Vec<Expr>> = node.inner[1..].iter().map(convert_expr).collect();
            Ok(Expr::Call(func_name, args?))
        }

        "ConditionalOperator" => {
            if node.inner.len() < 3 {
                bail!("ConditionalOperator with fewer than 3 children");
            }
            let cond = convert_expr(&node.inner[0])?;
            let then_expr = convert_expr(&node.inner[1])?;
            let else_expr = convert_expr(&node.inner[2])?;
            Ok(Expr::Ternary(
                Box::new(cond),
                Box::new(then_expr),
                Box::new(else_expr),
            ))
        }

        // Implicit casts: look through them to the inner expression
        "ImplicitCastExpr" | "CStyleCastExpr" => {
            if node.inner.is_empty() {
                bail!("{} with no children", node.kind);
            }

            let inner = convert_expr(&node.inner[0])?;

            // For explicit casts, wrap in a Cast node
            if node.kind == "CStyleCastExpr" {
                if let Some(ty) = node.qual_type().map(parse_c_type).transpose()? {
                    return Ok(Expr::Cast(Box::new(inner), ty));
                }
            }

            // For implicit casts, we mostly look through them.
            // But NullToPointer is important — it means a literal 0
            // being used as a null pointer.
            if node.cast_kind.as_deref() == Some("NullToPointer") {
                // Keep the inner expression (usually IntegerLiteral 0)
                return Ok(inner);
            }

            Ok(inner)
        }

        "ParenExpr" => {
            if node.inner.is_empty() {
                bail!("ParenExpr with no children");
            }
            convert_expr(&node.inner[0])
        }

        "MemberExpr" => {
            if node.inner.is_empty() {
                bail!("MemberExpr with no children");
            }
            let base = convert_expr(&node.inner[0])?;
            let field = node.name.as_deref().unwrap_or("?").to_string();
            Ok(Expr::FieldAccess(Box::new(base), field))
        }

        _ => Err(anyhow!(
            "unrecognised expression kind: '{}' (type: {:?})",
            node.kind,
            node.qual_type()
        )),
    }
}

/// Extract the function name from a call expression's first child.
fn extract_call_name(node: &Node) -> Option<String> {
    match node.kind.as_str() {
        "DeclRefExpr" => node.ref_name().map(|s| s.to_string()),
        "ImplicitCastExpr" => node.inner.first().and_then(extract_call_name),
        _ => None,
    }
}

fn parse_binop(op: &str) -> Result<BinOp> {
    match op {
        "+" => Ok(BinOp::Add),
        "-" => Ok(BinOp::Sub),
        "*" => Ok(BinOp::Mul),
        "/" => Ok(BinOp::Div),
        "%" => Ok(BinOp::Mod),
        "&" => Ok(BinOp::BitAnd),
        "|" => Ok(BinOp::BitOr),
        "^" => Ok(BinOp::BitXor),
        "<<" => Ok(BinOp::ShiftL),
        ">>" => Ok(BinOp::ShiftR),
        "==" => Ok(BinOp::Eq),
        "!=" => Ok(BinOp::Ne),
        "<" => Ok(BinOp::Lt),
        "<=" => Ok(BinOp::Le),
        ">" => Ok(BinOp::Gt),
        ">=" => Ok(BinOp::Ge),
        "&&" => Ok(BinOp::LAnd),
        "||" => Ok(BinOp::LOr),
        _ => Err(anyhow!("unrecognised binary operator: '{}'", op)),
    }
}

fn type_to_int_width(type_str: &str) -> IntWidth {
    match type_str {
        s if s.contains("64") || s.contains("long long") => IntWidth::W64,
        s if s.contains("16") || s.contains("short") => IntWidth::W16,
        s if s.contains("8") || s.contains("char") => IntWidth::W8,
        _ => IntWidth::W32,
    }
}
