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

    // First pass: collect all function declarations from the user's
    // source file. We need to see all of them before converting because
    // BPF_PROG macro creates a trampoline + inner function pair and we
    // need to resolve the inner function's body.
    let mut all_func_nodes: Vec<&Node> = Vec::new();

    for node in &root.inner {
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

        let is_user_source = current_file.contains(source_file)
            || current_file.is_empty();

        if !is_user_source {
            continue;
        }

        match node.kind.as_str() {
            "FunctionDecl" => {
                all_func_nodes.push(node);
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

    // Second pass: convert functions, handling BPF_PROG trampolines.
    //
    // BPF_PROG(name, args...) expands to:
    //   - trace_name(unsigned long long *ctx)  [SEC'd trampoline]
    //   - ____trace_name(unsigned long long *ctx, typed_args...)  [real body]
    //
    // We want to emit the real body with the typed parameters, but
    // attribute it to the SEC'd name and section.
    //
    // Build a map from "____<name>" to its node (with body) so we can
    // look up the inner function when processing a trampoline.

    let mut inner_funcs: std::collections::HashMap<String, &Node> = std::collections::HashMap::new();
    for node in &all_func_nodes {
        if let Some(name) = &node.name {
            if name.starts_with("____") {
                let has_body = node.inner.iter().any(|n| n.kind == "CompoundStmt");
                if has_body {
                    inner_funcs.insert(name.clone(), node);
                }
            }
        }
    }

    let mut seen_sections = std::collections::HashSet::new();

    for node in &all_func_nodes {
        let name = match &node.name {
            Some(n) => n,
            None => continue,
        };

        // Skip ____-prefixed functions — they'll be pulled in via trampolines
        if name.starts_with("____") {
            continue;
        }

        // Only convert functions with a SEC attribute
        let section = node.inner.iter()
            .find(|n| n.kind == "SectionAttr")
            .and_then(|n| n.section_name.as_deref());
        let section = match section {
            Some(s) if s != "license" && s != ".maps" => s,
            _ => continue,
        };

        // Deduplicate: skip if we've already seen this section
        if !seen_sections.insert(section.to_string()) {
            continue;
        }

        // Check if there's a ____-prefixed inner function with the real body
        let inner_name = format!("____{}", name);
        let body_node = inner_funcs.get(&inner_name).copied().unwrap_or(node);

        match convert_function_with_body(node, body_node)
            .with_context(|| format!("converting function '{}'", name))?
        {
            Some(prog) => progs.push(prog),
            None => {}
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

    // Array types: "type[N]"
    if let Some(bracket_pos) = s.find('[') {
        let elem_type_str = s[..bracket_pos].trim();
        let size_str = s[bracket_pos + 1..].trim_end_matches(']').trim();
        let elem_type = parse_c_type(elem_type_str)?;
        let size: usize = size_str.parse().unwrap_or(0);
        return Ok(CType::CArray(Box::new(elem_type), size));
    }

    // Basic types
    match s {
        "void" => Ok(CType::CVoid),
        "_Bool" | "bool" => Ok(CType::CBool),

        // Unsigned
        "char" | "unsigned char" | "__u8" | "uint8_t" | "u8" => Ok(CType::CUInt(IntWidth::W8)),
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
            let fields = context_struct_fields(struct_name);
            Ok(CType::CStruct(StructDef {
                name: struct_name.to_string(),
                fields,
            }))
        }

        // Typedef names ending in _t — common in BPF/kernel code for
        // enum wrappers, integer typedefs, etc.
        s if s.ends_with("_t") => Ok(CType::CInt(IntWidth::W32)),

        // Fallback: treat unrecognised types as opaque pointer-sized values.
        // This handles typeof_unqual, __typeof__, and other compiler
        // builtins that appear in BPF_CORE_READ macro expansions.
        _ => Ok(CType::CUInt(IntWidth::W64)),
    }
}

/// Convert a FunctionDecl into a BpfProg using a (possibly different) node for the body.
///
/// `sec_node` provides the section attribute and programme name.
/// `body_node` provides the parameters and body — this may be the same node,
/// or it may be the `____`-prefixed inner function from a BPF_PROG expansion.
fn convert_function_with_body(sec_node: &Node, body_node: &Node) -> Result<Option<BpfProg>> {
    let name = sec_node.name.as_deref().unwrap_or("?");

    let section = sec_node
        .inner
        .iter()
        .find(|n| n.kind == "SectionAttr")
        .and_then(|n| n.section_name.as_deref());

    let section = match section {
        Some(s) if s != "license" && s != ".maps" => s.to_string(),
        _ => return Ok(None),
    };

    // Get return type from the SEC'd function (always int for BPF progs)
    let return_type = sec_node
        .qual_type()
        .and_then(|t| t.split('(').next().map(|r| r.trim()))
        .map(parse_c_type)
        .transpose()?
        .unwrap_or(CType::CInt(IntWidth::W32));

    // Get parameters from body_node — for BPF_PROG trampolines, the inner
    // function has the typed parameters (skipping the first ctx param which
    // is the raw unsigned long long *ctx from the trampoline).
    let params: Vec<&Node> = body_node.children_of_kind("ParmVarDecl");
    let (param_name, param_type) = if std::ptr::eq(sec_node, body_node) {
        // Same node — use the first parameter as-is
        let param = params.first();
        let pn = param
            .and_then(|p| p.name.as_deref())
            .unwrap_or("ctx")
            .to_string();
        let pt = param
            .and_then(|p| p.qual_type())
            .map(parse_c_type)
            .transpose()?
            .unwrap_or(CType::CPtr(Box::new(CType::CVoid)));
        (pn, pt)
    } else {
        // Inner function from BPF_PROG — skip the first param (raw ctx)
        // and use the second (typed context pointer)
        if params.len() >= 2 {
            let typed_param = params[1];
            let pn = typed_param
                .name
                .as_deref()
                .unwrap_or("ctx")
                .to_string();
            let pt = typed_param
                .qual_type()
                .map(parse_c_type)
                .transpose()?
                .unwrap_or(CType::CPtr(Box::new(CType::CVoid)));
            (pn, pt)
        } else {
            ("ctx".to_string(), CType::CPtr(Box::new(CType::CVoid)))
        }
    };

    // Get body from body_node
    let body_compound = body_node.first_child_of_kind("CompoundStmt");
    let body = match body_compound {
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

        "GotoStmt" => {
            let label = node.name.as_deref().unwrap_or("?").to_string();
            Ok(Stmt::Goto(label))
        }

        "LabelStmt" => {
            let label = node.name.as_deref().unwrap_or("?").to_string();
            // The labelled statement is the first (and only) child
            let body = if let Some(child) = node.inner.first() {
                convert_stmt(child)?
            } else {
                Stmt::Compound(vec![])
            };
            Ok(Stmt::Label(label, Box::new(body)))
        }

        "SwitchStmt" => {
            convert_switch(node)
        }

        "BreakStmt" => Ok(Stmt::Break),

        // Clang wraps the default: branch body in a DefaultStmt node.
        // We handle it like a compound of its children.
        "DefaultStmt" => {
            let stmts: Result<Vec<Stmt>> = node.inner.iter().map(convert_stmt).collect();
            Ok(Stmt::Compound(stmts?))
        }

        // Expression statement (e.g. function call as a statement)
        _ => {
            // Check for assignment: BinaryOperator with "=" opcode
            if node.kind == "BinaryOperator" && node.opcode.as_deref() == Some("=") {
                if let Some(assign) = try_convert_assignment(node)? {
                    return Ok(assign);
                }
            }
            // Check for compound assignment: +=, -=, etc.
            if node.kind == "CompoundAssignOperator" {
                if let Some(assign) = try_convert_compound_assignment(node)? {
                    return Ok(assign);
                }
            }
            // Increment/decrement as statement: x++ or ++x
            if node.kind == "UnaryOperator" {
                if let Some(op) = node.opcode.as_deref() {
                    if op == "++" || op == "--" {
                        if let Some(assign) = try_convert_inc_dec_stmt(node, op)? {
                            return Ok(assign);
                        }
                    }
                }
            }
            let expr = convert_expr(node)?;
            Ok(Stmt::ExprStmt(expr))
        }
    }
}

/// Convert a SwitchStmt into our Switch representation.
///
/// Clang represents switch as:
///   SwitchStmt → [condition_expr, CompoundStmt]
///   CompoundStmt → [CaseStmt, CaseStmt, DefaultStmt, ...]
///   CaseStmt → [value_expr, body_stmt, ...]
fn convert_switch(node: &Node) -> Result<Stmt> {
    if node.inner.len() < 2 {
        bail!("SwitchStmt with fewer than 2 children");
    }

    let cond = convert_expr(&node.inner[0])?;

    // The second child is typically a CompoundStmt containing CaseStmt nodes
    let body = &node.inner[1];
    let case_nodes = if body.kind == "CompoundStmt" {
        &body.inner
    } else {
        std::slice::from_ref(body)
    };

    let mut cases = Vec::new();
    for case_node in case_nodes {
        match case_node.kind.as_str() {
            "CaseStmt" => {
                if case_node.inner.is_empty() {
                    continue;
                }
                // First child is the case value (possibly wrapped in ConstantExpr)
                let value = convert_expr(&case_node.inner[0])?;
                // Remaining children are the body statements
                let body_stmts: Result<Vec<Stmt>> =
                    case_node.inner[1..].iter().map(convert_stmt).collect();
                cases.push(SwitchCase {
                    value: Some(value),
                    body: body_stmts?,
                });
            }
            "DefaultStmt" => {
                let body_stmts: Result<Vec<Stmt>> =
                    case_node.inner.iter().map(convert_stmt).collect();
                cases.push(SwitchCase {
                    value: None,
                    body: body_stmts?,
                });
            }
            _ => {
                // Stray statement between cases — append to previous case
                let stmt = convert_stmt(case_node)?;
                if let Some(last) = cases.last_mut() {
                    last.body.push(stmt);
                }
            }
        }
    }

    Ok(Stmt::Switch(cond, cases))
}

/// Try to convert a BinaryOperator with "=" into an Assign statement.
///
/// Returns None if the LHS isn't a simple variable reference (e.g. it's
/// a struct field assignment like `args.metrics = ...` which we model
/// as an expression statement instead).
fn try_convert_assignment(node: &Node) -> Result<Option<Stmt>> {
    if node.inner.len() < 2 {
        return Ok(None);
    }
    let lhs = &node.inner[0];
    let rhs = &node.inner[1];

    // Simple variable assignment: x = expr
    if let Some(name) = extract_lhs_var_name(lhs) {
        let value = convert_expr(rhs)?;
        return Ok(Some(Stmt::Assign(name, value)));
    }
    Ok(None)
}

/// Try to convert a CompoundAssignOperator (+=, -=, etc.) into an Assign.
fn try_convert_compound_assignment(node: &Node) -> Result<Option<Stmt>> {
    if node.inner.len() < 2 {
        return Ok(None);
    }
    let op = node
        .opcode
        .as_deref()
        .ok_or_else(|| anyhow!("CompoundAssignOperator without opcode"))?;

    let binop = match op {
        "+=" => BinOp::Add,
        "-=" => BinOp::Sub,
        "*=" => BinOp::Mul,
        "/=" => BinOp::Div,
        "%=" => BinOp::Mod,
        "&=" => BinOp::BitAnd,
        "|=" => BinOp::BitOr,
        "^=" => BinOp::BitXor,
        "<<=" => BinOp::ShiftL,
        ">>=" => BinOp::ShiftR,
        _ => return Ok(None),
    };

    let lhs = &node.inner[0];
    let rhs = &node.inner[1];

    if let Some(name) = extract_lhs_var_name(lhs) {
        let lhs_expr = convert_expr(lhs)?;
        let rhs_expr = convert_expr(rhs)?;
        let combined = Expr::BinOp(binop, Box::new(lhs_expr), Box::new(rhs_expr));
        return Ok(Some(Stmt::Assign(name, combined)));
    }
    Ok(None)
}

/// Try to convert a unary ++/-- as a statement into an Assign.
fn try_convert_inc_dec_stmt(node: &Node, op: &str) -> Result<Option<Stmt>> {
    if node.inner.is_empty() {
        return Ok(None);
    }
    let operand = &node.inner[0];
    if let Some(name) = extract_lhs_var_name(operand) {
        let var_expr = convert_expr(operand)?;
        let one = Expr::IntLit(1, IntWidth::W32);
        let binop = if op == "++" { BinOp::Add } else { BinOp::Sub };
        let combined = Expr::BinOp(binop, Box::new(var_expr), Box::new(one));
        return Ok(Some(Stmt::Assign(name, combined)));
    }
    Ok(None)
}

/// Extract the variable name from an LHS expression if it's a simple
/// variable reference (possibly wrapped in implicit casts).
fn extract_lhs_var_name(node: &Node) -> Option<String> {
    match node.kind.as_str() {
        "DeclRefExpr" => node.ref_name().map(|s| s.to_string()),
        "ImplicitCastExpr" => node.inner.first().and_then(extract_lhs_var_name),
        _ => None,
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

        "BinaryOperator" | "CompoundAssignOperator" => {
            let op = node
                .opcode
                .as_deref()
                .ok_or_else(|| anyhow!("BinaryOperator without opcode"))?;
            if node.inner.len() < 2 {
                bail!("BinaryOperator with fewer than 2 children");
            }
            // Assignment operators in expression context — model as the
            // RHS value (the assignment side-effect is handled at the
            // statement level when possible).
            match op {
                "=" => {
                    // In expression context, x = y evaluates to y
                    convert_expr(&node.inner[1])
                }
                "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<=" | ">>=" => {
                    // Compound assignment in expression context — model as the
                    // binary operation (lhs op rhs)
                    let compound_op = match op {
                        "+=" => BinOp::Add, "-=" => BinOp::Sub,
                        "*=" => BinOp::Mul, "/=" => BinOp::Div,
                        "%=" => BinOp::Mod, "&=" => BinOp::BitAnd,
                        "|=" => BinOp::BitOr, "^=" => BinOp::BitXor,
                        "<<=" => BinOp::ShiftL, ">>=" => BinOp::ShiftR,
                        _ => unreachable!(),
                    };
                    let lhs = convert_expr(&node.inner[0])?;
                    let rhs = convert_expr(&node.inner[1])?;
                    Ok(Expr::BinOp(compound_op, Box::new(lhs), Box::new(rhs)))
                }
                _ => {
                    let op = parse_binop(op)?;
                    let lhs = convert_expr(&node.inner[0])?;
                    let rhs = convert_expr(&node.inner[1])?;
                    Ok(Expr::BinOp(op, Box::new(lhs), Box::new(rhs)))
                }
            }
        }

        "UnaryOperator" => {
            let op = node
                .opcode
                .as_deref()
                .ok_or_else(|| anyhow!("UnaryOperator without opcode"))?;
            if node.inner.is_empty() {
                bail!("UnaryOperator with no children");
            }
            let inner = convert_expr(&node.inner[0])?;
            match op {
                "*" => Ok(Expr::Deref(Box::new(inner))),
                "&" => Ok(Expr::AddrOf(Box::new(inner))),
                "-" => Ok(Expr::UnaryOp(UnaryOp::Neg, Box::new(inner))),
                "~" => Ok(Expr::UnaryOp(UnaryOp::BitNot, Box::new(inner))),
                "!" => Ok(Expr::UnaryOp(UnaryOp::LNot, Box::new(inner))),
                "++" => Ok(Expr::UnaryOp(UnaryOp::PreInc, Box::new(inner))),
                "--" => Ok(Expr::UnaryOp(UnaryOp::PreDec, Box::new(inner))),
                _ => Err(anyhow!("unrecognised unary operator: '{}'", op)),
            }
        }

        // Postfix increment/decrement — Clang uses a separate node kind
        // but in practice it appears as UnaryOperator with isPostfix.
        // Some clang versions emit it as UnaryOperator with "++" opcode
        // regardless. We handle both prefix and postfix the same way
        // since our AST models the side effect, not the evaluation order.

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
            // If the base is a pointer to struct (arrow operator ctx->field),
            // insert a Deref so the F* AST sees FieldAccess(Deref(ptr), field)
            // which matches the FieldAccess constructor expecting CStruct, not CPtr.
            let base = match base_type(&base) {
                Some(CType::CPtr(_)) => Expr::Deref(Box::new(base)),
                _ => base,
            };
            Ok(Expr::FieldAccess(Box::new(base), field))
        }

        "ArraySubscriptExpr" => {
            // arr[idx] — first child is the array/pointer, second is the index
            if node.inner.len() < 2 {
                bail!("ArraySubscriptExpr with fewer than 2 children");
            }
            let base = convert_expr(&node.inner[0])?;
            let index = convert_expr(&node.inner[1])?;
            Ok(Expr::ArraySubscript(Box::new(base), Box::new(index)))
        }

        "StringLiteral" => {
            let val = node
                .value
                .as_deref()
                .unwrap_or("\"\"")
                .to_string();
            // Clang includes the surrounding quotes in the value field
            let val = val.trim_matches('"').to_string();
            Ok(Expr::StringLit(val))
        }

        "UnaryExprOrTypeTraitExpr" => {
            // sizeof — Clang puts the name as "sizeof". The child is the
            // operand (type or expr). We evaluate it as a constant if
            // possible, otherwise fall back to the type size.
            let type_str = node.qual_type().unwrap_or("unsigned long");
            // The inner node, if present, gives us the operand type
            let operand_type = node
                .inner
                .first()
                .and_then(|n| n.qual_type())
                .or_else(|| node.inner.first().and_then(|n| {
                    // ParenExpr wrapping a type reference
                    n.inner.first().and_then(|inner| inner.qual_type())
                }));
            let size = match operand_type {
                Some(t) => estimate_type_size(t),
                None => 8, // default to pointer size
            };
            let _ = type_str; // result type is unsigned long
            Ok(Expr::SizeOf(size))
        }

        "StmtExpr" => {
            // GNU statement expression: ({ stmt; stmt; expr; })
            // The child is a CompoundStmt. The value is the last expression.
            if node.inner.is_empty() {
                bail!("StmtExpr with no children");
            }
            let compound = &node.inner[0];
            if compound.inner.is_empty() {
                return Ok(Expr::IntLit(0, IntWidth::W32));
            }
            let last_idx = compound.inner.len() - 1;
            let stmts: Result<Vec<Stmt>> = compound.inner[..last_idx]
                .iter()
                .map(convert_stmt)
                .collect();
            let last_expr = convert_expr(&compound.inner[last_idx])?;
            Ok(Expr::StmtExpr(stmts?, Box::new(last_expr)))
        }

        "InitListExpr" => {
            // Initialiser list: {expr, expr, ...}
            // Children are the initialisers (may include ImplicitValueInitExpr for gaps)
            let exprs: Result<Vec<Expr>> = node.inner.iter().map(convert_expr).collect();
            Ok(Expr::InitList(exprs?))
        }

        "ImplicitValueInitExpr" => {
            // Zero-initialisation for struct/array members not explicitly initialised
            // We represent as an integer zero of the appropriate type
            let ty = node.qual_type().unwrap_or("int");
            let width = type_to_int_width(ty);
            Ok(Expr::IntLit(0, width))
        }

        "ConstantExpr" => {
            // Wrapper around a compile-time constant — look through to inner
            if node.inner.is_empty() {
                // Some ConstantExpr have a value directly
                let val: i64 = node
                    .value
                    .as_deref()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
                Ok(Expr::IntLit(val, IntWidth::W32))
            } else {
                convert_expr(&node.inner[0])
            }
        }

        // Empty nodes (Clang emits {} for synthetic placeholders)
        "" => Ok(Expr::IntLit(0, IntWidth::W32)),

        _ => Err(anyhow!(
            "unrecognised expression kind: '{}' (type: {:?})",
            node.kind,
            node.qual_type()
        )),
    }
}

/// Get the approximate C type of an expression (for deciding whether
/// to insert a Deref for arrow-operator field access).
fn base_type(expr: &Expr) -> Option<CType> {
    match expr {
        Expr::VarRef(_, ty) => Some(ty.clone()),
        Expr::Deref(inner) => match base_type(inner)? {
            CType::CPtr(inner_ty) => Some(*inner_ty),
            _ => None,
        },
        Expr::Cast(_, ty) => Some(ty.clone()),
        _ => None,
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

/// Return known fields for BPF context structs.
///
/// These must match the definitions in BPF.AST.Decl.prog_ctx_type
/// exactly — same field names, same types, same order — otherwise
/// F*'s FieldAccess check (has_field) will reject the access.
fn context_struct_fields(struct_name: &str) -> Vec<(String, CType)> {
    match struct_name {
        "__sk_buff" => vec![
            ("len".into(), CType::CUInt(IntWidth::W32)),
            ("protocol".into(), CType::CUInt(IntWidth::W32)),
            ("data".into(), CType::CUInt(IntWidth::W32)),
            ("data_end".into(), CType::CUInt(IntWidth::W32)),
        ],
        "xdp_md" => vec![
            ("data".into(), CType::CUInt(IntWidth::W32)),
            ("data_end".into(), CType::CUInt(IntWidth::W32)),
            ("data_meta".into(), CType::CUInt(IntWidth::W32)),
            ("ingress_ifindex".into(), CType::CUInt(IntWidth::W32)),
            ("rx_queue_index".into(), CType::CUInt(IntWidth::W32)),
        ],
        "pt_regs" => vec![
            ("di".into(), CType::CUInt(IntWidth::W64)),
            ("si".into(), CType::CUInt(IntWidth::W64)),
            ("dx".into(), CType::CUInt(IntWidth::W64)),
            ("cx".into(), CType::CUInt(IntWidth::W64)),
            ("r8".into(), CType::CUInt(IntWidth::W64)),
            ("r9".into(), CType::CUInt(IntWidth::W64)),
            ("ax".into(), CType::CUInt(IntWidth::W64)),
            ("sp".into(), CType::CUInt(IntWidth::W64)),
            ("ip".into(), CType::CUInt(IntWidth::W64)),
        ],
        _ => vec![], // Unknown struct — no field validation
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

/// Estimate the byte size of a C type from its string representation.
/// Used for sizeof() evaluation.
fn estimate_type_size(type_str: &str) -> u64 {
    let s = type_str.trim();
    // Pointer types
    if s.ends_with('*') {
        return 8;
    }
    match s {
        "void" => 0,
        "_Bool" | "bool" => 1,
        "unsigned char" | "__u8" | "uint8_t" | "u8"
        | "signed char" | "__s8" | "int8_t" | "s8" | "char" => 1,
        "unsigned short" | "__u16" | "uint16_t" | "u16"
        | "short" | "__s16" | "int16_t" | "s16" => 2,
        "unsigned int" | "__u32" | "uint32_t" | "u32"
        | "int" | "__s32" | "int32_t" | "s32" => 4,
        "unsigned long" | "unsigned long long" | "__u64" | "uint64_t" | "u64"
        | "long" | "long long" | "__s64" | "int64_t" | "s64" => 8,
        _ => 8, // default to pointer size for unknown types (structs etc.)
    }
}
