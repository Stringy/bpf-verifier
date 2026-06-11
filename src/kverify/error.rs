use std::fmt;

use crate::bpf::instruction::Reg;
use crate::elf::parser::SourceLoc;

/// A verification error anchored to a specific instruction, with optional
/// DWARF source location for pointing at the C code that caused it.
#[derive(Debug, Clone)]
pub struct VerifyError {
    /// Programme counter (instruction index) where the error was detected.
    pub pc: usize,
    /// What went wrong.
    pub kind: ErrorKind,
    /// DWARF source location (file:line), if available.
    pub source_loc: Option<SourceLoc>,
}

#[derive(Debug, Clone)]
pub enum ErrorKind {
    /// Attempted to read an uninitialised stack slot.
    UninitStackRead {
        offset: i64,
        width: u8,
    },
    /// Memory access out of bounds for the backing region.
    OutOfBoundsAccess {
        reg: Reg,
        ptr_kind: &'static str,
        offset: i64,
        width: u8,
        region_size: i64,
    },
    /// Dereferenced a register that might be null (e.g. unchecked map_lookup_elem return).
    NullPointerDeref {
        reg: Reg,
        /// Where the nullable pointer was created (helper call PC).
        origin_pc: Option<usize>,
        origin_loc: Option<SourceLoc>,
    },
    /// Dereferenced a register that doesn't hold a valid pointer.
    InvalidPointerDeref {
        reg: Reg,
        actual: String,
    },
    /// Used an unknown or disallowed BPF helper.
    UnknownHelper {
        id: i32,
    },
    /// Helper argument has wrong type.
    InvalidHelperArg {
        helper: String,
        arg_index: usize,
        expected: String,
        actual: String,
    },
    /// Programme exceeds the instruction complexity limit.
    ComplexityExceeded {
        limit: usize,
        visited: usize,
    },
    /// Back-edge detected without a bounded loop proof.
    UnboundedLoop {
        target_pc: usize,
    },
    /// Register used before being written.
    UninitRegRead {
        reg: Reg,
    },
    /// ALU operation on a pointer that isn't allowed.
    InvalidPointerArith {
        reg: Reg,
        op: String,
    },
    /// Division or modulo by zero.
    DivByZero {
        divisor_reg: Reg,
    },
    /// Programme falls through without an exit instruction.
    FallThrough,
    /// Unknown/unsupported opcode.
    UnknownOpcode {
        raw: u8,
    },
    /// R0 is not a scalar at exit.
    InvalidReturnType {
        actual: String,
    },
    /// Shift amount exceeds operand width.
    ShiftOverflow {
        width: u8,
        amount: u64,
    },
    /// Pointer leaked (returned in r0 or stored without proper spill).
    PtrLeak {
        reg: Reg,
        ptr_kind: String,
    },
    /// R0 not written before exit.
    UninitReturn,
}

impl VerifyError {
    pub fn new(pc: usize, kind: ErrorKind) -> Self {
        Self {
            pc,
            kind,
            source_loc: None,
        }
    }

    pub fn with_source(mut self, loc: Option<&SourceLoc>) -> Self {
        self.source_loc = loc.cloned();
        self
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref loc) = self.source_loc {
            write!(f, "{}:{}: ", loc.file, loc.line)?;
        }
        write!(f, "insn #{}: {}", self.pc, self.kind)
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::UninitStackRead { offset, width } => {
                write!(f, "read of {width}B from uninitialised stack [fp{offset:+}]")
            }
            ErrorKind::OutOfBoundsAccess { reg, ptr_kind, offset, width, region_size } => {
                write!(
                    f,
                    "{ptr_kind} access via {reg} at offset {offset} width {width} is out of bounds (region size {region_size})"
                )
            }
            ErrorKind::NullPointerDeref { reg, origin_pc, origin_loc } => {
                write!(f, "dereference of {reg} which may be null")?;
                if let Some(loc) = origin_loc {
                    write!(f, " (returned from helper at {}:{})", loc.file, loc.line)?;
                } else if let Some(pc) = origin_pc {
                    write!(f, " (returned from helper at insn #{pc})")?;
                }
                Ok(())
            }
            ErrorKind::InvalidPointerDeref { reg, actual } => {
                write!(f, "{reg} holds {actual}, not a dereferenceable pointer")
            }
            ErrorKind::UnknownHelper { id } => {
                write!(f, "call to unknown helper #{id}")
            }
            ErrorKind::InvalidHelperArg { helper, arg_index, expected, actual } => {
                write!(f, "{helper}(): arg {arg_index} must be {expected}, got {actual}")
            }
            ErrorKind::ComplexityExceeded { limit, visited } => {
                write!(f, "programme too complex: visited {visited} states, limit is {limit}")
            }
            ErrorKind::UnboundedLoop { target_pc } => {
                write!(f, "back-edge to insn #{target_pc} creates an unbounded loop")
            }
            ErrorKind::UninitRegRead { reg } => {
                write!(f, "read of {reg} before initialisation")
            }
            ErrorKind::InvalidPointerArith { reg, op } => {
                write!(f, "{op} on {reg} is not a valid pointer operation")
            }
            ErrorKind::DivByZero { divisor_reg } => {
                write!(f, "division by {divisor_reg} which may be zero")
            }
            ErrorKind::FallThrough => {
                write!(f, "programme does not terminate with an exit instruction")
            }
            ErrorKind::UnknownOpcode { raw } => {
                write!(f, "unknown opcode 0x{raw:02x}")
            }
            ErrorKind::InvalidReturnType { actual } => {
                write!(f, "r0 at exit holds {actual}, must be a scalar")
            }
            ErrorKind::ShiftOverflow { width, amount } => {
                write!(f, "shift by {amount} exceeds {width}-bit width")
            }
            ErrorKind::PtrLeak { reg, ptr_kind } => {
                write!(f, "{ptr_kind} pointer in {reg} would leak to userspace")
            }
            ErrorKind::UninitReturn => {
                write!(f, "r0 not written before exit")
            }
        }
    }
}

/// Format a list of verification errors into a diagnostic report using ariadne,
/// pointing at C source lines where possible.
pub fn format_errors(
    errors: &[VerifyError],
    source_locs: &[Option<SourceLoc>],
    c_sources: &std::collections::HashMap<String, String>,
) -> String {
    use ariadne::{CharSet, Config};

    if errors.is_empty() {
        return String::new();
    }

    let config = Config::default().with_char_set(CharSet::Unicode);
    let mut output = String::new();

    for err in errors {
        // Try to find the C source location for the error instruction
        let loc = err.source_loc.as_ref()
            .or_else(|| source_locs.get(err.pc).and_then(|l| l.as_ref()));

        if let Some(loc) = loc
            && let Some(source) = c_sources.get(&loc.path)
        {
            output.push_str(&format_error_with_source(err, loc, source, c_sources, config));
        } else {
            // No source -- plain text with as much context as we can give
            output.push_str(&format!("error[E{:04}]: {}\n", error_code(&err.kind), err.kind));
            output.push_str(&format!("  --> insn #{}\n", err.pc));
            if let Some(loc) = loc {
                output.push_str(&format!("  = source: {}:{}\n", loc.file, loc.line));
            }
            output.push('\n');
        }
    }

    output
}

/// Render a single error with ariadne source annotations.
///
/// Separated into its own function so all the owned Strings used as ariadne
/// file IDs live long enough (they must outlive the report).
fn format_error_with_source(
    err: &VerifyError,
    loc: &SourceLoc,
    source: &str,
    c_sources: &std::collections::HashMap<String, String>,
    config: ariadne::Config,
) -> String {
    use ariadne::{Color, Label, Report, ReportKind};

    let line_start = byte_offset_of_line(source, loc.line as usize);
    let line_text = source[line_start..].lines().next().unwrap_or("");
    let line_end = line_start + line_text.len();

    let file_id: String = loc.path.clone();
    // Clone for the origin label if needed.
    let origin_id: String;
    let origin_src: Option<&str>;
    let origin_range: std::ops::Range<usize>;

    let mut has_origin = false;

    if let ErrorKind::NullPointerDeref { origin_loc: Some(ref oloc), .. } = err.kind
        && let Some(osrc) = c_sources.get(&oloc.path)
    {
        origin_id = oloc.path.clone();
        let ostart = byte_offset_of_line(osrc, oloc.line as usize);
        let oline = osrc[ostart..].lines().next().unwrap_or("");
        origin_range = ostart..ostart + oline.len();
        origin_src = Some(osrc.as_str());
        has_origin = true;
    } else {
        origin_id = String::new();
        origin_range = 0..0;
        origin_src = None;
    }

    let mut builder = Report::build(ReportKind::Error, (file_id.clone(), line_start..line_end))
        .with_config(config)
        .with_message(format!("{}", err.kind));

    builder = builder.with_label(
        Label::new((file_id.clone(), line_start..line_end))
            .with_message(short_label(&err.kind))
            .with_color(Color::Red),
    );

    if has_origin {
        builder = builder.with_label(
            Label::new((origin_id.clone(), origin_range))
                .with_message("returns a possibly-null pointer")
                .with_color(Color::Yellow),
        );
    }

    builder = builder.with_note(format!("insn #{}", err.pc));

    let report = builder.finish();
    let mut buf = Vec::new();

    // Build source entries -- file_id is always present, origin_id only if used.
    let mut entries: Vec<(String, String)> = vec![
        (file_id, source.to_string()),
    ];
    if has_origin {
        entries.push((origin_id, origin_src.unwrap_or("").to_string()));
    }
    let cache = ariadne::sources(entries);
    let _ = report.write(cache, &mut buf);
    String::from_utf8(buf).unwrap_or_default()
}

/// Short label for ariadne annotations -- one line, no full sentences.
fn short_label(kind: &ErrorKind) -> String {
    match kind {
        ErrorKind::UninitStackRead { .. } => "uninitialised stack read".into(),
        ErrorKind::OutOfBoundsAccess { ptr_kind, .. } => format!("out-of-bounds {ptr_kind} access"),
        ErrorKind::NullPointerDeref { reg, .. } => format!("{reg} may be null here"),
        ErrorKind::InvalidPointerDeref { reg, actual } => format!("{reg} is {actual}"),
        ErrorKind::UnknownHelper { id } => format!("unknown helper #{id}"),
        ErrorKind::InvalidHelperArg { helper, arg_index, expected, .. } => {
            format!("{helper} arg{arg_index} needs {expected}")
        }
        ErrorKind::ComplexityExceeded { .. } => "complexity limit hit".into(),
        ErrorKind::UnboundedLoop { .. } => "unbounded loop".into(),
        ErrorKind::UninitRegRead { reg } => format!("{reg} uninitialised"),
        ErrorKind::InvalidPointerArith { op, .. } => format!("invalid: {op} on pointer"),
        ErrorKind::DivByZero { .. } => "divisor may be zero".into(),
        ErrorKind::FallThrough => "missing exit".into(),
        ErrorKind::UnknownOpcode { raw } => format!("unknown opcode 0x{raw:02x}"),
        ErrorKind::InvalidReturnType { actual } => format!("r0 is {actual}, not scalar"),
        ErrorKind::ShiftOverflow { amount, .. } => format!("shift by {amount} overflows"),
        ErrorKind::PtrLeak { ptr_kind, .. } => format!("{ptr_kind} pointer leaked"),
        ErrorKind::UninitReturn => "r0 not set".into(),
    }
}

/// Numeric error code for machine-parseable output.
fn error_code(kind: &ErrorKind) -> u16 {
    match kind {
        ErrorKind::UninitStackRead { .. } => 1,
        ErrorKind::OutOfBoundsAccess { .. } => 2,
        ErrorKind::NullPointerDeref { .. } => 3,
        ErrorKind::InvalidPointerDeref { .. } => 4,
        ErrorKind::UnknownHelper { .. } => 5,
        ErrorKind::InvalidHelperArg { .. } => 6,
        ErrorKind::ComplexityExceeded { .. } => 7,
        ErrorKind::UnboundedLoop { .. } => 8,
        ErrorKind::UninitRegRead { .. } => 9,
        ErrorKind::InvalidPointerArith { .. } => 10,
        ErrorKind::DivByZero { .. } => 11,
        ErrorKind::FallThrough => 12,
        ErrorKind::UnknownOpcode { .. } => 13,
        ErrorKind::InvalidReturnType { .. } => 14,
        ErrorKind::ShiftOverflow { .. } => 15,
        ErrorKind::PtrLeak { .. } => 16,
        ErrorKind::UninitReturn => 17,
    }
}

/// Compute byte offset of the start of a 1-based line number.
fn byte_offset_of_line(source: &str, line: usize) -> usize {
    source
        .lines()
        .take(line.saturating_sub(1))
        .map(|l| l.len() + 1)
        .sum()
}
