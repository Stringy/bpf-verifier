/// BPF register identifiers (R0 through R10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reg {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
}

impl Reg {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Reg::R0),
            1 => Some(Reg::R1),
            2 => Some(Reg::R2),
            3 => Some(Reg::R3),
            4 => Some(Reg::R4),
            5 => Some(Reg::R5),
            6 => Some(Reg::R6),
            7 => Some(Reg::R7),
            8 => Some(Reg::R8),
            9 => Some(Reg::R9),
            10 => Some(Reg::R10),
            _ => None,
        }
    }

    pub fn index(&self) -> u8 {
        match self {
            Reg::R0 => 0,
            Reg::R1 => 1,
            Reg::R2 => 2,
            Reg::R3 => 3,
            Reg::R4 => 4,
            Reg::R5 => 5,
            Reg::R6 => 6,
            Reg::R7 => 7,
            Reg::R8 => 8,
            Reg::R9 => 9,
            Reg::R10 => 10,
        }
    }
}

impl std::fmt::Display for Reg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "r{}", self.index())
    }
}

/// ALU instruction source operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Imm,
    Reg,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Imm => write!(f, "IMM"),
            Source::Reg => write!(f, "REG"),
        }
    }
}

/// ALU operation codes, decoded from the upper nibble of the opcode byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AluOp {
    Add,
    Sub,
    Mul,
    Div,
    Or,
    And,
    Lsh,
    Rsh,
    Neg,
    Mod,
    Xor,
    Mov,
    Arsh,
}

impl AluOp {
    /// Decode from the upper nibble (bits [7:4]) of the opcode byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x0 => Some(AluOp::Add),
            0x1 => Some(AluOp::Sub),
            0x2 => Some(AluOp::Mul),
            0x3 => Some(AluOp::Div),
            0x4 => Some(AluOp::Or),
            0x5 => Some(AluOp::And),
            0x6 => Some(AluOp::Lsh),
            0x7 => Some(AluOp::Rsh),
            0x8 => Some(AluOp::Neg),
            0x9 => Some(AluOp::Mod),
            0xa => Some(AluOp::Xor),
            0xb => Some(AluOp::Mov),
            0xc => Some(AluOp::Arsh),
            _ => None,
        }
    }
}

impl std::fmt::Display for AluOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AluOp::Add => "ADD",
            AluOp::Sub => "SUB",
            AluOp::Mul => "MUL",
            AluOp::Div => "DIV",
            AluOp::Or => "OR",
            AluOp::And => "AND",
            AluOp::Lsh => "LSH",
            AluOp::Rsh => "RSH",
            AluOp::Neg => "NEG",
            AluOp::Mod => "MOD",
            AluOp::Xor => "XOR",
            AluOp::Mov => "MOV",
            AluOp::Arsh => "ARSH",
        };
        write!(f, "{s}")
    }
}

/// Memory access width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemWidth {
    B,
    H,
    W,
    DW,
}

impl MemWidth {
    fn from_size_bits(bits: u8) -> Option<Self> {
        match bits {
            0x00 => Some(MemWidth::W),
            0x01 => Some(MemWidth::H),
            0x02 => Some(MemWidth::B),
            0x03 => Some(MemWidth::DW),
            _ => None,
        }
    }
}

impl std::fmt::Display for MemWidth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MemWidth::B => "W8",
            MemWidth::H => "W16",
            MemWidth::W => "W32",
            MemWidth::DW => "W64",
        };
        write!(f, "{s}")
    }
}

/// Jump comparison operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JmpOp {
    Ja,
    Jeq, Jgt, Jge, Jset,
    Jne, Jlt, Jle,
    Jsgt, Jsge, Jslt, Jsle,
}

impl JmpOp {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(JmpOp::Ja),
            0x01 => Some(JmpOp::Jeq),
            0x02 => Some(JmpOp::Jgt),
            0x03 => Some(JmpOp::Jge),
            0x04 => Some(JmpOp::Jset),
            0x05 => Some(JmpOp::Jne),
            0x06 => Some(JmpOp::Jsgt),
            0x07 => Some(JmpOp::Jsge),
            0x0a => Some(JmpOp::Jlt),
            0x0b => Some(JmpOp::Jle),
            0x0c => Some(JmpOp::Jslt),
            0x0d => Some(JmpOp::Jsle),
            _ => None,
        }
    }
}

impl std::fmt::Display for JmpOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            JmpOp::Ja => "JA",
            JmpOp::Jeq => "JEQ",
            JmpOp::Jgt => "JGT",
            JmpOp::Jge => "JGE",
            JmpOp::Jset => "JSET",
            JmpOp::Jne => "JNE",
            JmpOp::Jlt => "JLT",
            JmpOp::Jle => "JLE",
            JmpOp::Jsgt => "JSGT",
            JmpOp::Jsge => "JSGE",
            JmpOp::Jslt => "JSLT",
            JmpOp::Jsle => "JSLE",
        };
        write!(f, "{s}")
    }
}

/// Decoded BPF opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Alu64(AluOp, Source),
    Alu32(AluOp, Source),
    Ldx(MemWidth),
    Stx(MemWidth),
    St(MemWidth),
    Jmp64(JmpOp, Source),
    Jmp32(JmpOp, Source),
    JmpJa,
    Exit,
    Unknown(u8),
}

impl Opcode {
    /// Decode from the raw opcode byte.
    ///
    /// Layout: class = bits [2:0], source flag = bit 3, operation = bits [7:4].
    /// Class 0x07 = ALU64, 0x04 = ALU32. Byte 0x95 = EXIT.
    pub fn decode(raw: u8) -> Self {
        if raw == 0x95 {
            return Opcode::Exit;
        }

        let class = raw & 0x07;
        let src_flag = raw & 0x08;
        let op_nibble = (raw >> 4) & 0x0f;

        let source = if src_flag != 0 {
            Source::Reg
        } else {
            Source::Imm
        };

        let size_bits = (raw >> 3) & 0x03;

        match class {
            0x07 => match AluOp::from_u8(op_nibble) {
                Some(op) => Opcode::Alu64(op, source),
                None => Opcode::Unknown(raw),
            },
            0x04 => match AluOp::from_u8(op_nibble) {
                Some(op) => Opcode::Alu32(op, source),
                None => Opcode::Unknown(raw),
            },
            0x01 => match MemWidth::from_size_bits(size_bits) {
                Some(w) => Opcode::Ldx(w),
                None => Opcode::Unknown(raw),
            },
            0x02 => match MemWidth::from_size_bits(size_bits) {
                Some(w) => Opcode::St(w),
                None => Opcode::Unknown(raw),
            },
            0x03 => match MemWidth::from_size_bits(size_bits) {
                Some(w) => Opcode::Stx(w),
                None => Opcode::Unknown(raw),
            },
            // JMP class (64-bit): op 0x00 = JA (unconditional), 0x09 = EXIT (handled above)
            0x05 => {
                if op_nibble == 0x00 {
                    Opcode::JmpJa
                } else {
                    match JmpOp::from_u8(op_nibble) {
                        Some(op) => Opcode::Jmp64(op, source),
                        None => Opcode::Unknown(raw),
                    }
                }
            }
            // JMP32 class (32-bit comparisons)
            0x06 => match JmpOp::from_u8(op_nibble) {
                Some(op) => Opcode::Jmp32(op, source),
                None => Opcode::Unknown(raw),
            },
            _ => Opcode::Unknown(raw),
        }
    }
}

/// A decoded BPF instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInsn {
    pub opcode: Opcode,
    pub dst: Reg,
    pub src: Reg,
    pub offset: i16,
    pub imm: i32,
}

impl BpfInsn {
    /// Decode a BPF instruction from a 64-bit little-endian value.
    ///
    /// Encoding (8 bytes LE):
    ///   byte 0: opcode
    ///   byte 1: dst_reg (low nibble) | src_reg (high nibble)
    ///   bytes 2-3: offset (i16 LE)
    ///   bytes 4-7: imm (i32 LE)
    pub fn decode(raw: u64) -> Option<Self> {
        let bytes = raw.to_le_bytes();

        let opcode = Opcode::decode(bytes[0]);
        let dst = Reg::from_u8(bytes[1] & 0x0f)?;
        let src = Reg::from_u8((bytes[1] >> 4) & 0x0f)?;
        let offset = i16::from_le_bytes([bytes[2], bytes[3]]);
        let imm = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        Some(BpfInsn {
            opcode,
            dst,
            src,
            offset,
            imm,
        })
    }

    /// Emit F* constructor syntax for this instruction.
    pub fn to_fstar(&self) -> String {
        match self.opcode {
            Opcode::Alu64(op, Source::Reg) => {
                format!("BPF_ALU64_REG {} {} {}", op, self.dst, self.src)
            }
            Opcode::Alu64(op, Source::Imm) => {
                format!("BPF_ALU64_IMM {} {} {}l", op, self.dst, self.imm)
            }
            Opcode::Alu32(op, Source::Reg) => {
                format!("BPF_ALU32_REG {} {} {}", op, self.dst, self.src)
            }
            Opcode::Alu32(op, Source::Imm) => {
                format!("BPF_ALU32_IMM {} {} {}l", op, self.dst, self.imm)
            }
            Opcode::Ldx(w) => {
                format!("BPF_LDX {} {} {} ({}l)", w, self.dst, self.src, self.offset)
            }
            Opcode::Stx(w) => {
                format!("BPF_STX {} {} {} ({}l)", w, self.dst, self.src, self.offset)
            }
            Opcode::St(w) => {
                format!("BPF_ST {} {} ({}l) ({}l)", w, self.dst, self.offset, self.imm)
            }
            Opcode::Jmp64(op, Source::Reg) => {
                format!("BPF_JMP64_REG {} {} {} {}", op, self.dst, self.src, self.offset)
            }
            Opcode::Jmp64(op, Source::Imm) => {
                format!("BPF_JMP64_IMM {} {} ({}l) {}", op, self.dst, self.imm, self.offset)
            }
            Opcode::Jmp32(op, Source::Reg) => {
                format!("BPF_JMP32_REG {} {} {} {}", op, self.dst, self.src, self.offset)
            }
            Opcode::Jmp32(op, Source::Imm) => {
                format!("BPF_JMP32_IMM {} {} ({}l) {}", op, self.dst, self.imm, self.offset)
            }
            Opcode::JmpJa => {
                format!("BPF_JMP_JA {}", self.offset)
            }
            Opcode::Exit => "BPF_EXIT".to_string(),
            Opcode::Unknown(raw) => format!("BPF_UNKNOWN 0x{:02x}", raw),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_alu64_add_reg() {
        // 0x0f = class 0x07 (ALU64) | source 0x08 (Reg) | op 0x0 (Add)
        // dst_reg:src_reg byte = 0x10 → dst=R0, src=R1
        let raw: u64 = 0x0000_0000_0000_100f;
        let insn = BpfInsn::decode(raw).unwrap();
        assert_eq!(insn.opcode, Opcode::Alu64(AluOp::Add, Source::Reg));
        assert_eq!(insn.dst, Reg::R0);
        assert_eq!(insn.src, Reg::R1);
        assert_eq!(insn.offset, 0);
        assert_eq!(insn.imm, 0);
        assert_eq!(insn.to_fstar(), "BPF_ALU64_REG ADD r0 r1");
    }

    #[test]
    fn decode_alu64_add_imm() {
        // 0x07 = class 0x07 (ALU64) | source 0x00 (Imm) | op 0x0 (Add)
        // dst_reg:src_reg byte = 0x00 → dst=R0, src=R0
        // imm = 42 = 0x2a
        let raw: u64 = 0x0000_002a_0000_0007;
        let insn = BpfInsn::decode(raw).unwrap();
        assert_eq!(insn.opcode, Opcode::Alu64(AluOp::Add, Source::Imm));
        assert_eq!(insn.dst, Reg::R0);
        assert_eq!(insn.imm, 42);
        assert_eq!(insn.to_fstar(), "BPF_ALU64_IMM ADD r0 42l");
    }

    #[test]
    fn decode_alu32_add_reg() {
        // 0x0c = class 0x04 (ALU32) | source 0x08 (Reg) | op 0x0 (Add)
        // dst_reg:src_reg byte = 0x32 → dst=R2, src=R3
        let raw: u64 = 0x0000_0000_0000_320c;
        let insn = BpfInsn::decode(raw).unwrap();
        assert_eq!(insn.opcode, Opcode::Alu32(AluOp::Add, Source::Reg));
        assert_eq!(insn.dst, Reg::R2);
        assert_eq!(insn.src, Reg::R3);
        assert_eq!(insn.to_fstar(), "BPF_ALU32_REG ADD r2 r3");
    }

    #[test]
    fn decode_exit() {
        let raw: u64 = 0x0000_0000_0000_0095;
        let insn = BpfInsn::decode(raw).unwrap();
        assert_eq!(insn.opcode, Opcode::Exit);
        assert_eq!(insn.to_fstar(), "BPF_EXIT");
    }

    #[test]
    fn decode_mov64_imm() {
        // 0xb7 = class 0x07 (ALU64) | source 0x00 (Imm) | op 0xb (Mov)
        // dst_reg:src_reg byte = 0x00 → dst=R0, src=R0
        // imm = 0
        let raw: u64 = 0x0000_0000_0000_00b7;
        let insn = BpfInsn::decode(raw).unwrap();
        assert_eq!(insn.opcode, Opcode::Alu64(AluOp::Mov, Source::Imm));
        assert_eq!(insn.dst, Reg::R0);
        assert_eq!(insn.imm, 0);
        assert_eq!(insn.to_fstar(), "BPF_ALU64_IMM MOV r0 0l");
    }
}
