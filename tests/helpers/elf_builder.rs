use object::write::Object;
use object::{Architecture, BinaryFormat, Endianness, SectionFlags, SectionKind};

// BPF instruction opcode constants
pub const BPF_ALU64_REG_ADD: u8 = 0x0f;
pub const BPF_ALU64_IMM_ADD: u8 = 0x07;
pub const BPF_ALU64_REG_MOV: u8 = 0xbf;
pub const BPF_ALU64_IMM_MOV: u8 = 0xb7;
pub const BPF_ALU64_REG_SUB: u8 = 0x1f;
pub const BPF_ALU64_IMM_MUL: u8 = 0x27;
pub const BPF_EXIT: u8 = 0x95;

/// Encode a single BPF instruction as a u64 in little-endian format.
///
/// Layout (8 bytes LE):
///   byte 0: opcode
///   byte 1: dst_reg (low nibble) | src_reg (high nibble)
///   bytes 2-3: offset (i16 LE)
///   bytes 4-7: imm (i32 LE)
pub fn bpf_insn(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> u64 {
    let mut bytes = [0u8; 8];
    bytes[0] = opcode;
    bytes[1] = (src << 4) | (dst & 0x0f);
    bytes[2..4].copy_from_slice(&offset.to_le_bytes());
    bytes[4..8].copy_from_slice(&imm.to_le_bytes());
    u64::from_le_bytes(bytes)
}

/// Build a minimal BPF ELF binary with a single text section containing the
/// given instructions.
pub fn build_bpf_elf(section_name: &str, instructions: &[u64]) -> Vec<u8> {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);
    let section_id = obj.add_section(
        Vec::new(),
        section_name.as_bytes().to_vec(),
        SectionKind::Text,
    );

    // Flatten instructions into a byte buffer
    let mut data = Vec::with_capacity(instructions.len() * 8);
    for insn in instructions {
        data.extend_from_slice(&insn.to_le_bytes());
    }

    obj.section_mut(section_id).set_data(data, 8);
    obj.section_mut(section_id).flags = SectionFlags::Elf {
        sh_flags: object::elf::SHF_ALLOC as u64 | object::elf::SHF_EXECINSTR as u64,
    };

    let mut buf = Vec::new();
    obj.emit(&mut buf).expect("failed to emit BPF ELF");
    buf
}
