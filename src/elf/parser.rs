use object::read::ObjectSection;
use object::{File, Object, SectionKind};
use addr2line::gimli;

use crate::bpf::instruction::{BpfInsn, Opcode};

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("ELF parse error: {0}")]
    Elf(#[from] object::read::Error),

    #[error("no BPF program sections found")]
    NoProgramSections,

    #[error("section '{0}' data is not aligned to 8 bytes")]
    UnalignedSection(String),
}

#[derive(Debug, Clone)]
pub struct SourceLoc {
    pub file: String,
    pub line: u32,
}

#[derive(Debug)]
pub struct BpfProgram {
    pub section_name: String,
    pub instructions: Vec<BpfInsn>,
    pub source_locs: Vec<Option<SourceLoc>>,
}

#[derive(Debug)]
pub struct BpfObject {
    pub programs: Vec<BpfProgram>,
}

/// Parse an ELF binary and extract BPF programs from text sections.
///
/// Iterates over all sections, selecting those that are `Text`, have a
/// non-empty name, and whose name doesn't start with '.'. Each qualifying
/// section's data is decoded as a sequence of 8-byte little-endian BPF
/// instructions.
pub fn parse_elf(data: &[u8]) -> Result<BpfObject, ParseError> {
    let file = File::parse(data)?;

    let addr2line_ctx = build_addr2line_context(&file);

    let mut programs = Vec::new();

    for section in file.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }

        let name = match section.name() {
            Ok(n) if !n.is_empty() && !n.starts_with('.') => n.to_string(),
            _ => continue,
        };

        let section_data = section.data()?;

        if section_data.len() % 8 != 0 {
            return Err(ParseError::UnalignedSection(name));
        }

        let section_addr = section.address();
        let mut instructions = Vec::new();
        let mut source_locs = Vec::new();
        let mut byte_offset: u64 = 0;
        let mut chunks = section_data.chunks_exact(8);
        while let Some(chunk) = chunks.next() {
            let raw = u64::from_le_bytes(chunk.try_into().expect("chunks_exact(8) guarantees 8 bytes"));
            let insn_addr = section_addr + byte_offset;
            if let Some(mut insn) = BpfInsn::decode(raw) {
                if insn.opcode == Opcode::LdImm64 && let Some(next_chunk) = chunks.next() {
                    let raw2 = u64::from_le_bytes(next_chunk.try_into().expect("chunks_exact(8) guarantees 8 bytes"));
                    let high = i32::from_le_bytes(raw2.to_le_bytes()[4..8].try_into().expect("4-byte slice"));
                    insn.imm64 = Some((insn.imm as u32 as u64) | ((high as u32 as u64) << 32));
                    byte_offset += 8;
                }
                instructions.push(insn);
                source_locs.push(lookup_source_loc(&addr2line_ctx, insn_addr));
            }
            byte_offset += 8;
        }

        programs.push(BpfProgram {
            section_name: name,
            instructions,
            source_locs,
        });
    }

    if programs.is_empty() {
        return Err(ParseError::NoProgramSections);
    }

    Ok(BpfObject { programs })
}

type Addr2LineCtx<'a> = addr2line::Context<gimli::EndianSlice<'a, gimli::LittleEndian>>;

fn build_addr2line_context<'a>(file: &'a File<'a>) -> Option<Addr2LineCtx<'a>> {
    let load_section = |id: gimli::SectionId| -> Result<gimli::EndianSlice<gimli::LittleEndian>, gimli::Error> {
        use object::ObjectSection;
        let data = file
            .section_by_name(id.name())
            .and_then(|s| s.data().ok())
            .unwrap_or(&[]);
        Ok(gimli::EndianSlice::new(data, gimli::LittleEndian))
    };
    let dwarf = gimli::Dwarf::load(&load_section).ok()?;
    addr2line::Context::from_dwarf(dwarf).ok()
}

fn lookup_source_loc(ctx: &Option<Addr2LineCtx>, addr: u64) -> Option<SourceLoc> {
    let ctx = ctx.as_ref()?;
    let loc = ctx.find_location(addr).ok()??;
    let file = loc.file?;
    let line = loc.line?;
    let basename = file.rsplit('/').next().unwrap_or(file);
    Some(SourceLoc {
        file: basename.to_string(),
        line,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::instruction::Opcode;
    use object::write::Object;
    use object::{Architecture, BinaryFormat, Endianness, SectionFlags};

    /// Encode a BPF instruction into its 64-bit little-endian representation.
    fn encode_insn(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> u64 {
        let mut bytes = [0u8; 8];
        bytes[0] = opcode;
        bytes[1] = (src << 4) | (dst & 0x0f);
        bytes[2..4].copy_from_slice(&offset.to_le_bytes());
        bytes[4..8].copy_from_slice(&imm.to_le_bytes());
        u64::from_le_bytes(bytes)
    }

    /// Build a minimal ELF with one text section containing the given
    /// instruction data.
    fn build_test_elf(section_name: &str, insn_data: &[u8]) -> Vec<u8> {
        let mut obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);
        let section_id = obj.add_section(
            Vec::new(),
            section_name.as_bytes().to_vec(),
            SectionKind::Text,
        );
        obj.section_mut(section_id).set_data(insn_data.to_vec(), 8);
        obj.section_mut(section_id).flags = SectionFlags::Elf {
            sh_flags: object::elf::SHF_ALLOC as u64 | object::elf::SHF_EXECINSTR as u64,
        };
        let mut buf = Vec::new();
        obj.emit(&mut buf).expect("failed to emit test ELF");
        buf
    }

    #[test]
    fn parse_simple_alu_program() {
        // mov r0, r1 (0xbf), add r0, r2 (0x0f), exit (0x95)
        let mov = encode_insn(0xbf, 0, 1, 0, 0);
        let add = encode_insn(0x0f, 0, 2, 0, 0);
        let exit = encode_insn(0x95, 0, 0, 0, 0);

        let mut insn_bytes = Vec::new();
        insn_bytes.extend_from_slice(&mov.to_le_bytes());
        insn_bytes.extend_from_slice(&add.to_le_bytes());
        insn_bytes.extend_from_slice(&exit.to_le_bytes());

        let elf_data = build_test_elf("test_prog", &insn_bytes);
        let result = parse_elf(&elf_data).expect("parse_elf should succeed");

        assert_eq!(result.programs.len(), 1);
        let prog = &result.programs[0];
        assert_eq!(prog.section_name, "test_prog");
        assert_eq!(prog.instructions.len(), 3);

        assert!(matches!(
            prog.instructions[0].opcode,
            Opcode::Alu64(crate::bpf::instruction::AluOp::Mov, crate::bpf::instruction::Source::Reg)
        ));
        assert!(matches!(
            prog.instructions[1].opcode,
            Opcode::Alu64(crate::bpf::instruction::AluOp::Add, crate::bpf::instruction::Source::Reg)
        ));
        assert!(matches!(prog.instructions[2].opcode, Opcode::Exit));
    }

    #[test]
    fn parse_empty_elf_fails() {
        let obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);
        let mut elf_data = Vec::new();
        obj.emit(&mut elf_data).expect("failed to emit empty ELF");

        let result = parse_elf(&elf_data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ParseError::NoProgramSections));
    }
}
