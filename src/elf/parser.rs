use object::read::ObjectSection;
use object::{File, Object, ObjectSymbol, SectionKind};
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
    pub path: String,
    pub line: u32,
}

/// The target of an LD_IMM64 relocation.
#[derive(Debug, Clone)]
pub enum RelocTarget {
    /// References a BPF map (map fd will be patched at load time).
    Map { name: String },
    /// References a global variable or rodata section.
    Data { name: String },
    /// CO-RE field byte offset -- the immediate will be patched to the byte
    /// offset of a kernel struct field. Used with bpf_probe_read_kernel.
    CoreFieldOffset,
}

#[derive(Debug)]
pub struct BpfProgram {
    pub section_name: String,
    pub instructions: Vec<BpfInsn>,
    pub source_locs: Vec<Option<SourceLoc>>,
    /// Relocations for LD_IMM64 instructions, keyed by collapsed instruction index.
    pub relocations: std::collections::HashMap<usize, RelocTarget>,
}

#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub offset: u64,
    pub byte_size: u64,
}

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: String,
    pub is_user_defined: bool,
    pub fields: Vec<StructField>,
}

#[derive(Debug)]
pub struct BpfObject {
    pub programs: Vec<BpfProgram>,
    pub structs: Vec<StructDef>,
}

/// Parse an ELF binary and extract BPF programs from text sections.
///
/// Iterates over all sections, selecting those that are `Text`, have a
/// non-empty name, and whose name doesn't start with '.'. Each qualifying
/// section's data is decoded as a sequence of 8-byte little-endian BPF
/// instructions.
pub fn parse_elf(data: &[u8]) -> Result<BpfObject, ParseError> {
    let file = File::parse(data)?;

    let dwarf = build_dwarf(&file);
    let structs = dwarf.as_ref().map(extract_structs).unwrap_or_default();
    let addr2line_ctx = dwarf.and_then(|d| addr2line::Context::from_dwarf(d).ok());

    // Parse BTF.ext CO-RE relocations. These tell us which LD_IMM64
    // instructions will be patched with kernel struct field offsets.
    let core_relos = parse_btf_ext_core_relos(&file);

    // Collect map section names so we can distinguish map relocations from
    // data/rodata relocations. Map sections have names like "maps" or are
    // in a ".maps" section, but the most reliable signal is the symbol
    // section index pointing to a maps section. We'll use a simpler heuristic:
    // known BPF map names from the symbol table.
    let map_section_indices: std::collections::HashSet<object::SectionIndex> = file
        .sections()
        .filter(|s| {
            s.name().is_ok_and(|n| n == ".maps" || n == "maps")
        })
        .map(|s| s.index())
        .collect();

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

        let _section_idx = section.index();
        let section_addr = section.address();

        // Parse relocations for this section.
        // BPF relocation sections are named ".rel<section_name>" (REL, not RELA).
        let mut reloc_offsets = std::collections::HashMap::<u64, RelocTarget>::new();
        for rel_section in file.sections() {
            let rel_name = rel_section.name().unwrap_or("");
            // Match ".rel" + section name (e.g. ".rellsm/file_open" for "lsm/file_open")
            // or ".rel." + section name.
            let expected = format!(".rel{}", name);
            if rel_name != expected && rel_name != format!(".rel.{}", name) {
                continue;
            }
            if let Ok(rel_data) = rel_section.data() {
                // Parse REL entries (16 bytes each: 8-byte offset + 8-byte info).
                for entry in rel_data.chunks_exact(16) {
                    let offset = u64::from_le_bytes(entry[0..8].try_into().unwrap());
                    let info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
                    let sym_idx = (info >> 32) as u32;
                    let rel_type = info as u32;
                    // R_BPF_64_64 = 1
                    if rel_type != 1 {
                        continue;
                    }
                    // Look up the symbol name.
                    if let Some(sym) = file.symbol_by_index(object::SymbolIndex(sym_idx as usize)).ok() {
                        let sym_name = sym.name().unwrap_or("").to_string();
                        let sym_section = sym.section_index();
                        let target = if sym_section.is_some_and(|si| map_section_indices.contains(&si)) {
                            RelocTarget::Map { name: sym_name }
                        } else {
                            RelocTarget::Data { name: sym_name }
                        };
                        reloc_offsets.insert(offset, target);
                    }
                }
            }
        }

        // Get CO-RE relocations for this section.
        let section_core_relos = core_relos.get(name.as_str());

        let mut instructions = Vec::new();
        let mut source_locs = Vec::new();
        let mut relocations = std::collections::HashMap::new();
        let mut byte_offset: u64 = 0;
        let mut insn_idx: usize = 0;
        let mut chunks = section_data.chunks_exact(8);
        while let Some(chunk) = chunks.next() {
            let raw = u64::from_le_bytes(chunk.try_into().expect("chunks_exact(8) guarantees 8 bytes"));
            let insn_addr = section_addr + byte_offset;
            if let Some(mut insn) = BpfInsn::decode(raw) {
                if insn.opcode == Opcode::LdImm64 && let Some(next_chunk) = chunks.next() {
                    let raw2 = u64::from_le_bytes(next_chunk.try_into().expect("chunks_exact(8) guarantees 8 bytes"));
                    let high = i32::from_le_bytes(raw2.to_le_bytes()[4..8].try_into().expect("4-byte slice"));
                    insn.imm64 = Some((insn.imm as u32 as u64) | ((high as u32 as u64) << 32));
                    // Check if this LD_IMM64 has an ELF relocation.
                    if let Some(target) = reloc_offsets.remove(&byte_offset) {
                        relocations.insert(insn_idx, target);
                    }
                    // Check if this LD_IMM64 has a CO-RE relocation.
                    else if section_core_relos.is_some_and(|r| r.contains(&(byte_offset as u32))) {
                        relocations.insert(insn_idx, RelocTarget::CoreFieldOffset);
                    }
                    byte_offset += 8;
                }
                instructions.push(insn);
                source_locs.push(lookup_source_loc(&addr2line_ctx, insn_addr));
                insn_idx += 1;
            }
            byte_offset += 8;
        }

        programs.push(BpfProgram {
            section_name: name,
            instructions,
            source_locs,
            relocations,
        });
    }

    if programs.is_empty() {
        return Err(ParseError::NoProgramSections);
    }

    Ok(BpfObject { programs, structs })
}

/// Parse CO-RE relocations from the .BTF.ext section.
///
/// Returns a map from section name to a set of instruction byte offsets
/// that have FIELD_BYTE_OFFSET CO-RE relocations (kind 0). These are
/// instructions whose immediate value will be patched to a kernel struct
/// field offset at load time.
fn parse_btf_ext_core_relos(file: &File) -> std::collections::HashMap<String, std::collections::HashSet<u32>> {
    let mut result = std::collections::HashMap::new();

    // Find .BTF and .BTF.ext sections.
    let btf_data = file.sections()
        .find(|s| s.name().is_ok_and(|n| n == ".BTF"))
        .and_then(|s| s.data().ok());
    let btf_ext_data = file.sections()
        .find(|s| s.name().is_ok_and(|n| n == ".BTF.ext"))
        .and_then(|s| s.data().ok());

    let (Some(btf), Some(ext)) = (btf_data, btf_ext_data) else {
        return result;
    };

    // Parse BTF header to get the string table.
    if btf.len() < 24 {
        return result;
    }
    let btf_hdr_len = u32::from_le_bytes(btf[4..8].try_into().unwrap()) as usize;
    let btf_str_off = u32::from_le_bytes(btf[16..20].try_into().unwrap()) as usize;
    let btf_str_len = u32::from_le_bytes(btf[20..24].try_into().unwrap()) as usize;
    let str_start = btf_hdr_len + btf_str_off;
    if str_start + btf_str_len > btf.len() {
        return result;
    }
    let strtab = &btf[str_start..str_start + btf_str_len];

    let btf_str = |off: u32| -> &str {
        let start = off as usize;
        if start >= strtab.len() {
            return "";
        }
        let end = strtab[start..].iter().position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(strtab.len());
        std::str::from_utf8(&strtab[start..end]).unwrap_or("")
    };

    // Parse BTF.ext header.
    if ext.len() < 32 {
        return result;
    }
    let ext_hdr_len = u32::from_le_bytes(ext[4..8].try_into().unwrap()) as usize;
    // core_relo_off and core_relo_len are at bytes 24-31 in the header.
    if ext_hdr_len < 32 {
        return result; // no CO-RE relo section in this BTF.ext version
    }
    let core_relo_off = u32::from_le_bytes(ext[24..28].try_into().unwrap()) as usize;
    let core_relo_len = u32::from_le_bytes(ext[28..32].try_into().unwrap()) as usize;

    if core_relo_len == 0 {
        return result;
    }

    let relo_start = ext_hdr_len + core_relo_off;
    if relo_start + core_relo_len > ext.len() || core_relo_len < 4 {
        return result;
    }

    // First u32 is the record size.
    let rec_size = u32::from_le_bytes(ext[relo_start..relo_start + 4].try_into().unwrap()) as usize;
    if rec_size < 16 {
        return result; // records must be at least 16 bytes
    }

    let mut pos = relo_start + 4;
    let end = relo_start + core_relo_len;

    while pos + 8 <= end {
        let sec_name_off = u32::from_le_bytes(ext[pos..pos + 4].try_into().unwrap());
        let num_info = u32::from_le_bytes(ext[pos + 4..pos + 8].try_into().unwrap()) as usize;
        pos += 8;

        let sec_name = btf_str(sec_name_off).to_string();

        for i in 0..num_info {
            let rec_pos = pos + i * rec_size;
            if rec_pos + 16 > end {
                break;
            }
            let insn_off = u32::from_le_bytes(ext[rec_pos..rec_pos + 4].try_into().unwrap());
            // type_id at rec_pos+4, access_str_off at rec_pos+8
            let kind = u32::from_le_bytes(ext[rec_pos + 12..rec_pos + 16].try_into().unwrap());

            // FIELD_BYTE_OFFSET = 0
            if kind == 0 {
                result.entry(sec_name.clone())
                    .or_insert_with(std::collections::HashSet::new)
                    .insert(insn_off);
            }
        }

        pos += num_info * rec_size;
    }

    result
}

type GimliDwarf<'a> = gimli::Dwarf<gimli::EndianSlice<'a, gimli::LittleEndian>>;
type Addr2LineCtx<'a> = addr2line::Context<gimli::EndianSlice<'a, gimli::LittleEndian>>;

fn build_dwarf<'a>(file: &'a File<'a>) -> Option<GimliDwarf<'a>> {
    let load_section = |id: gimli::SectionId| -> Result<gimli::EndianSlice<gimli::LittleEndian>, gimli::Error> {
        use object::ObjectSection;
        let data = file
            .section_by_name(id.name())
            .and_then(|s| s.data().ok())
            .unwrap_or(&[]);
        Ok(gimli::EndianSlice::new(data, gimli::LittleEndian))
    };
    gimli::Dwarf::load(&load_section).ok()
}

fn attr_to_string(dwarf: &GimliDwarf<'_>, unit: &gimli::Unit<gimli::EndianSlice<'_, gimli::LittleEndian>>, val: gimli::AttributeValue<gimli::EndianSlice<'_, gimli::LittleEndian>>) -> Option<String> {
    let s = dwarf.attr_string(unit, val).ok()?;
    Some(s.to_string_lossy().into_owned())
}

fn extract_structs(dwarf: &GimliDwarf<'_>) -> Vec<StructDef> {
    let mut result = Vec::new();
    let mut type_sizes: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
    let mut type_refs: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();

    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else { continue };
        let mut cursor = unit.entries();
        while let Ok(Some(entry)) = cursor.next_dfs() {
            let offset = entry.offset().0;
            if let Some(sz) = entry.attr_value(gimli::DW_AT_byte_size)
                .and_then(|v| v.udata_value())
            {
                type_sizes.insert(offset, sz);
            }
            if let Some(gimli::AttributeValue::UnitRef(target)) = entry.attr_value(gimli::DW_AT_type) {
                type_refs.insert(offset, target.0);
            }
        }
    }

    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else { continue };
        let mut cursor = unit.entries();

        let mut current_struct: Option<(String, bool)> = None;
        let mut current_fields: Vec<StructField> = Vec::new();

        while let Ok(Some(entry)) = cursor.next_dfs() {
            match entry.tag() {
                gimli::DW_TAG_structure_type => {
                    if let Some((name, is_user)) = current_struct.take() {
                        if !current_fields.is_empty() {
                            result.push(StructDef {
                                name,
                                is_user_defined: is_user,
                                fields: std::mem::take(&mut current_fields),
                            });
                        }
                    }
                    current_fields.clear();
                    if let Some(name) = entry.attr_value(gimli::DW_AT_name)
                        .and_then(|v| attr_to_string(dwarf, &unit, v))
                    {
                        let decl_file = entry.attr_value(gimli::DW_AT_decl_file);
                        let is_user = decl_file
                            .map(|fv| match fv {
                                gimli::AttributeValue::FileIndex(i) => i == 0,
                                other => other.udata_value() == Some(0),
                            })
                            .unwrap_or(false);
                        current_struct = Some((name, is_user));
                    }
                }
                gimli::DW_TAG_member if current_struct.is_some() => {
                    if let Some((_, ref mut is_user)) = current_struct {
                        if !*is_user {
                            if let Some(fv) = entry.attr_value(gimli::DW_AT_decl_file) {
                                let idx = match fv {
                                    gimli::AttributeValue::FileIndex(i) => Some(i),
                                    other => other.udata_value(),
                                };
                                if idx == Some(0) {
                                    *is_user = true;
                                }
                            }
                        }
                    }
                    let field_name = entry.attr_value(gimli::DW_AT_name)
                        .and_then(|v| attr_to_string(dwarf, &unit, v));
                    let field_offset = entry.attr_value(gimli::DW_AT_data_member_location)
                        .and_then(|v| v.udata_value());
                    // Chase typedef/const/volatile chains to find the
                    // underlying type's byte_size. Depth-limited to 10 to
                    // guard against circular references in malformed DWARF.
                    let byte_size = entry.attr_value(gimli::DW_AT_type).and_then(|v| {
                        let mut cur = match v {
                            gimli::AttributeValue::UnitRef(o) => o.0,
                            _ => return None,
                        };
                        for _ in 0..10 {
                            if let Some(&sz) = type_sizes.get(&cur) {
                                return Some(sz);
                            }
                            match type_refs.get(&cur) {
                                Some(&next) => cur = next,
                                None => return None,
                            }
                        }
                        None
                    });
                    if let (Some(name), Some(off), Some(size)) = (field_name, field_offset, byte_size)
                        && matches!(size, 1 | 2 | 4 | 8)
                    {
                        current_fields.push(StructField { name, offset: off, byte_size: size });
                    }
                }
                _ => {
                    if current_struct.is_some() && entry.tag() != gimli::DW_TAG_member {
                        if let Some((name, is_user)) = current_struct.take() {
                            if !current_fields.is_empty() {
                                result.push(StructDef {
                                    name,
                                    is_user_defined: is_user,
                                    fields: std::mem::take(&mut current_fields),
                                });
                            }
                        }
                    }
                }
            }
        }
        if let Some((name, is_user)) = current_struct.take() {
            if !current_fields.is_empty() {
                result.push(StructDef {
                    name,
                    is_user_defined: is_user,
                    fields: current_fields,
                });
            }
        }
    }
    result
}

fn lookup_source_loc(ctx: &Option<Addr2LineCtx>, addr: u64) -> Option<SourceLoc> {
    let ctx = ctx.as_ref()?;
    let loc = ctx.find_location(addr).ok()??;
    let file = loc.file?;
    let line = loc.line?;
    let basename = file.rsplit('/').next().unwrap_or(file);
    Some(SourceLoc {
        file: basename.to_string(),
        path: file.to_string(),
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
