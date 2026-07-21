use anyhow::Result;
use goblin::elf::Elf;

use super::{BinaryFormat, BinarySection, ParsedBinary};

pub fn parse(data: &[u8]) -> Result<ParsedBinary> {
    let elf = Elf::parse(data)?;

    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => "x86_64",
        goblin::elf::header::EM_386 => "x86",
        goblin::elf::header::EM_AARCH64 => "aarch64",
        goblin::elf::header::EM_ARM => "arm",
        goblin::elf::header::EM_RISCV => "riscv",
        _ => "unknown",
    }
    .to_string();

    let mut sections = Vec::new();

    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();

        if sh.sh_type == goblin::elf::section_header::SHT_NULL || sh.sh_size == 0 {
            continue;
        }

        let offset = sh.sh_offset as usize;
        let size = sh.sh_size as usize;

        if offset.saturating_add(size) > data.len() {
            continue;
        }

        sections.push(BinarySection {
            name: if name.is_empty() { format!("section_{}", sh.sh_name) } else { name },
            data: data[offset..offset + size].to_vec(),
            offset: sh.sh_offset,
        });
    }

    if sections.is_empty() {
        sections.push(BinarySection {
            name: "raw".to_string(),
            data: data.to_vec(),
            offset: 0,
        });
    }

    Ok(ParsedBinary {
        format: BinaryFormat::Elf,
        arch,
        sections,
        raw: data.to_vec(),
    })
}
