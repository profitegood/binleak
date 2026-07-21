use anyhow::Result;
use goblin::mach::{Mach, MachO};

use super::{BinaryFormat, BinarySection, ParsedBinary};

pub fn parse(data: &[u8]) -> Result<ParsedBinary> {
    match Mach::parse(data)? {
        Mach::Binary(macho) => parse_macho(&macho, data),
        Mach::Fat(fat) => {
            let arches: Vec<_> = fat.iter_arches().filter_map(|a| a.ok()).collect();
            if let Some(arch) = arches.first() {
                let slice = arch.slice(data);
                let macho = MachO::parse(slice, 0)?;
                parse_macho(&macho, slice)
            } else {
                super::raw::parse(data)
            }
        }
    }
}

fn parse_macho(macho: &MachO, data: &[u8]) -> Result<ParsedBinary> {
    let arch = match macho.header.cputype() {
        goblin::mach::cputype::CPU_TYPE_X86_64 => "x86_64",
        goblin::mach::cputype::CPU_TYPE_ARM64 => "arm64",
        goblin::mach::cputype::CPU_TYPE_X86 => "x86",
        _ => "unknown",
    }
    .to_string();

    let mut sections = Vec::new();

    for segment in macho.segments.iter() {
        let seg_name = segment.name().unwrap_or("").trim_matches('\0').to_string();

        let seg_sections = match segment.sections() {
            Ok(s) => s,
            Err(_) => continue,
        };

        for (sh, _) in seg_sections {
            let sec_name = sh.name().unwrap_or("").trim_matches('\0').to_string();
            let offset = sh.offset as usize;
            let size = sh.size as usize;

            if size == 0 || offset.saturating_add(size) > data.len() {
                continue;
            }

            sections.push(BinarySection {
                name: format!("{},{}", seg_name, sec_name),
                data: data[offset..offset + size].to_vec(),
                offset: sh.offset as u64,
            });
        }
    }

    if sections.is_empty() {
        sections.push(BinarySection {
            name: "raw".to_string(),
            data: data.to_vec(),
            offset: 0,
        });
    }

    Ok(ParsedBinary {
        format: BinaryFormat::MachO,
        arch,
        sections,
        raw: data.to_vec(),
    })
}
