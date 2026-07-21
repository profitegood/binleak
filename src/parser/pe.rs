use anyhow::Result;
use goblin::pe::PE;

use super::{BinaryFormat, BinarySection, ParsedBinary};

pub fn parse(data: &[u8]) -> Result<ParsedBinary> {
    let pe = PE::parse(data)?;

    let arch = if pe.is_64 { "x86_64" } else { "x86" }.to_string();

    let mut sections = Vec::new();

    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();

        let offset = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;

        if size == 0 || offset.saturating_add(size) > data.len() {
            continue;
        }

        sections.push(BinarySection {
            name,
            data: data[offset..offset + size].to_vec(),
            offset: section.pointer_to_raw_data as u64,
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
        format: BinaryFormat::Pe,
        arch,
        sections,
        raw: data.to_vec(),
    })
}
