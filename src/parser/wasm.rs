use anyhow::Result;
use wasmparser::{Parser, Payload};

use super::{BinaryFormat, BinarySection, ParsedBinary};

pub fn parse(data: &[u8]) -> Result<ParsedBinary> {
    let mut sections = Vec::new();

    let parser = Parser::new(0);
    let mut offset: u64 = 0;

    for payload in parser.parse_all(data) {
        match payload? {
            Payload::DataSection(reader) => {
                for segment in reader {
                    let seg = segment?;
                    sections.push(BinarySection {
                        name: "data".to_string(),
                        data: seg.data.to_vec(),
                        offset,
                    });
                    offset += seg.data.len() as u64;
                }
            }
            Payload::CustomSection(s) => {
                sections.push(BinarySection {
                    name: format!("custom:{}", s.name()),
                    data: s.data().to_vec(),
                    offset: s.data_offset() as u64,
                });
            }
            _ => {}
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
        format: BinaryFormat::Wasm,
        arch: "wasm32".to_string(),
        sections,
        raw: data.to_vec(),
    })
}
