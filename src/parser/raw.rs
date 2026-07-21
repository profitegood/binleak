use anyhow::Result;
use super::{BinaryFormat, BinarySection, ParsedBinary};

pub fn parse(data: &[u8]) -> Result<ParsedBinary> {
    Ok(ParsedBinary {
        format: BinaryFormat::Raw,
        arch: "unknown".to_string(),
        sections: vec![BinarySection {
            name: "raw".to_string(),
            data: data.to_vec(),
            offset: 0,
        }],
        raw: data.to_vec(),
    })
}
