pub mod elf;
pub mod macho;
pub mod pe;
pub mod raw;
pub mod wasm;

use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct BinarySection {
    pub name: String,
    pub data: Vec<u8>,
    pub offset: u64,
}

#[derive(Debug)]
pub struct ParsedBinary {
    pub format: BinaryFormat,
    pub arch: String,
    pub sections: Vec<BinarySection>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Wasm,
    Raw,
}

impl BinaryFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            BinaryFormat::Elf => "ELF",
            BinaryFormat::Pe => "PE",
            BinaryFormat::MachO => "Mach-O",
            BinaryFormat::Wasm => "WebAssembly",
            BinaryFormat::Raw => "Raw",
        }
    }
}

pub fn parse(path: &Path) -> Result<ParsedBinary> {
    let data = std::fs::read(path)?;
    parse_bytes(&data)
}

pub fn parse_bytes(data: &[u8]) -> Result<ParsedBinary> {
    if data.len() < 4 {
        return raw::parse(data);
    }

    match &data[..4] {
        [0x7f, 0x45, 0x4c, 0x46] => elf::parse(data),
        [0x4d, 0x5a, ..] => pe::parse(data),
        [0xfe, 0xed, 0xfa, 0xce]
        | [0xfe, 0xed, 0xfa, 0xcf]
        | [0xce, 0xfa, 0xed, 0xfe]
        | [0xcf, 0xfa, 0xed, 0xfe] => macho::parse(data),
        [0x00, 0x61, 0x73, 0x6d] => wasm::parse(data),
        [0xca, 0xfe, 0xba, 0xbe] => macho::parse(data),
        _ => raw::parse(data),
    }
}
