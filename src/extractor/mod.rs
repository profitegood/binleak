pub mod ascii;
pub mod base64_decoder;
pub mod unicode;
pub mod xor;

use crate::parser::BinarySection;

#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub value: String,
    pub offset: u64,
    pub section: String,
    pub encoding: Encoding,
    pub entropy: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Encoding {
    Ascii,
    Utf16Le,
    Utf16Be,
    Base64Decoded,
    XorDecoded(u8),
}

impl Encoding {
    pub fn as_str(&self) -> String {
        match self {
            Encoding::Ascii => "ascii".to_string(),
            Encoding::Utf16Le => "utf16-le".to_string(),
            Encoding::Utf16Be => "utf16-be".to_string(),
            Encoding::Base64Decoded => "base64".to_string(),
            Encoding::XorDecoded(k) => format!("xor(0x{:02x})", k),
        }
    }
}

pub struct ExtractorConfig {
    pub min_length: usize,
    pub xor_bruteforce: bool,
    pub decode_base64: bool,
    pub min_entropy: f64,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            min_length: 6,
            xor_bruteforce: true,
            decode_base64: true,
            min_entropy: 0.0,
        }
    }
}

pub fn extract_all(sections: &[BinarySection], cfg: &ExtractorConfig) -> Vec<ExtractedString> {
    use rayon::prelude::*;
    sections
        .par_iter()
        .flat_map(|section| extract_section(section, cfg))
        .collect()
}

fn extract_section(section: &BinarySection, cfg: &ExtractorConfig) -> Vec<ExtractedString> {
    let mut results = Vec::new();

    results.extend(ascii::extract(&section.data, section.offset, &section.name, cfg.min_length));
    results.extend(unicode::extract_utf16le(&section.data, section.offset, &section.name, cfg.min_length));
    results.extend(unicode::extract_utf16be(&section.data, section.offset, &section.name, cfg.min_length));

    if cfg.decode_base64 {
        results.extend(base64_decoder::extract(&section.data, section.offset, &section.name, cfg.min_length));
    }

    if cfg.xor_bruteforce {
        results.extend(xor::extract(&section.data, section.offset, &section.name, cfg.min_length));
    }

    for s in &mut results {
        s.entropy = compute_entropy(&s.value);
    }

    results.sort_by(|a, b| a.value.cmp(&b.value).then(a.offset.cmp(&b.offset)));
    results.dedup_by(|a, b| a.value == b.value);

    results
}

pub fn compute_entropy(s: &str) -> f64 {
    let len = s.len();
    if len == 0 {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len_f = len as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len_f;
            -p * p.log2()
        })
        .sum()
}
