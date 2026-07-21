use super::{Encoding, ExtractedString};

pub fn extract_utf16le(data: &[u8], base_offset: u64, section: &str, min_len: usize) -> Vec<ExtractedString> {
    extract_utf16(data, base_offset, section, min_len, true)
}

pub fn extract_utf16be(data: &[u8], base_offset: u64, section: &str, min_len: usize) -> Vec<ExtractedString> {
    extract_utf16(data, base_offset, section, min_len, false)
}

fn extract_utf16(
    data: &[u8],
    base_offset: u64,
    section: &str,
    min_len: usize,
    little_endian: bool,
) -> Vec<ExtractedString> {
    if data.len() < 2 {
        return vec![];
    }

    let mut results = Vec::new();
    let mut chars = Vec::new();
    let mut start_offset = 0u64;

    let chunks: Vec<[u8; 2]> = data
        .chunks_exact(2)
        .map(|c| [c[0], c[1]])
        .collect();

    for (i, pair) in chunks.iter().enumerate() {
        let code = if little_endian {
            u16::from_le_bytes(*pair)
        } else {
            u16::from_be_bytes(*pair)
        };

        let ch = char::from_u32(code as u32);
        match ch {
            Some(c) if c.is_ascii_graphic() || c == ' ' => {
                if chars.is_empty() {
                    start_offset = base_offset + (i * 2) as u64;
                }
                chars.push(c);
            }
            _ => {
                if chars.len() >= min_len {
                    let s: String = chars.iter().collect();
                    results.push(ExtractedString {
                        value: s,
                        offset: start_offset,
                        section: section.to_string(),
                        encoding: if little_endian { Encoding::Utf16Le } else { Encoding::Utf16Be },
                        entropy: 0.0,
                    });
                }
                chars.clear();
            }
        }
    }

    if chars.len() >= min_len {
        let s: String = chars.iter().collect();
        results.push(ExtractedString {
            value: s,
            offset: start_offset,
            section: section.to_string(),
            encoding: if little_endian { Encoding::Utf16Le } else { Encoding::Utf16Be },
            entropy: 0.0,
        });
    }

    results
}
