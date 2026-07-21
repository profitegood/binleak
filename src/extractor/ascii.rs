use super::{Encoding, ExtractedString};

pub fn extract(data: &[u8], base_offset: u64, section: &str, min_len: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut current = Vec::new();
    let mut start_offset = 0u64;

    for (i, &byte) in data.iter().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
            if current.is_empty() {
                start_offset = base_offset + i as u64;
            }
            current.push(byte);
        } else {
            if current.len() >= min_len {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    results.push(ExtractedString {
                        value: s,
                        offset: start_offset,
                        section: section.to_string(),
                        encoding: Encoding::Ascii,
                        entropy: 0.0,
                    });
                }
            }
            current.clear();
        }
    }

    if current.len() >= min_len {
        if let Ok(s) = String::from_utf8(current) {
            results.push(ExtractedString {
                value: s,
                offset: start_offset,
                section: section.to_string(),
                encoding: Encoding::Ascii,
                entropy: 0.0,
            });
        }
    }

    results
}
