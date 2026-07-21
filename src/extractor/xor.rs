use super::{Encoding, ExtractedString, compute_entropy};

const MIN_PRINTABLE_RATIO: f64 = 0.85;
const MIN_ENTROPY_AFTER_XOR: f64 = 3.2;

pub fn extract(data: &[u8], base_offset: u64, section: &str, min_len: usize) -> Vec<ExtractedString> {
    if data.is_empty() {
        return vec![];
    }

    let printable_count = data.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count();
    let printable_ratio = printable_count as f64 / data.len() as f64;
    if printable_ratio > 0.7 {
        return vec![];
    }

    let mut results = Vec::new();

    for key in 1u8..=255u8 {
        let pr = data.iter().filter(|&&b| {
            let d = b ^ key;
            d.is_ascii_graphic() || d == b' '
        }).count() as f64 / data.len() as f64;

        if pr < MIN_PRINTABLE_RATIO {
            continue;
        }

        let mut current: Vec<u8> = Vec::new();
        let mut start = 0u64;

        for (i, &byte) in data.iter().enumerate() {
            let decoded = byte ^ key;
            if decoded.is_ascii_graphic() || decoded == b' ' {
                if current.is_empty() {
                    start = base_offset + i as u64;
                }
                current.push(decoded);
            } else {
                flush_string(&mut current, &mut results, start, section, key, min_len);
            }
        }
        flush_string(&mut current, &mut results, start, section, key, min_len);
    }

    results
}

fn flush_string(
    current: &mut Vec<u8>,
    results: &mut Vec<ExtractedString>,
    start: u64,
    section: &str,
    key: u8,
    min_len: usize,
) {
    if current.len() >= min_len {
        if let Ok(s) = String::from_utf8(current.clone()) {
            let ent = compute_entropy(&s);
            if ent >= MIN_ENTROPY_AFTER_XOR {
                results.push(ExtractedString {
                    value: s,
                    offset: start,
                    section: section.to_string(),
                    encoding: Encoding::XorDecoded(key),
                    entropy: ent,
                });
            }
        }
    }
    current.clear();
}
