use base64::{Engine as _, engine::general_purpose::STANDARD};
use super::{Encoding, ExtractedString};

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const MIN_BASE64_LEN: usize = 16;

pub fn extract(data: &[u8], base_offset: u64, section: &str, min_len: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let text = String::from_utf8_lossy(data);
    let mut i = 0;
    let bytes = text.as_bytes();

    while i < bytes.len() {
        if BASE64_CHARS.contains(&bytes[i]) {
            let start = i;
            while i < bytes.len() && (BASE64_CHARS.contains(&bytes[i]) || bytes[i] == b'\n' || bytes[i] == b'\r') {
                i += 1;
            }
            let candidate = &text[start..i];
            let candidate = candidate.replace(['\n', '\r'], "");

            if candidate.len() >= MIN_BASE64_LEN && candidate.len() % 4 == 0 {
                if let Ok(decoded) = STANDARD.decode(&candidate) {
                    if decoded.len() >= min_len {
                        let decoded_str = String::from_utf8_lossy(&decoded).to_string();
                        if decoded_str.chars().any(|c| c.is_ascii_graphic()) {
                            results.push(ExtractedString {
                                value: decoded_str,
                                offset: base_offset + start as u64,
                                section: section.to_string(),
                                encoding: Encoding::Base64Decoded,
                                entropy: 0.0,
                            });
                        }
                    }
                }
            }
        } else {
            i += 1;
        }
    }

    results
}
