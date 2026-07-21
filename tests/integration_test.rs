use binleak::extractor::{self, ExtractorConfig};
use binleak::detector::{Detector, Severity};
use binleak::parser;

/// Build a minimal ELF-like blob with a known secret embedded
fn make_test_blob(secret: &str) -> Vec<u8> {
    let mut data = vec![0u8; 64];
    let bytes = secret.as_bytes();
    data.extend_from_slice(bytes);
    data.extend_from_slice(&[0u8; 64]);
    data
}

#[test]
fn test_ascii_extraction_finds_string() {
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let blob = make_test_blob(secret);

    let section = binleak::parser::BinarySection {
        name: ".rodata".to_string(),
        data: blob,
        offset: 0,
    };

    let cfg = ExtractorConfig::default();
    let strings = extractor::extract_all(&[section], &cfg);
    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
    assert!(values.iter().any(|v| v.contains(secret)), "Expected to find: {}", secret);
}

#[test]
fn test_entropy_filter_removes_low_entropy() {
    // Low entropy string: all same character
    let blob = make_test_blob("aaaaaaaaaaaaaaaaaaaaaa");
    let section = binleak::parser::BinarySection {
        name: ".data".to_string(),
        data: blob,
        offset: 0,
    };
    let cfg = ExtractorConfig::default();
    let strings = extractor::extract_all(&[section], &cfg);

    let detector = Detector::new(vec![], 3.5, Severity::Low);
    let findings = detector.detect(&strings);
    // Should find nothing (entropy of "aaa..." is 0)
    assert!(findings.is_empty());
}

#[test]
fn test_aws_key_pattern_matches() {
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let blob = make_test_blob(secret);
    let section = binleak::parser::BinarySection {
        name: ".rodata".to_string(),
        data: blob,
        offset: 0,
    };
    let cfg = ExtractorConfig::default();
    let strings = extractor::extract_all(&[section], &cfg);

    let detector = Detector::new(vec![], 0.0, Severity::Low);
    let findings = detector.detect(&strings);

    assert!(
        findings.iter().any(|f| f.rule_id == "aws_access_key_id"),
        "Expected aws_access_key_id finding"
    );
}

#[test]
fn test_github_pat_detection() {
    let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh";
    let blob = make_test_blob(token);
    let section = binleak::parser::BinarySection {
        name: ".rodata".to_string(),
        data: blob,
        offset: 0,
    };
    let cfg = ExtractorConfig::default();
    let strings = extractor::extract_all(&[section], &cfg);
    let detector = Detector::new(vec![], 0.0, Severity::Low);
    let findings = detector.detect(&strings);

    assert!(
        findings.iter().any(|f| f.rule_id.starts_with("github_")),
        "Expected GitHub token finding"
    );
}

#[test]
fn test_xor_extraction() {
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let key: u8 = 0x42;
    let xored: Vec<u8> = secret.bytes().map(|b| b ^ key).collect();

    let mut data = vec![0u8; 64];
    data.extend_from_slice(&xored);
    data.extend_from_slice(&[0u8; 64]);

    let section = binleak::parser::BinarySection {
        name: ".data".to_string(),
        data,
        offset: 0,
    };

    let cfg = ExtractorConfig {
        xor_bruteforce: true,
        min_length: 6,
        decode_base64: false,
        min_entropy: 0.0,
    };

    let strings = extractor::extract_all(&[section], &cfg);
    let values: Vec<String> = strings.iter().map(|s| s.value.clone()).collect();
    assert!(
        values.iter().any(|v| v.contains(secret)),
        "XOR extraction should find the secret. Got: {:?}",
        values
    );
}

#[test]
fn test_raw_format_fallback() {
    let data = b"This is not a valid binary format but contains AKIAIOSFODNN7EXAMPLE secret";
    let parsed = parser::parse_bytes(data).unwrap();
    assert_eq!(parsed.format, parser::BinaryFormat::Raw);
    assert!(!parsed.sections.is_empty());
}
