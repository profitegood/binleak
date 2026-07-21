use anyhow::Result;
use serde::Serialize;

use crate::scanner::ScanResults;

#[derive(Serialize)]
struct JsonOutput<'a> {
    scan: ScanMeta<'a>,
    findings: &'a Vec<crate::detector::Finding>,
}

#[derive(Serialize)]
struct ScanMeta<'a> {
    target: &'a str,
    binary_format: &'a str,
    arch: &'a str,
    files_scanned: usize,
    duration_ms: u128,
    total_findings: usize,
}

pub fn render(results: &ScanResults) -> Result<String> {
    let output = JsonOutput {
        scan: ScanMeta {
            target: &results.target,
            binary_format: &results.format,
            arch: &results.arch,
            files_scanned: results.files_scanned,
            duration_ms: results.duration_ms,
            total_findings: results.findings.len(),
        },
        findings: &results.findings,
    };

    Ok(serde_json::to_string_pretty(&output)?)
}
