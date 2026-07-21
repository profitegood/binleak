use anyhow::Result;
use serde::Serialize;
use crate::scanner::ScanResults;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    artifacts: Vec<SarifArtifact>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    default_configuration: SarifConfiguration,
}

#[derive(Serialize)]
struct SarifConfiguration {
    level: String,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    byte_offset: u64,
}

#[derive(Serialize)]
struct SarifArtifact {
    location: SarifArtifactLocation,
}

fn severity_to_sarif_level(sev: &crate::detector::Severity) -> &'static str {
    use crate::detector::Severity;
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

pub fn render(results: &ScanResults) -> Result<String> {
    let mut seen_rules = std::collections::HashSet::new();
    let mut sarif_rules = Vec::new();

    for finding in &results.findings {
        if seen_rules.insert(finding.rule_id.clone()) {
            sarif_rules.push(SarifRule {
                id: finding.rule_id.clone(),
                name: finding.rule_id.replace('_', " "),
                short_description: SarifMessage { text: finding.description.clone() },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(&finding.severity).to_string(),
                },
            });
        }
    }

    let sarif_results: Vec<SarifResult> = results.findings.iter().map(|f| {
        SarifResult {
            rule_id: f.rule_id.clone(),
            level: severity_to_sarif_level(&f.severity).to_string(),
            message: SarifMessage {
                text: format!(
                    "{} detected in section '{}' at offset 0x{:08x} (entropy: {:.2})",
                    f.description, f.section, f.offset, f.entropy
                ),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation { uri: results.target.clone() },
                    region: SarifRegion { byte_offset: f.offset },
                },
            }],
        }
    }).collect();

    let log = SarifLog {
        schema: "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "binleak",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/yourname/binleak",
                    rules: sarif_rules,
                },
            },
            results: sarif_results,
            artifacts: vec![SarifArtifact {
                location: SarifArtifactLocation { uri: results.target.clone() },
            }],
        }],
    };

    Ok(serde_json::to_string_pretty(&log)?)
}
