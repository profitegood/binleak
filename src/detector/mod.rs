pub mod rules;

use crate::extractor::ExtractedString;
use rules::Rule;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn color_str(&self) -> colored::ColoredString {
        use colored::Colorize;
        match self {
            Severity::Low => "LOW".white(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::High => "HIGH".red(),
            Severity::Critical => "CRITICAL".red().bold(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub description: String,
    pub severity: Severity,
    pub value: String,
    pub redacted_value: String,
    pub offset: u64,
    pub section: String,
    pub encoding: String,
    pub entropy: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationStatus>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStatus {
    Live,
    Revoked,
    Unknown,
    Unverified,
}

impl VerificationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerificationStatus::Live => "LIVE",
            VerificationStatus::Revoked => "REVOKED",
            VerificationStatus::Unknown => "UNKNOWN",
            VerificationStatus::Unverified => "UNVERIFIED",
        }
    }
}

pub struct Detector {
    rules: Vec<Rule>,
    min_entropy: f64,
    min_severity: Severity,
}

impl Detector {
    pub fn new(custom_rules: Vec<Rule>, min_entropy: f64, min_severity: Severity) -> Self {
        let mut all_rules = rules::builtin_rules();
        all_rules.extend(custom_rules);
        Self { rules: all_rules, min_entropy, min_severity }
    }

    pub fn detect(&self, strings: &[ExtractedString]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for s in strings {
            if s.entropy < self.min_entropy {
                continue;
            }

            for rule in &self.rules {
                if rule.severity < self.min_severity {
                    continue;
                }

                if rule.regex.is_match(&s.value) {
                    findings.push(Finding {
                        rule_id: rule.id.clone(),
                        description: rule.description.clone(),
                        severity: rule.severity.clone(),
                        redacted_value: redact(&s.value),
                        value: s.value.clone(),
                        offset: s.offset,
                        section: s.section.clone(),
                        encoding: s.encoding.as_str(),
                        entropy: (s.entropy * 100.0).round() / 100.0,
                        verification: Some(VerificationStatus::Unverified),
                    });
                    break;
                }
            }
        }

        findings.sort_by(|a, b| {
            severity_order(&b.severity)
                .cmp(&severity_order(&a.severity))
                .then(a.offset.cmp(&b.offset))
        });
        findings.dedup_by(|a, b| a.rule_id == b.rule_id && a.value == b.value);

        findings
    }
}

fn severity_order(s: &Severity) -> u8 {
    match s {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    if len <= 8 {
        return "•".repeat(len);
    }
    let keep = 4;
    let prefix: String = chars[..keep].iter().collect();
    let suffix: String = chars[len - keep..].iter().collect();
    format!("{}{}{}", prefix, "•".repeat(len - keep * 2), suffix)
}
