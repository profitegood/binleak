use colored::Colorize;

use crate::detector::{Severity, VerificationStatus};
use crate::scanner::ScanResults;

pub fn render(results: &ScanResults) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "\n{} {}\n",
        "binleak".cyan().bold(),
        env!("CARGO_PKG_VERSION").dimmed()
    ));
    out.push_str(&format!(
        "{} {} · {} · {}\n\n",
        "→".dimmed(),
        results.target.white(),
        results.format.dimmed(),
        results.arch.dimmed()
    ));

    if results.findings.is_empty() {
        out.push_str(&format!("{} No secrets found\n", "✓".green().bold()));
        out.push_str(&format!(
            "\n  Scanned {} file(s) in {}ms\n\n",
            results.files_scanned, results.duration_ms
        ));
        return out;
    }

    for finding in &results.findings {
        let sev_badge = finding.severity.color_str();

        out.push_str(&format!("[{}] {}\n", sev_badge, finding.description.white().bold()));
        out.push_str(&format!("  {:<10} {}\n", "Rule:".dimmed(), finding.rule_id.yellow()));
        out.push_str(&format!("  {:<10} {}\n", "Offset:".dimmed(), format!("0x{:08x}", finding.offset).cyan()));
        out.push_str(&format!("  {:<10} {}\n", "Section:".dimmed(), finding.section.white()));
        out.push_str(&format!("  {:<10} {}\n", "Encoding:".dimmed(), finding.encoding.white()));
        out.push_str(&format!("  {:<10} {}\n", "Entropy:".dimmed(), format!("{:.2}", finding.entropy).white()));
        out.push_str(&format!("  {:<10} {}\n", "Value:".dimmed(), finding.redacted_value.yellow()));

        if let Some(ref status) = finding.verification {
            let status_str = match status {
                VerificationStatus::Live => status.as_str().red().bold().to_string(),
                VerificationStatus::Revoked => status.as_str().green().to_string(),
                VerificationStatus::Unknown => status.as_str().yellow().to_string(),
                VerificationStatus::Unverified => status.as_str().dimmed().to_string(),
            };
            out.push_str(&format!("  {:<10} {}\n", "Status:".dimmed(), status_str));
        }

        out.push('\n');
    }

    let critical = results.findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = results.findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = results.findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = results.findings.iter().filter(|f| f.severity == Severity::Low).count();

    out.push_str(&format!(
        "{} {} finding(s)  {}  {}  {}  {}\n",
        "✗".red().bold(),
        results.findings.len().to_string().red().bold(),
        format!("critical:{}", critical).red(),
        format!("high:{}", high).red(),
        format!("medium:{}", medium).yellow(),
        format!("low:{}", low).white(),
    ));
    out.push_str(&format!(
        "  Scanned {} file(s) in {}ms\n\n",
        results.files_scanned, results.duration_ms
    ));

    out
}
