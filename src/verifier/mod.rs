pub mod aws;
pub mod github;
pub mod openai;
pub mod stripe;
pub mod generic;

use crate::detector::{Finding, VerificationStatus};

pub fn verify_findings(findings: &mut Vec<Finding>) {
    for finding in findings.iter_mut() {
        finding.verification = Some(verify_one(finding));
    }
}

fn verify_one(finding: &Finding) -> VerificationStatus {
    match finding.rule_id.as_str() {
        "aws_access_key_id" => aws::verify(&finding.value),
        "github_pat_classic" | "github_pat_fine" | "github_oauth" => github::verify(&finding.value),
        "stripe_secret_key" => stripe::verify(&finding.value),
        "openai_api_key" | "openai_project_key" => openai::verify(&finding.value),
        _ => generic::verify_url_in_value(&finding.value),
    }
}
