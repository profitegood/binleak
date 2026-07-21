use crate::detector::VerificationStatus;
use reqwest::blocking::Client;
use std::time::Duration;

pub fn verify(token: &str) -> VerificationStatus {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let result = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("token {}", token))
        .header("User-Agent", "binleak-verifier/0.1")
        .send();

    match result {
        Ok(resp) => match resp.status().as_u16() {
            200 => VerificationStatus::Live,
            401 => VerificationStatus::Revoked,
            _ => VerificationStatus::Unknown,
        },
        Err(_) => VerificationStatus::Unknown,
    }
}
