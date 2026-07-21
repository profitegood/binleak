use crate::detector::VerificationStatus;
use reqwest::blocking::Client;
use std::time::Duration;

fn client() -> Client {
    Client::builder().timeout(Duration::from_secs(5)).build().unwrap_or_default()
}

pub fn verify(token: &str) -> VerificationStatus {
    let result = client()
        .get("https://api.stripe.com/v1/account")
        .header("Authorization", format!("Bearer {}", token))
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
