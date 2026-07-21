use crate::detector::VerificationStatus;
use reqwest::blocking::Client;
use std::time::Duration;

pub fn verify(access_key: &str) -> VerificationStatus {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let result = client
        .get("https://sts.amazonaws.com/")
        .query(&[
            ("Action", "GetCallerIdentity"),
            ("Version", "2011-06-15"),
            ("AWSAccessKeyId", access_key),
        ])
        .send();

    match result {
        Ok(resp) => {
            let body = resp.text().unwrap_or_default();
            if body.contains("InvalidClientTokenId") {
                VerificationStatus::Revoked
            } else if body.contains("AuthFailure") || body.contains("InvalidSignatureException") {
                VerificationStatus::Live
            } else {
                VerificationStatus::Unknown
            }
        }
        Err(_) => VerificationStatus::Unknown,
    }
}
