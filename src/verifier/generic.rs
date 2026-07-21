use crate::detector::VerificationStatus;

pub fn verify_url_in_value(_value: &str) -> VerificationStatus {
    VerificationStatus::Unverified
}
