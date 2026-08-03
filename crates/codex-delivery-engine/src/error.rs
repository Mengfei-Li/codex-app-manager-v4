use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeliveryError {
    #[error("invalid bootstrap envelope: {0}")]
    InvalidEnvelope(String),
    #[error("bootstrap envelope signature is invalid")]
    EnvelopeSignature,
    #[error("bootstrap envelope is expired or not yet valid")]
    EnvelopeTime,
    #[error("invalid claim response: {0}")]
    InvalidClaim(String),
    #[error("claim receipt signature is invalid")]
    ReceiptSignature,
    #[error("claim delivery digest does not match the signed receipt")]
    DeliveryDigest,
    #[error("claim transport failed: {0}")]
    Transport(String),
    #[error("configuration conflict: {0}")]
    ConfigConflict(String),
    #[error("configuration transaction failed: {0}")]
    ConfigTransaction(String),
    #[error("configuration rollback failed: {0}")]
    Rollback(String),
    #[error("locale contract is invalid: {0}")]
    Locale(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("TOML failed: {0}")]
    Toml(String),
}
