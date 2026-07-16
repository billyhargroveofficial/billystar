use std::fmt;

pub type Result<T> = std::result::Result<T, PolicyError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    TooLarge {
        what: &'static str,
        actual: usize,
        maximum: usize,
    },
    Decode(String),
    NonCanonical(&'static str),
    Invalid(String),
    Signature,
    NotYetValid(&'static str),
    Expired(&'static str),
    Rollback(String),
    Gap(String),
    Fork(String),
    Chain(String),
    Rotation(String),
}

impl PolicyError {
    pub(crate) fn decode(error: impl fmt::Display) -> Self {
        Self::Decode(error.to_string())
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge {
                what,
                actual,
                maximum,
            } => write!(f, "{what} is {actual} bytes; maximum is {maximum}"),
            Self::Decode(error) => write!(f, "CBOR decode failed: {error}"),
            Self::NonCanonical(what) => write!(f, "non-canonical {what}"),
            Self::Invalid(message) => write!(f, "invalid signed policy: {message}"),
            Self::Signature => write!(f, "Ed25519 signature verification failed"),
            Self::NotYetValid(what) => write!(f, "{what} is not yet valid"),
            Self::Expired(what) => write!(f, "{what} is expired"),
            Self::Rollback(message) => write!(f, "rollback rejected: {message}"),
            Self::Gap(message) => write!(f, "non-contiguous update rejected: {message}"),
            Self::Fork(message) => write!(f, "equivocation/fork rejected: {message}"),
            Self::Chain(message) => write!(f, "hash-chain violation: {message}"),
            Self::Rotation(message) => write!(f, "unsafe rotation rejected: {message}"),
        }
    }
}

impl std::error::Error for PolicyError {}
