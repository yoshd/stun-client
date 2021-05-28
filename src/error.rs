use thiserror::Error;

/// Defines the error used by the stun_client library.
#[derive(Error, Debug)]
pub enum STUNClientError {
    #[error("cannot parse as STUN message")]
    ParseError(),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("not supported by the server: {0}")]
    NotSupportedError(String),
    #[error("request timeout")]
    TimeoutError(),
    #[error("unknown error: {0}")]
    Unknown(String),
}

impl Clone for STUNClientError {
    fn clone(&self) -> Self {
        match self {
            Self::ParseError() => Self::ParseError(),
            Self::IOError(e) => Self::IOError(std::io::Error::new(e.kind(), e.to_string())),
            Self::NotSupportedError(msg) => Self::NotSupportedError(msg.clone()),
            Self::TimeoutError() => Self::TimeoutError(),
            Self::Unknown(msg) => Self::Unknown(msg.clone()),
        }
    }
}
