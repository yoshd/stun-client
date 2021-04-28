use thiserror::Error;

#[derive(Error, Debug)]
pub enum STUNClientError {
    #[error("cannot parse as STUN message")]
    ParseError(),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}
