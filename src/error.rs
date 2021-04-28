use thiserror::Error;

#[derive(Error, Debug)]
pub enum StunClientError {
    #[error("cannot parse as STUN message")]
    ParseError(),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}
