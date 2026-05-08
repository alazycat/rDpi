use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Truncated header")]
    TruncatedHeader,

    #[error("Unsupported protocol")]
    UnsupportedProtocol,

    #[error("Flow table full")]
    FlowTableFull,
}

pub type Result<T> = std::result::Result<T, Error>;
