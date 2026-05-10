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

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
