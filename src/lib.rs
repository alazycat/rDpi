//! rDpi - Rust Deep Packet Inspection Library
//!
//! 轻量级、高性能的深度包检测库，专注协议识别与流量分析。

pub mod core;
pub mod error;
pub mod parser;
pub mod protocols;

pub use error::Error;
