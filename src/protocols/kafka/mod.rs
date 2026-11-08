//! Apache Kafka protocol detection module for rDpi
//!
//! 识别长度前缀自洽的 Kafka 请求头并提取 API key/version/correlation/client_id。

mod detector;
mod parser;

pub use detector::KafkaDetector;
pub use parser::{KafkaParsed, parse_kafka_request};

use crate::protocols::Registry;

/// Register Kafka detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(KafkaDetector::new()));
}
