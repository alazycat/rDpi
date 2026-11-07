//! Elasticsearch protocol detection module for rDpi
//!
//! 二进制 `ES` + BE u32 长度（对齐 nDPI 5.0），并由 HTTP detector 通过
//! `X-elastic-product: Elasticsearch` 响应头补充 HTTP 子分类。

mod detector;
mod parser;

pub use detector::ElasticsearchDetector;
pub use parser::{is_elasticsearch_http_response, parse_elasticsearch};

use crate::protocols::Registry;

/// Register Elasticsearch detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(ElasticsearchDetector::new()));
}
