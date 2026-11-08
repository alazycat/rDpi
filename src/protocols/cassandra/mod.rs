//! Apache Cassandra CQL protocol detection module for rDpi
//!
//! 识别 19 字节 internode magic 与 CQL STARTUP 帧。

mod detector;
pub mod parser;

pub use detector::CassandraDetector;
pub use parser::{
    CASSANDRA_INTERNODE_LEN, CASSANDRA_INTERNODE_MAGIC, CQL_OPCODE_STARTUP, CQL_STARTUP_HEADER_LEN,
    CassandraParsed, CassandraStartupParsed, parse_cassandra, parse_cassandra_startup,
};

use crate::protocols::Registry;

/// Register Cassandra detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(CassandraDetector::new()));
}
