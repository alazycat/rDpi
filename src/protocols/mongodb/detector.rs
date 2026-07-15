//! MongoDB protocol detector for rDpi
//!
//! Detects MongoDB isMaster/hello handshake messages using BSON scanning.
//! Works on any port (MongoDB commonly runs on 27017, 27018, 27019).

use crate::core::types::{Confidence, DetectionResult, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::parse_mongodb_handshake;

/// MongoDB protocol detector
pub struct MongodbDetector {
    _private: (),
}

impl MongodbDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for MongodbDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for MongodbDetector {
    fn name(&self) -> &'static str {
        "mongodb"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        // MongoDB can run on any port, no port context needed
        let meta = parse_mongodb_handshake(payload)?;

        Some(
            DetectionResult::new(Protocol::Mongodb)
                .with_metadata(Metadata::Mongodb(meta))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::ProtocolCategory;

    fn build_isMaster_bson(version: &str) -> Vec<u8> {
        let mut bson = Vec::new();
        // isMaster: boolean true
        bson.push(0x08);
        bson.extend_from_slice(b"isMaster");
        bson.push(0x00);
        bson.push(0x01);
        // ok: double 1.0
        bson.push(0x01);
        bson.extend_from_slice(b"ok");
        bson.push(0x00);
        bson.extend_from_slice(&1.0f64.to_le_bytes());
        // version (optional)
        if !version.is_empty() {
            bson.push(0x02);
            bson.extend_from_slice(b"version");
            bson.push(0x00);
            let v = version.as_bytes();
            bson.extend_from_slice(&((v.len() + 1) as i32).to_le_bytes());
            bson.extend_from_slice(v);
            bson.push(0x00);
        }

        let doc_len = (4 + bson.len() + 1) as i32;
        let mut doc = Vec::new();
        doc.extend_from_slice(&doc_len.to_le_bytes());
        doc.extend_from_slice(&bson);
        doc.push(0x00);
        doc
    }

    fn build_op_msg_packet(bson: &[u8]) -> Vec<u8> {
        let body_len = 1 + 1 + bson.len();
        let msg_len = (16 + body_len) as i32;
        let mut packet = Vec::new();
        packet.extend_from_slice(&msg_len.to_le_bytes());
        packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0xDC, 0x07, 0x00, 0x00]); // OP_MSG
        packet.push(0x00);
        packet.push(0x00);
        packet.extend_from_slice(bson);
        packet
    }

    #[test]
    fn test_mongodb_detector_handshake() {
        let detector = MongodbDetector::new();
        let bson = build_isMaster_bson("6.0.0");
        let packet = build_op_msg_packet(&bson);

        let result = detector.detect(&packet).unwrap();
        assert_eq!(result.protocol, Protocol::Mongodb);
        assert_eq!(result.confidence, Confidence::Dpi);
        assert_eq!(result.category, ProtocolCategory::Database);
    }

    #[test]
    fn test_mongodb_detector_no_handshake() {
        let detector = MongodbDetector::new();
        // HTTP data should not match MongoDB
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn test_mongodb_detector_empty() {
        let detector = MongodbDetector::new();
        assert!(detector.detect(b"").is_none());
    }

    #[test]
    fn test_mongodb_detector_wrong_bson() {
        let detector = MongodbDetector::new();
        // Valid BSON but no isMaster/hello
        let mut bson = Vec::new();
        bson.push(0x10);
        bson.extend_from_slice(b"someField");
        bson.push(0x00);
        bson.extend_from_slice(&42i32.to_le_bytes());
        let doc_len = (4 + bson.len() + 1) as i32;
        let mut doc = Vec::new();
        doc.extend_from_slice(&doc_len.to_le_bytes());
        doc.extend_from_slice(&bson);
        doc.push(0x00);

        let packet = build_op_msg_packet(&doc);
        assert!(detector.detect(&packet).is_none());
    }
}
