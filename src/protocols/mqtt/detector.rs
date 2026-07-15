//! MQTT protocol detector for rDpi
//!
//! Detects MQTT CONNECT messages using payload inspection.
//! Uses port context (1883, 8883) for confidence adjustment.

use crate::core::types::{Confidence, DetectContext, DetectionResult, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::parse_mqtt_connect;

/// MQTT protocol detector
pub struct MqttDetector {
    _private: (),
}

impl MqttDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for MqttDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for MqttDetector {
    fn name(&self) -> &'static str {
        "mqtt"
    }

    fn detect(&self, _payload: &[u8]) -> Option<DetectionResult> {
        // MQTT detection needs port context for confidence adjustment
        None
    }

    fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
        if payload.is_empty() {
            return None;
        }

        let is_mqtt_port = ctx.dst_port == 1883
            || ctx.dst_port == 8883
            || ctx.src_port == 1883
            || ctx.src_port == 8883;

        // Quick pre-check: CONNECT type
        if (payload[0] & 0xF0) != 0x10 {
            return None;
        }

        let meta = parse_mqtt_connect(payload)?;

        let confidence = if is_mqtt_port {
            Confidence::Dpi
        } else {
            Confidence::DpiPartial
        };

        Some(
            DetectionResult::new(Protocol::Mqtt)
                .with_metadata(Metadata::Mqtt(meta))
                .with_confidence(confidence),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::ProtocolCategory;

    /// Build a minimal MQTT CONNECT packet
    fn build_connect(client_id: &str) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(0x10); // CONNECT type

        // Remaining Length (variable header + payload)
        let mut body = Vec::new();
        // Protocol Name "MQTT"
        body.extend_from_slice(&[0x00, 0x04]);
        body.extend_from_slice(b"MQTT");
        // Protocol Level 4 (3.1.1)
        body.push(0x04);
        // Connect Flags: Clean Session
        body.push(0x02);
        // Keep Alive: 60s
        body.extend_from_slice(&[0x00, 0x3C]);
        // Client ID
        let cid = client_id.as_bytes();
        body.extend_from_slice(&(cid.len() as u16).to_be_bytes());
        body.extend_from_slice(cid);

        // Encode remaining length
        let remaining = body.len();
        packet.push(remaining as u8);
        packet.extend_from_slice(&body);
        packet
    }

    #[test]
    fn test_mqtt_detector_connect_standard_port() {
        let detector = MqttDetector::new();
        let packet = build_connect("test-device");
        let ctx = DetectContext {
            src_port: 54321,
            dst_port: 1883,
            is_http3_port: false,
        };

        let result = detector.detect_with_context(&packet, &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Mqtt);
        assert_eq!(result.confidence, Confidence::Dpi);
        assert_eq!(result.category, ProtocolCategory::Iot);
    }

    #[test]
    fn test_mqtt_detector_connect_non_standard_port() {
        let detector = MqttDetector::new();
        let packet = build_connect("test-device");
        let ctx = DetectContext {
            src_port: 54321,
            dst_port: 8080,
            is_http3_port: false,
        };

        let result = detector.detect_with_context(&packet, &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Mqtt);
        assert_eq!(result.confidence, Confidence::DpiPartial);
    }

    #[test]
    fn test_mqtt_detector_reject_http() {
        let detector = MqttDetector::new();
        let ctx = DetectContext {
            src_port: 54321,
            dst_port: 80,
            is_http3_port: false,
        };

        // HTTP GET request should NOT match MQTT
        assert!(detector.detect_with_context(b"GET / HTTP/1.1\r\n", &ctx).is_none());
        // Empty payload
        assert!(detector.detect_with_context(b"", &ctx).is_none());
    }

    #[test]
    fn test_mqtt_detector_tls_port() {
        let detector = MqttDetector::new();
        let packet = build_connect("secure-device");
        let ctx = DetectContext {
            src_port: 54321,
            dst_port: 8883,
            is_http3_port: false,
        };

        let result = detector.detect_with_context(&packet, &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Mqtt);
        assert_eq!(result.confidence, Confidence::Dpi);
    }
}
