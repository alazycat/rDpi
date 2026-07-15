//! MQTT protocol detection module for rDpi
//!
//! Provides MQTT CONNECT packet detection for protocol identification.
//!
//! ## Supported Detection
//!
//! - MQTT v3.1 (MQIsdp), v3.1.1, v5.0 CONNECT messages
//! - Protocol version, Client ID, Will Topic extraction
//!
//! ## Example
//!
//! ```ignore
//! use rdpi::protocols::mqtt::MqttDetector;
//! use rdpi::protocols::ProtocolDetector;
//!
//! let detector = MqttDetector::new();
//! let ctx = rdpi::DetectContext { src_port: 54321, dst_port: 1883, is_http3_port: false };
//! if let Some(result) = detector.detect_with_context(payload, &ctx) {
//!     println!("Detected MQTT: {:?}", result);
//! }
//! ```

mod detector;
mod parser;

pub use detector::MqttDetector;
pub use parser::parse_mqtt_connect;

use crate::protocols::Registry;

/// Register MQTT detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(MqttDetector::new()));
}
