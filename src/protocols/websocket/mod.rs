//! WebSocket protocol detection module for rDpi

mod detector;
mod parser;

pub use detector::WebSocketDetector;
pub use parser::is_websocket_upgrade;

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(WebSocketDetector::new()));
}
