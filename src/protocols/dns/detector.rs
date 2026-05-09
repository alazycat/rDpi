use super::parser;
use crate::core::types::*;
use crate::protocols::ProtocolDetector;

pub struct DnsDetector;

impl Default for DnsDetector {
    fn default() -> Self {
        Self
    }
}

impl DnsDetector {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolDetector for DnsDetector {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        // DNS minimum length is 12 bytes (header)
        if payload.len() < 12 {
            return None;
        }

        // Try to parse DNS header
        let header = match parser::parse_header(payload) {
            Ok(h) => h,
            Err(_) => return None,
        };

        // Basic validation: opcode and rcode should be in reasonable range
        if header.opcode > 2 && header.rcode > 5 {
            return None;
        }

        // If there are questions, try to parse domain name
        let metadata = if header.qdcount > 0 && payload.len() > 12 {
            match parser::parse_name(payload, 12) {
                Ok((domain, _)) => Some(DnsMetadata {
                    query_domain: Some(domain),
                }),
                Err(_) => None,
            }
        } else {
            None
        };

        let mut result = DetectionResult::new(Protocol::Dns);
        if let Some(meta) = metadata {
            result = result.with_metadata(Metadata::Dns(meta));
        }

        Some(result)
    }
}
