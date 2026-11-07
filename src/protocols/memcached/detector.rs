//! Memcached protocol detector for rDpi

use crate::core::types::{
    Confidence, DetectContext, DetectionResult, Direction, DissectorOutcome, DissectorState,
    MemcachedDissectorState, MemcachedMetadata, Metadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::{MemcachedParsed, parse_memcached, parse_memcached_udp};

/// 标准端口
const MEMCACHED_PORT: u16 = 11211;
/// 非标端口需要的最少匹配包数（对齐 nDPI MEMCACHED_MIN_MATCH）
const MEMCACHED_MIN_MATCH: u8 = 2;
/// 已接管后的包上限（对齐 nDPI packet_counter > 5）
const MEMCACHED_MAX_PACKETS: u8 = 5;

/// Memcached protocol detector
pub struct MemcachedDetector {
    _private: (),
}

impl MemcachedDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }

    fn result(parsed: MemcachedParsed) -> DetectionResult {
        DetectionResult::new(Protocol::Memcached)
            .with_metadata(Metadata::Memcached(MemcachedMetadata {
                command: Some(parsed.token.to_string()),
                is_response: parsed.is_response,
            }))
            .with_confidence(Confidence::Dpi)
    }
}

impl Default for MemcachedDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for MemcachedDetector {
    fn name(&self) -> &'static str {
        "memcached"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        parse_memcached(payload).map(Self::result)
    }

    fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
        if ctx.src_port != MEMCACHED_PORT && ctx.dst_port != MEMCACHED_PORT {
            return None;
        }
        parse_memcached(payload)
            .or_else(|| parse_memcached_udp(payload))
            .map(Self::result)
    }

    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        _direction: Direction,
        ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        let first_match = match state {
            DissectorState::None => {
                let parsed = parse_memcached(payload)?;
                *state = DissectorState::Memcached(MemcachedDissectorState::default());
                Some(parsed)
            }
            DissectorState::Memcached(_) => None,
            _ => return None,
        };
        let DissectorState::Memcached(memcached) = state else {
            return None;
        };
        memcached.packets = memcached.packets.saturating_add(1);

        let parsed = match first_match {
            Some(parsed) => Some(parsed),
            None => parse_memcached(payload),
        };
        if let Some(parsed) = parsed {
            memcached.matches = memcached.matches.saturating_add(1);
            let required = if ctx.src_port == MEMCACHED_PORT || ctx.dst_port == MEMCACHED_PORT {
                1
            } else {
                MEMCACHED_MIN_MATCH
            };
            if memcached.matches >= required {
                return Some(DissectorOutcome::Classified(Self::result(parsed)));
            }
        }
        if memcached.packets > MEMCACHED_MAX_PACKETS {
            return Some(DissectorOutcome::GiveUp);
        }
        Some(DissectorOutcome::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(src_port: u16, dst_port: u16) -> DetectContext {
        DetectContext {
            src_port,
            dst_port,
            is_http3_port: false,
        }
    }

    fn udp_payload(body: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x12, 0x34, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00];
        payload.extend_from_slice(body);
        payload
    }

    #[test]
    fn test_detect_text_command() {
        let detector = MemcachedDetector::new();
        let result = detector.detect(b"get foo\r\n").unwrap();
        assert_eq!(result.protocol, Protocol::Memcached);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Memcached(meta) => {
                assert_eq!(meta.command.as_deref(), Some("get"));
                assert!(!meta.is_response);
            }
            _ => panic!("expected Memcached metadata"),
        }
    }

    #[test]
    fn test_detect_udp_on_standard_port() {
        let detector = MemcachedDetector::new();
        let payload = udp_payload(b"get foo\r\n");
        let result = detector
            .detect_with_context(&payload, &ctx(40000, 11211))
            .unwrap();
        assert_eq!(result.protocol, Protocol::Memcached);
    }

    #[test]
    fn test_detect_with_context_requires_port() {
        let detector = MemcachedDetector::new();
        let payload = udp_payload(b"get foo\r\n");
        assert!(
            detector
                .detect_with_context(&payload, &ctx(40000, 9999))
                .is_none()
        );
    }

    #[test]
    fn test_process_standard_port_single_match() {
        let detector = MemcachedDetector::new();
        let mut state = DissectorState::None;
        let outcome = detector.process(
            &mut state,
            b"delete foo\r\n",
            Direction::Forward,
            &ctx(40000, 11211),
        );
        assert!(matches!(outcome, Some(DissectorOutcome::Classified(_))));
    }

    #[test]
    fn test_process_nonstandard_port_requires_two_matches() {
        let detector = MemcachedDetector::new();
        let mut state = DissectorState::None;
        let first = detector.process(
            &mut state,
            b"get foo\r\n",
            Direction::Forward,
            &ctx(40000, 9999),
        );
        assert!(matches!(first, Some(DissectorOutcome::Continue)));

        let second = detector.process(
            &mut state,
            b"DELETED\r\n",
            Direction::Reverse,
            &ctx(40000, 9999),
        );
        assert!(matches!(second, Some(DissectorOutcome::Classified(_))));
    }

    #[test]
    fn test_process_does_not_take_over_without_match() {
        let detector = MemcachedDetector::new();
        let mut state = DissectorState::None;
        let outcome = detector.process(
            &mut state,
            b"GET / HTTP/1.1\r\n",
            Direction::Forward,
            &ctx(40000, 9999),
        );
        assert!(outcome.is_none());
        assert_eq!(state, DissectorState::None);
    }

    #[test]
    fn test_process_gives_up_after_six_packets() {
        let detector = MemcachedDetector::new();
        let mut state = DissectorState::None;
        let first = detector.process(
            &mut state,
            b"get foo\r\n",
            Direction::Forward,
            &ctx(40000, 9999),
        );
        assert!(matches!(first, Some(DissectorOutcome::Continue)));

        for _ in 0..4 {
            let outcome = detector.process(
                &mut state,
                b"PING\r\n",
                Direction::Forward,
                &ctx(40000, 9999),
            );
            assert!(matches!(outcome, Some(DissectorOutcome::Continue)));
        }

        let last = detector.process(
            &mut state,
            b"PING\r\n",
            Direction::Forward,
            &ctx(40000, 9999),
        );
        assert!(matches!(last, Some(DissectorOutcome::GiveUp)));
    }
}
