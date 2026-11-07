use super::parser::{self, NetBiosParsed};
use crate::core::types::*;
use crate::protocols::ProtocolDetector;

const NETBIOS_MAX_BUFFER_BYTES: usize = 4096;

pub struct NetBiosDetector;

impl Default for NetBiosDetector {
    fn default() -> Self {
        Self
    }
}

impl NetBiosDetector {
    pub fn new() -> Self {
        Self
    }
}

fn result_from(parsed: NetBiosParsed) -> DetectionResult {
    DetectionResult::new(Protocol::NetBios).with_metadata(Metadata::NetBios(NetBiosMetadata {
        service: parsed.service,
        name: parsed.name,
        suffix: parsed.suffix,
    }))
}

fn parse_any(payload: &[u8]) -> Option<NetBiosParsed> {
    parser::parse_nbns(payload)
        .or_else(|| parser::parse_nbds(payload))
        .or_else(|| parser::parse_nbss(payload))
        .or_else(|| parser::parse_nbss_session_message(payload))
}

impl ProtocolDetector for NetBiosDetector {
    fn name(&self) -> &'static str {
        "netbios"
    }

    /// 首字节任意：NBNS transaction ID、NBDS type、NBSS type 均不固定。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        None
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        parse_any(payload).map(result_from)
    }

    fn detect_with_context(
        &self,
        payload: &[u8],
        ctx: &DetectContext,
    ) -> Option<DetectionResult> {
        let parsed = if ctx.src_port == 137 || ctx.dst_port == 137 {
            parser::parse_nbns(payload)
        } else if ctx.src_port == 138 || ctx.dst_port == 138 {
            parser::parse_nbds(payload)
        } else if ctx.src_port == 139 || ctx.dst_port == 139 {
            parser::parse_nbss(payload).or_else(|| parser::parse_nbss_session_message(payload))
        } else {
            None
        }?;
        Some(result_from(parsed))
    }

    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        _direction: Direction,
        ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        if ctx.src_port != 139 && ctx.dst_port != 139 {
            return None;
        }
        match state {
            DissectorState::None => {
                if payload.is_empty() {
                    return None;
                }
                if payload[0] != 0x81 && payload[0] != 0x00 {
                    return None;
                }
                *state = DissectorState::NetBios(NetBiosDissectorState::default());
            }
            DissectorState::NetBios(_) => {}
            _ => return None,
        }
        let DissectorState::NetBios(nb) = state else {
            return None;
        };
        if nb.buffer.len() + payload.len() > NETBIOS_MAX_BUFFER_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        nb.buffer.extend_from_slice(payload);

        let parsed = match nb.buffer[0] {
            0x81 => {
                if nb.buffer.len() < 37 {
                    return Some(DissectorOutcome::Continue);
                }
                parser::parse_nbss(&nb.buffer)
            }
            0x00 => {
                if nb.buffer.len() < 8 {
                    return Some(DissectorOutcome::Continue);
                }
                parser::parse_nbss_session_message(&nb.buffer)
            }
            _ => None,
        };

        match parsed {
            Some(parsed) => {
                nb.buffer.clear();
                Some(DissectorOutcome::Classified(result_from(parsed)))
            }
            None => Some(DissectorOutcome::GiveUp),
        }
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

    fn nbns_query() -> Vec<u8> {
        let mut name_bytes = b"SERVER".to_vec();
        name_bytes.resize(15, b' ');
        name_bytes.push(0x20);
        let mut name = Vec::new();
        for byte in name_bytes {
            name.push(b'A' + (byte >> 4));
            name.push(b'A' + (byte & 0x0F));
        }
        let mut payload = vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        payload.push(0x20);
        payload.extend(name);
        payload.push(0x00);
        payload.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);
        payload
    }

    fn nbss_request() -> Vec<u8> {
        let mut payload = vec![0x81, 0x00, 0x00, 0x44];
        payload.extend_from_slice(b"SERVER          ");
        payload.extend_from_slice(b"CLIENT          ");
        payload.push(0x20);
        payload.extend_from_slice(&[0x00; 35]);
        payload
    }

    #[test]
    fn detects_nbns_on_137() {
        let detector = NetBiosDetector::new();
        let result = detector
            .detect_with_context(&nbns_query(), &ctx(50010, 137))
            .unwrap();
        assert_eq!(result.protocol, Protocol::NetBios);
        match result.metadata {
            Metadata::NetBios(meta) => {
                assert_eq!(meta.service, NetBiosService::NameService);
                assert_eq!(meta.name.as_deref(), Some("SERVER"));
                assert_eq!(meta.suffix, Some(0x20));
            }
            other => panic!("expected NetBios metadata, got {other:?}"),
        }
    }

    #[test]
    fn ignores_nbns_on_other_port() {
        let detector = NetBiosDetector::new();
        assert!(detector
            .detect_with_context(&nbns_query(), &ctx(50010, 53))
            .is_none());
    }

    #[test]
    fn detects_nbss_on_139() {
        let detector = NetBiosDetector::new();
        let result = detector
            .detect_with_context(&nbss_request(), &ctx(50000, 139))
            .unwrap();
        assert_eq!(result.protocol, Protocol::NetBios);
        match result.metadata {
            Metadata::NetBios(meta) => {
                assert_eq!(meta.service, NetBiosService::SessionService);
                assert_eq!(meta.name.as_deref(), Some("SERVER"));
            }
            other => panic!("expected NetBios metadata, got {other:?}"),
        }
    }

    #[test]
    fn process_reassembles_split_nbss_request() {
        let detector = NetBiosDetector::new();
        let mut state = DissectorState::None;
        let c = ctx(50000, 139);
        let payload = nbss_request();

        let first = detector
            .process(&mut state, &payload[..4], Direction::Forward, &c)
            .unwrap();
        assert!(matches!(first, DissectorOutcome::Continue));

        let second = detector
            .process(&mut state, &payload[4..], Direction::Forward, &c)
            .unwrap();
        match second {
            DissectorOutcome::Classified(result) => {
                assert_eq!(result.protocol, Protocol::NetBios);
            }
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn process_ignores_non_139_port() {
        let detector = NetBiosDetector::new();
        let mut state = DissectorState::None;
        assert!(detector
            .process(
                &mut state,
                &nbss_request(),
                Direction::Forward,
                &ctx(50000, 445)
            )
            .is_none());
        assert_eq!(state, DissectorState::None);
    }

    #[test]
    fn process_gives_up_on_unknown_type() {
        let detector = NetBiosDetector::new();
        let mut state = DissectorState::None;
        detector
            .process(
                &mut state,
                &[0x00, 0x00, 0x00, 0x20],
                Direction::Forward,
                &ctx(50000, 139),
            )
            .unwrap();
        let outcome = detector
            .process(&mut state, b"XXXX", Direction::Forward, &ctx(50000, 139))
            .unwrap();
        assert!(matches!(outcome, DissectorOutcome::GiveUp));
    }
}
