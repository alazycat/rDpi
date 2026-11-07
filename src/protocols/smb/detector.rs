use super::parser::{self, SmbHeader, SmbVersion};
use crate::core::types::*;
use crate::protocols::ProtocolDetector;

const SMB_MAX_BUFFER_BYTES: usize = 64 * 1024;

pub struct SmbDetector;

impl Default for SmbDetector {
    fn default() -> Self {
        Self
    }
}

impl SmbDetector {
    pub fn new() -> Self {
        Self
    }
}

fn result_from(header: SmbHeader) -> DetectionResult {
    let protocol = match header.version {
        SmbVersion::V1 => Protocol::Smb1,
        SmbVersion::V23 => Protocol::Smb23,
    };
    DetectionResult::new(protocol).with_metadata(Metadata::Smb(SmbMetadata {
        command: header.command,
        status: header.status,
    }))
}

fn is_negotiate(header: &SmbHeader) -> bool {
    header.version == SmbVersion::V1 && header.command == Some(0x72)
}

impl ProtocolDetector for SmbDetector {
    fn name(&self) -> &'static str {
        "smb"
    }

    /// 首字节门：NBSS session message type 恒为 0x00。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x00u8, 0x00u8)])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let message_len = parser::parse_nbss_length(payload)?;
        if message_len + 4 < payload.len() {
            return None;
        }
        let header = parser::parse_smb(payload)?;
        if is_negotiate(&header) {
            return None;
        }
        Some(result_from(header))
    }

    fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
        if ctx.src_port != 445 && ctx.dst_port != 445 {
            return None;
        }
        self.detect(payload)
    }

    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        _direction: Direction,
        ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        if ctx.src_port != 445 && ctx.dst_port != 445 {
            return None;
        }
        match state {
            DissectorState::None => {
                if payload.first() != Some(&0x00) {
                    return None;
                }
                *state = DissectorState::Smb(SmbDissectorState::default());
            }
            DissectorState::Smb(_) => {}
            _ => return None,
        }
        let DissectorState::Smb(smb) = state else {
            return None;
        };
        if smb.buffer.len() + payload.len() > SMB_MAX_BUFFER_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        smb.buffer.extend_from_slice(payload);

        loop {
            let message_len = match parser::parse_nbss_length(&smb.buffer) {
                Some(length) => length,
                None => {
                    if smb.buffer.len() < 4 {
                        return Some(DissectorOutcome::Continue);
                    }
                    return Some(DissectorOutcome::GiveUp);
                }
            };
            if smb.buffer.len() < 8 {
                return Some(DissectorOutcome::Continue);
            }
            let is_v1 = smb.buffer[4..8] == *b"\xFFSMB";
            if is_v1 && smb.buffer.len() < 9 {
                return Some(DissectorOutcome::Continue);
            }

            let available = smb.buffer.len().min(4 + message_len);
            let header = match parser::parse_smb(&smb.buffer[..available]) {
                Some(header) => header,
                None => return Some(DissectorOutcome::GiveUp),
            };

            if is_negotiate(&header) {
                if smb.buffer.len() < 4 + message_len {
                    return Some(DissectorOutcome::Continue);
                }
                smb.buffer.drain(..4 + message_len);
                if smb.buffer.is_empty() {
                    return Some(DissectorOutcome::Continue);
                }
                continue;
            }

            smb.buffer.clear();
            return Some(DissectorOutcome::Classified(result_from(header)));
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

    fn nbss(payload: &[u8]) -> Vec<u8> {
        let length = payload.len();
        let mut out = vec![
            0x00,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
        ];
        out.extend_from_slice(payload);
        out
    }

    fn smb1(command: u8) -> Vec<u8> {
        let mut smb = b"\xFFSMB".to_vec();
        smb.push(command);
        smb.extend_from_slice(&0u32.to_le_bytes());
        smb.resize(32, 0);
        nbss(&smb)
    }

    fn smb2(command: u16) -> Vec<u8> {
        let mut smb = b"\xFESMB".to_vec();
        smb.extend_from_slice(&64u16.to_le_bytes());
        smb.extend_from_slice(&1u16.to_le_bytes());
        smb.extend_from_slice(&0u32.to_le_bytes());
        smb.extend_from_slice(&command.to_le_bytes());
        smb.resize(64, 0);
        nbss(&smb)
    }

    #[test]
    fn detects_smb1_session_setup() {
        let detector = SmbDetector::new();
        let result = detector
            .detect_with_context(&smb1(0x73), &ctx(50000, 445))
            .unwrap();
        assert_eq!(result.protocol, Protocol::Smb1);
        match result.metadata {
            Metadata::Smb(meta) => assert_eq!(meta.command, Some(0x73)),
            other => panic!("expected Smb metadata, got {other:?}"),
        }
    }

    #[test]
    fn detects_smb23_negotiate() {
        let detector = SmbDetector::new();
        let result = detector
            .detect_with_context(&smb2(0x0000), &ctx(50000, 445))
            .unwrap();
        assert_eq!(result.protocol, Protocol::Smb23);
    }

    #[test]
    fn stateless_skips_smb1_negotiate() {
        let detector = SmbDetector::new();
        assert!(
            detector
                .detect_with_context(&smb1(0x72), &ctx(50000, 445))
                .is_none()
        );
    }

    #[test]
    fn ignores_non_445_port() {
        let detector = SmbDetector::new();
        assert!(
            detector
                .detect_with_context(&smb1(0x73), &ctx(50000, 139))
                .is_none()
        );
    }

    #[test]
    fn process_skips_negotiate_then_classifies_setup() {
        let detector = SmbDetector::new();
        let mut state = DissectorState::None;
        let c = ctx(50000, 445);

        let outcome = detector
            .process(&mut state, &smb1(0x72), Direction::Forward, &c)
            .unwrap();
        assert!(matches!(outcome, DissectorOutcome::Continue));

        let outcome = detector
            .process(&mut state, &smb1(0x73), Direction::Forward, &c)
            .unwrap();
        match outcome {
            DissectorOutcome::Classified(result) => {
                assert_eq!(result.protocol, Protocol::Smb1);
            }
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn process_reassembles_split_header() {
        let detector = SmbDetector::new();
        let mut state = DissectorState::None;
        let c = ctx(50000, 445);
        let payload = smb2(0x0000);

        let outcome = detector
            .process(&mut state, &payload[..2], Direction::Forward, &c)
            .unwrap();
        assert!(matches!(outcome, DissectorOutcome::Continue));

        let outcome = detector
            .process(&mut state, &payload[2..], Direction::Forward, &c)
            .unwrap();
        match outcome {
            DissectorOutcome::Classified(result) => {
                assert_eq!(result.protocol, Protocol::Smb23);
            }
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn process_gives_up_on_unknown_signature() {
        let detector = SmbDetector::new();
        let mut state = DissectorState::None;
        let c = ctx(50000, 445);
        let payload = nbss(b"XXXXXXXX");
        let outcome = detector
            .process(&mut state, &payload, Direction::Forward, &c)
            .unwrap();
        assert!(matches!(outcome, DissectorOutcome::GiveUp));
    }

    #[test]
    fn first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = SmbDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = smb1(0x73);
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
