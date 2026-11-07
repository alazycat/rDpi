//! SSH protocol detection module for rDpi
//!
//! Provides SSH version banner detection and parsing.

mod parser;

pub use parser::{SshVersionInfo, is_ssh_prefix, parse_ssh_version};

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(SshDetector::new()));
}

/// SSH protocol detector
pub struct SshDetector {
    _private: (),
}

/// SSH 版本标识行魔数
const SSH_BANNER_MAGIC: &[u8] = b"SSH-";
/// 版本标识行缓冲上限（RFC 4253 §4.2 建议单行 ≤ 255 字节，留足注释空间）
const SSH_BANNER_MAX_BYTES: usize = 1024;

/// 当前缓冲是否仍可能是 SSH 标识行（"SSH-" 的严格前缀或以其开头）
fn may_be_ssh_banner(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    if data.len() <= SSH_BANNER_MAGIC.len() {
        SSH_BANNER_MAGIC.starts_with(data)
    } else {
        data.starts_with(SSH_BANNER_MAGIC)
    }
}

impl SshDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for SshDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::protocols::ProtocolDetector for SshDetector {
    fn name(&self) -> &'static str {
        "ssh"
    }

    /// 首字节门：SSH banner 以 "SSH-" 起始（0x53）。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x53u8, 0x53u8)])
    }

    /// 有状态逐包处理：版本标识行可能跨 TCP 段
    ///
    /// 首段只要仍是 "SSH-" 的严格前缀或以 "SSH-" 开头即接管，避免行未结束
    /// 时被 IKE/Whois 等低特异性 detector 抢占；完整行交给无状态解析。
    fn process(
        &self,
        state: &mut crate::core::types::DissectorState,
        payload: &[u8],
        _direction: crate::core::types::Direction,
        _ctx: &crate::core::types::DetectContext,
    ) -> Option<crate::core::types::DissectorOutcome> {
        use crate::core::types::{DissectorOutcome, DissectorState, SshDissectorState};

        match state {
            DissectorState::None => {
                if !may_be_ssh_banner(payload) {
                    return None;
                }
                *state = DissectorState::Ssh(SshDissectorState::default());
            }
            DissectorState::Ssh(_) => {}
            _ => return None,
        }
        let DissectorState::Ssh(ssh) = state else {
            return None;
        };

        if ssh.buffer.len() + payload.len() > SSH_BANNER_MAX_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        ssh.buffer.extend_from_slice(payload);

        if let Some(result) = self.detect(&ssh.buffer) {
            ssh.buffer.clear();
            return Some(DissectorOutcome::Classified(result));
        }
        // 行已结束仍解析失败，或缓冲已不可能成为 SSH 标识行
        if ssh.buffer.contains(&b'\n') || !may_be_ssh_banner(&ssh.buffer) {
            return Some(DissectorOutcome::GiveUp);
        }
        Some(DissectorOutcome::Continue)
    }

    fn detect(&self, payload: &[u8]) -> Option<crate::core::types::DetectionResult> {
        // Quick check: SSH prefix byte
        if !is_ssh_prefix(*payload.first()?) {
            return None;
        }

        // Parse SSH version banner
        let info = parse_ssh_version(payload)?;

        use crate::core::types::{Confidence, DetectionResult, Metadata, Protocol, SshMetadata};

        let metadata = SshMetadata {
            version: Some(info.protocol_version),
            software: info.software_version,
        };

        Some(
            DetectionResult::new(Protocol::Ssh)
                .with_metadata(Metadata::Ssh(metadata))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::ProtocolDetector;

    #[test]
    fn test_ssh_detector_new() {
        let detector = SshDetector::new();
        assert_eq!(detector.name(), "ssh");
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = SshDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = b"SSH-2.0-OpenSSH_8.9\r\n";
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
