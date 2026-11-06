//! HTTP/2 protocol detector for rDpi

use crate::core::types::{
    Confidence, DetectContext, DetectionResult, Direction, DissectorOutcome, DissectorState,
    Http2DissectorState, Metadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::{HTTP2_PREFACE, extract_request_headers, is_http2_preface};

/// HTTP/2 帧重组缓冲上限
const HTTP2_MAX_BUFFER_BYTES: usize = 64 * 1024;

pub struct Http2Detector {
    _private: (),
}

impl Http2Detector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for Http2Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for Http2Detector {
    fn name(&self) -> &'static str {
        "http2"
    }

    /// 首字节门：HTTP/2 preface 以 "PRI"（0x50）起始。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x50u8, 0x50u8)])
    }

    /// 有状态逐包 HTTP/2 preface + 帧重组
    ///
    /// 先缓冲 24 字节 connection preface（可跨包），再按帧扫描；首个完整
    /// HEADERS 帧经 HPACK 提取请求伪头部后定型。仅处理客户端方向。
    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        direction: Direction,
        _ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        if direction != Direction::Forward {
            return None;
        }

        match state {
            DissectorState::None => {
                if payload.is_empty() {
                    return None;
                }
                let begins_with_preface = if payload.len() <= HTTP2_PREFACE.len() {
                    HTTP2_PREFACE.starts_with(payload)
                } else {
                    payload.starts_with(HTTP2_PREFACE)
                };
                if !begins_with_preface {
                    return None;
                }
                *state = DissectorState::Http2(Http2DissectorState::default());
            }
            DissectorState::Http2(_) => {}
            _ => return None,
        }

        let DissectorState::Http2(h2_state) = state else {
            return None;
        };
        if h2_state.buffer.len() + payload.len() > HTTP2_MAX_BUFFER_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        h2_state.buffer.extend_from_slice(payload);

        if !h2_state.preface_seen {
            if h2_state.buffer.len() < HTTP2_PREFACE.len() {
                if HTTP2_PREFACE.starts_with(&h2_state.buffer) {
                    return Some(DissectorOutcome::Continue);
                }
                return Some(DissectorOutcome::GiveUp);
            }
            if !h2_state.buffer.starts_with(HTTP2_PREFACE) {
                return Some(DissectorOutcome::GiveUp);
            }
            h2_state.buffer.drain(..HTTP2_PREFACE.len());
            h2_state.preface_seen = true;
        }

        if let Some(metadata) = extract_request_headers(&h2_state.buffer) {
            h2_state.buffer.clear();
            let result = DetectionResult::new(Protocol::Http2)
                .with_confidence(Confidence::Dpi)
                .with_metadata(Metadata::Http2(metadata));
            return Some(DissectorOutcome::Classified(result));
        }

        Some(DissectorOutcome::Continue)
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if !is_http2_preface(payload) {
            return None;
        }
        // preface 包内若已含首个请求 HEADERS 帧则顺带提取；否则由 lib.rs
        // 定型流富化路径在后续包补齐（Http2Metadata::default 起步）
        let metadata = extract_request_headers(payload).unwrap_or_default();
        Some(
            DetectionResult::new(Protocol::Http2)
                .with_confidence(Confidence::Dpi)
                .with_metadata(Metadata::Http2(metadata)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_detector_preface() {
        let detector = Http2Detector::new();
        let result = detector
            .detect(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .unwrap();
        assert_eq!(result.protocol, Protocol::Http2);
    }

    #[test]
    fn test_http2_detector_http11() {
        let detector = Http2Detector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn test_http2_detector_empty() {
        let detector = Http2Detector::new();
        assert!(detector.detect(b"").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = Http2Detector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
