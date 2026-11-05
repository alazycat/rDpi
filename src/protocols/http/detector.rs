use super::parser::{
    is_http_prefix, parse_header_lines, parse_host_header, parse_request_line, parse_response_line,
};
use crate::core::types::*;
use crate::protocols::ProtocolDetector;

pub struct HttpDetector;

impl Default for HttpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpDetector {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolDetector for HttpDetector {
    fn name(&self) -> &'static str {
        "http"
    }

    /// 首字节门：HTTP 方法/响应行首字母（C/D/G/H/O/P/T）。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[
            (0x43u8, 0x43u8),
            (0x44u8, 0x44u8),
            (0x47u8, 0x47u8),
            (0x48u8, 0x48u8),
            (0x4Fu8, 0x4Fu8),
            (0x50u8, 0x50u8),
            (0x54u8, 0x54u8),
        ])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        // Layer 1: Quick pre-check - first byte must be HTTP method prefix
        if payload.is_empty() || !is_http_prefix(payload[0]) {
            return None;
        }

        // Layer 2: Try parsing as HTTP request
        if let Some(req) = parse_request_line(payload) {
            // Layer 3: Extract metadata
            let host = parse_host_header(payload);
            let application = host.as_ref().and_then(|h| {
                if !h.is_empty() {
                    crate::application::identify(h)
                } else {
                    None
                }
            });
            // JA4H 客户端指纹：仅请求路径计算（头部原始顺序/大小写敏感，
            // 官方 ja4h.py to_ja4h 语义；HTTP/2 请求由 proto3 模块处理，不在此路径）
            let header_lines = parse_header_lines(payload);
            let ja4h = Some(crate::application::compute_ja4h(
                &req.method,
                &req.version,
                &header_lines
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect::<Vec<_>>(),
            ));
            let metadata = Metadata::Http(HttpMetadata {
                host,
                method: Some(req.method),
                path: Some(req.path),
                application,
                ja4h,
            });

            return Some(
                DetectionResult::new(Protocol::Http)
                    .with_metadata(metadata)
                    .with_confidence(Confidence::Dpi),
            );
        }

        // Layer 2: Try parsing as HTTP response
        if let Some(_resp) = parse_response_line(payload) {
            // Layer 3: For responses, we just detect protocol (status code is in response line)
            let metadata = Metadata::Http(HttpMetadata {
                host: None,
                method: None,
                path: None,
                application: None,
                ja4h: None,
            });

            return Some(
                DetectionResult::new(Protocol::Http)
                    .with_metadata(metadata)
                    .with_confidence(Confidence::Dpi),
            );
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = HttpDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = b"GET / HTTP/1.1\r\n";
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
