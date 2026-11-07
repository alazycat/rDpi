use super::parser::{
    is_http_prefix, parse_header_lines, parse_host_header, parse_request_line, parse_response_line,
};
use crate::core::types::*;
use crate::protocols::ProtocolDetector;

/// HTTP 头重组缓冲上限（8 KiB）
const HTTP_MAX_HEADER_BYTES: usize = 8192;

fn has_complete_headers(buffer: &[u8]) -> bool {
    buffer
        .windows(4)
        .any(|window| window == b"\r\n\r\n".as_slice())
}

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

    /// 有状态逐包 HTTP 头重组
    ///
    /// 首个客户端包以 HTTP 方法/响应行前缀初始化 per-flow 缓冲；后续包追加，
    /// 直到出现 `\r\n\r\n` 再交给无状态 [`Self::detect`] 解析。缓冲超过
    /// [`HTTP_MAX_HEADER_BYTES`] 返回 `GiveUp`，由上层回退到无状态路径。
    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        direction: Direction,
        ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        // 仅接管客户端方向（请求）；服务端响应交给无状态路径。
        // DNS 端口上的 TCP 流交给 DNS-over-TCP dissector，避免长度前缀首字节
        // 恰好落在 HTTP 方法首字母区间时被误接管。
        if direction != Direction::Forward || ctx.src_port == 53 || ctx.dst_port == 53 {
            return None;
        }

        match state {
            DissectorState::None => {
                if payload.is_empty() || !is_http_prefix(payload[0]) {
                    return None;
                }
                *state = DissectorState::Http(HttpDissectorState::default());
            }
            DissectorState::Http(_) => {}
            DissectorState::Ssh(_)
            | DissectorState::DnsTcp(_)
            | DissectorState::Tls(_)
            | DissectorState::Http2(_)
            | DissectorState::Smtp(_)
            | DissectorState::Pop3(_)
            | DissectorState::Imap(_)
            | DissectorState::WebSocket(_)
            | DissectorState::Ftp(_)
            | DissectorState::NetBios(_)
            | DissectorState::Smb(_)
            | DissectorState::Memcached(_) => {
                return None;
            }
        }

        let DissectorState::Http(http_state) = state else {
            return None;
        };
        if http_state.buffer.len() + payload.len() > HTTP_MAX_HEADER_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        http_state.buffer.extend_from_slice(payload);

        if !has_complete_headers(&http_state.buffer) {
            return Some(DissectorOutcome::Continue);
        }

        match self.detect(&http_state.buffer) {
            Some(result) => {
                http_state.buffer.clear();
                Some(DissectorOutcome::Classified(result))
            }
            None => Some(DissectorOutcome::GiveUp),
        }
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
            // 子分类：CONNECT 隧道 / 绝对 URI 正向代理 / 普通 HTTP
            let protocol = if req.method.eq_ignore_ascii_case("CONNECT") {
                Protocol::HttpConnect
            } else if req
                .path
                .as_bytes()
                .get(..7)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http://"))
            {
                Protocol::HttpProxy
            } else {
                Protocol::Http
            };
            let metadata = Metadata::Http(HttpMetadata {
                host,
                method: Some(req.method),
                path: Some(req.path),
                application,
                ja4h,
            });

            return Some(
                DetectionResult::new(protocol)
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

    #[test]
    fn test_detect_http_connect() {
        let detector = HttpDetector::new();
        let result = detector
            .detect(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        assert_eq!(result.protocol, Protocol::HttpConnect);
    }

    #[test]
    fn test_detect_http_proxy_absolute_uri() {
        let detector = HttpDetector::new();
        let result = detector
            .detect(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        assert_eq!(result.protocol, Protocol::HttpProxy);
    }

    #[test]
    fn test_detect_http_proxy_case_insensitive_scheme() {
        let detector = HttpDetector::new();
        let result = detector
            .detect(b"GET HTTP://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        assert_eq!(result.protocol, Protocol::HttpProxy);
    }

    #[test]
    fn test_detect_normal_http_stays_http() {
        let detector = HttpDetector::new();
        let result = detector
            .detect(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        assert_eq!(result.protocol, Protocol::Http);
    }
}
