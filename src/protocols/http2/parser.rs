//! HTTP/2 protocol parser for rDpi
//!
//! Detects HTTP/2 via the 24-byte connection preface:
//! "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
//!
//! 元数据提取（feature: proto3）：扫描 preface 之后的帧，定位首个客户端
//! HEADERS 帧并 HPACK 解码，提取 `:authority` / `:method` / `:path`。
//! 无状态设计：连接级动态表在该帧解码时必为空（首个请求头块帧内自洽），
//! 不维护跨包 HPACK 状态（对齐 ADR-0004 一次性富化模式）。

use super::hpack;

/// HTTP/2 connection preface (24 bytes)
pub const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// 帧头长度（RFC 7540 §4.1：3 字节长度 + 1 字节类型 + 1 字节 flags + 4 字节 stream id）
const FRAME_HEADER_LEN: usize = 9;
/// HEADERS 帧类型
const FRAME_HEADERS: u8 = 0x01;
/// HEADERS flags：PADDED（首字节为 pad length）
const FLAG_PADDED: u8 = 0x08;
/// HEADERS flags：PRIORITY（帧体前 5 字节为优先级信息）
const FLAG_PRIORITY: u8 = 0x20;
/// 单包最多扫描帧数（防止恶意帧序列拖慢热路径）
const MAX_FRAMES: usize = 8;

/// Check if payload starts with HTTP/2 connection preface
pub fn is_http2_preface(data: &[u8]) -> bool {
    data.len() >= 24 && data[..24] == *HTTP2_PREFACE
}

/// 从 HTTP/2 载荷中提取首个请求 HEADERS 帧的元数据
///
/// - 若 payload 以 connection preface 开头则跳过 24 字节，否则从首字节
///   开始按帧扫描（调用方需保证已是定型 HTTP/2 流的载荷）。
/// - 仅处理首个 HEADERS 帧（type=0x01）：按 flags 跳过 PADDED/PRIORITY
///   字段后对头块做 HPACK 解码，匹配请求伪头部。
/// - 帧截断、头块解码失败、无请求伪头部均返回 `None`（不支持
///   CONTINUATION 跨帧重组，见 risks.md R14 边界）。
pub fn extract_request_headers(payload: &[u8]) -> Option<crate::core::types::Http2Metadata> {
    let body = if is_http2_preface(payload) {
        &payload[24..]
    } else {
        payload
    };

    let mut pos = 0usize;
    for _ in 0..MAX_FRAMES {
        if pos + FRAME_HEADER_LEN > body.len() {
            return None;
        }
        let len = u32::from_be_bytes([0, body[pos], body[pos + 1], body[pos + 2]]) as usize;
        let ftype = body[pos + 3];
        let flags = body[pos + 4];
        pos += FRAME_HEADER_LEN;
        // 帧体跨包截断：放弃本次提取
        if pos + len > body.len() {
            return None;
        }
        let frame = &body[pos..pos + len];
        pos += len;

        if ftype != FRAME_HEADERS {
            continue; // SETTINGS / WINDOW_UPDATE 等前置帧：跳过
        }

        // HEADERS 帧体布局（RFC 7540 §6.2）：
        // [pad length][priority 5B][header block][padding]
        let mut block_start = 0usize;
        let mut pad_len = 0usize;
        if flags & FLAG_PADDED != 0 {
            if frame.is_empty() {
                return None;
            }
            pad_len = frame[0] as usize;
            block_start = 1;
        }
        if flags & FLAG_PRIORITY != 0 {
            block_start += 5;
        }
        // 头块结束于帧体尾部 padding 之前
        let block_end = frame.len().saturating_sub(pad_len);
        if block_start >= block_end {
            return None;
        }

        let headers = hpack::decode_header_block(&frame[block_start..block_end])?;
        let mut md = crate::core::types::Http2Metadata::default();
        for (name, value) in headers {
            match name.as_str() {
                ":authority" => md.authority = Some(value),
                ":method" => md.method = Some(value),
                ":path" => md.path = Some(value),
                _ => {}
            }
        }
        // 首个 HEADERS 帧必须含请求伪头部（服务端响应帧不在此提取）
        if md.authority.is_some() || md.method.is_some() || md.path.is_some() {
            return Some(md);
        }
        return None;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_preface_valid() {
        assert!(is_http2_preface(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    }

    #[test]
    fn test_http2_preface_truncated() {
        assert!(!is_http2_preface(b"PRI * HTTP/2.0"));
        assert!(!is_http2_preface(b""));
    }

    #[test]
    fn test_http2_preface_http11() {
        assert!(!is_http2_preface(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn test_http2_preface_random() {
        assert!(!is_http2_preface(&[0u8; 24]));
    }

    /// 构造帧：9 字节帧头 + 帧体
    fn frame(ftype: u8, flags: u8, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(9 + body.len());
        let len = body.len() as u32;
        v.extend_from_slice(&len.to_be_bytes()[1..4]);
        v.push(ftype);
        v.push(flags);
        v.extend_from_slice(&[0, 0, 0, 1]); // stream id = 1
        v.extend_from_slice(body);
        v
    }

    /// 客户端 SETTINGS 空帧
    fn settings_frame() -> Vec<u8> {
        frame(0x04, 0x00, &[])
    }

    #[test]
    fn test_extract_preface_settings_headers() {
        // preface + SETTINGS + HEADERS（RFC C.4.1 头块：GET / :authority=www.example.com）
        let mut payload = HTTP2_PREFACE.to_vec();
        payload.extend_from_slice(&settings_frame());
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        payload.extend_from_slice(&frame(0x01, 0x04, &block));
        let md = extract_request_headers(&payload).unwrap();
        assert_eq!(md.method.as_deref(), Some("GET"));
        assert_eq!(md.path.as_deref(), Some("/"));
        assert_eq!(md.authority.as_deref(), Some("www.example.com"));
    }

    #[test]
    fn test_extract_headers_without_preface() {
        // 定型流后续包：无 preface，直接以帧流开头（富化路径）
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let payload = frame(0x01, 0x04, &block);
        let md = extract_request_headers(&payload).unwrap();
        assert_eq!(md.authority.as_deref(), Some("www.example.com"));
    }

    #[test]
    fn test_extract_padded_priority_headers() {
        // PADDED + PRIORITY：1 字节 pad_len + 5 字节优先级 + 头块 + 尾部 padding
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let mut body = vec![3u8]; // pad length
        body.extend_from_slice(&[0, 0, 0, 0, 255]); // 优先级：依赖流 0 + 权重 255
        body.extend_from_slice(&block);
        body.extend_from_slice(&[0u8; 3]); // 尾部 padding
        let payload = frame(0x01, 0x08 | 0x20, &body);
        let md = extract_request_headers(&payload).unwrap();
        assert_eq!(md.method.as_deref(), Some("GET"));
        assert_eq!(md.path.as_deref(), Some("/"));
    }

    #[test]
    fn test_extract_truncated_frame() {
        // 帧体跨包截断 → None
        let mut payload = HTTP2_PREFACE.to_vec();
        let mut f = frame(0x01, 0x04, &[0x82, 0x86, 0x84]);
        f.truncate(f.len() - 1);
        payload.extend_from_slice(&f);
        assert!(extract_request_headers(&payload).is_none());
    }

    #[test]
    fn test_extract_no_headers_max_frames() {
        // MAX_FRAMES 个非 HEADERS 帧 → None
        let mut payload = HTTP2_PREFACE.to_vec();
        for _ in 0..MAX_FRAMES {
            payload.extend_from_slice(&settings_frame());
        }
        assert!(extract_request_headers(&payload).is_none());
    }

    #[test]
    fn test_extract_response_headers_only() {
        // 服务端响应帧（:status 伪头部，静态索引 8 = 0x88）→ 不提取
        let payload = frame(0x01, 0x04, &[0x88]);
        assert!(extract_request_headers(&payload).is_none());
    }

    #[test]
    fn test_extract_preface_only() {
        assert!(extract_request_headers(HTTP2_PREFACE).is_none());
    }
}
