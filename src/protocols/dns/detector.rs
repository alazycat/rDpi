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

        // F6 修复：问题区可行性校验——每条 question 至少占 5 字节
        //（≥1 字符的标签 + 结尾 0 + qtype 2 字节 + qclass 2 字节）。
        // 修复前二进制载荷（如 TLS 记录，其长度字段被误读为 qdcount）会通过
        // opcode/rcode 检查被误判为 Dns（a7 实锤：0x0c0b=3083 条 question）。
        if 12 + header.qdcount as usize * 5 > payload.len() {
            return None;
        }

        // If there are questions, try to parse domain name.
        // F6 修复：qdcount > 0 却解析不出合法 qname（空/含不可打印字节/截断）
        // → 整体拒绝。真实 DNS 的问题区总是可解析；此处过滤把 TLS 长度字段
        // 等二进制噪声误读为 DNS 结构的载荷。
        let metadata = if header.qdcount > 0 && payload.len() > 12 {
            match parser::parse_name(payload, 12) {
                // F6 修复：qname 必须非空且全部为可打印 ASCII（标签语法上还
                // 限制字符集，此处取保守下界过滤二进制噪声）
                Ok((domain, _)) if is_printable_domain(&domain) => Some(DnsMetadata {
                    query_domain: Some(domain.clone()),
                    application: crate::application::identify(&domain),
                }),
                _ => return None,
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

/// F6：qname 合法性下界——非空且仅含可打印 ASCII 字符与分隔点
fn is_printable_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain
            .bytes()
            .all(|b| b == b'.' || (0x21..=0x7e).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_payload_rejected() {
        // F6 实锤载荷：TLS Certificate 记录头 + 假 DER（17 字节）。
        // 修复前被误判为 Dns（qdcount 误读为 0x0c0b=3083）
        let payload: Vec<u8> = vec![
            0x16, 0x03, 0x03, 0x00, 0x0c, 0x0b, 0x00, 0x00, 0x08, 0x00, 0x00, 0x05, 0x00, 0x00,
            0x02, 0x30, 0x82,
        ];
        assert!(DnsDetector::new().detect(&payload).is_none());
    }

    #[test]
    fn test_empty_qname_rejected() {
        // qdcount=1 但 qname 为空（0x00 根标签）→ 非 DNS，整体拒绝
        let mut payload = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        payload.push(0x00); // 空 qname
        payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        assert!(DnsDetector::new().detect(&payload).is_none());
    }

    #[test]
    fn test_valid_query_still_detected() {
        // 标准 A 查询：example.com
        let mut payload = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        payload.extend_from_slice(b"\x07example\x03com\x00");
        payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let r = DnsDetector::new().detect(&payload).expect("valid query");
        match r.metadata {
            Metadata::Dns(m) => assert_eq!(m.query_domain.as_deref(), Some("example.com")),
            _ => panic!("expected Dns metadata"),
        }
    }

    #[test]
    fn test_non_printable_qname_rejected() {
        // qdcount=1、qname 有非打印字节（0x01 控制字符标签）
        let mut payload = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        payload.extend_from_slice(&[0x01, 0x01, 0x00]); // label with control byte
        payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        assert!(DnsDetector::new().detect(&payload).is_none());
    }
}
