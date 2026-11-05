pub fn is_rtmp_handshake(data: &[u8]) -> bool {
    // 误报面审计 2026-11-05：旧判定「首字节 0x03 即命中」误报面极大——0x03 是
    // TLS 3.x record、各类二进制流的常见首字节。按 Adobe RTMP 规范，C0+C1
    // 握手为 1+1536 字节（C0 固定 0x03，C1 为 1536 字节 time/time2/random），
    // 收紧为长度下限 1537。
    data.len() >= 1537 && data[0] == 0x03
}
pub fn detect(data: &[u8]) -> bool {
    is_rtmp_handshake(data)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    vec![0x03; 1537]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_match() {
        assert!(is_rtmp_handshake(&valid_sample()));
    }
    #[test]
    fn test_not_rtmp() {
        assert!(!is_rtmp_handshake(b"GET"));
    }
    #[test]
    fn test_empty() {
        assert!(!is_rtmp_handshake(&[]));
    }
    // 误报探针：旧判定命中、新判定拒绝
    #[test]
    fn test_fp_probe_short_c0c1() {
        // 旧判定 4 字节 0x03 开头即命中；不满足 C0+C1 全长的截断握手应拒绝
        assert!(!is_rtmp_handshake(&[0x03, 0x00, 0x00, 0x00]));
    }
    #[test]
    fn test_fp_probe_tls_like_0x03() {
        // 0x03 开头的短二进制载荷（如 TLS record 首字节），旧判定误报
        assert!(!is_rtmp_handshake(&[0x03, 0x01, 0x02, 0x03, 0x04]));
    }
}
