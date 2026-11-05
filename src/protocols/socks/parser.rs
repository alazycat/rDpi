pub fn is_socks(data: &[u8]) -> bool {
    // 误报面审计 2026-11-05：旧判定「首字节 0x04/0x05 即命中」误报面极大——
    // 大量二进制载荷首字节恰为 0x04/0x05。收紧为结构校验：
    // - v5 方法协商请求（RFC 1928）：VER + NMETHODS + METHODS，nmethods>=1
    //   且 2+nmethods 不超载荷长度；
    // - v4 请求（SOCKS4）：VER + CMD + PORT(2) + IP(4) 至少 8 字节，且命令
    //   CMD 限 1..=4（CONNECT/BIND 一族）。
    if data.is_empty() {
        return false;
    }
    match data[0] {
        0x05 => data.len() >= 3 && data[1] >= 1 && 2 + data[1] as usize <= data.len(),
        0x04 => data.len() >= 8 && (1..=4).contains(&data[1]),
        _ => false,
    }
}
pub fn detect(data: &[u8]) -> bool {
    is_socks(data)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    vec![0x05, 0x01, 0x00]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_socks4() {
        // VER + CMD=CONNECT + PORT 0x0050 + IP 127.0.0.1
        assert!(is_socks(&[0x04, 0x01, 0x00, 0x50, 0x7F, 0x00, 0x00, 0x01]));
    }
    #[test]
    fn test_socks5() {
        // 误报面审计 2026-11-05：旧样本 [0x05,0x01] 为被截断的方法协商请求
        // （NMETHODS=1 声明 3 字节载荷），新判定拒绝；改为真实结构样本
        // VER + NMETHODS=1 + METHOD=NO-AUTH
        assert!(is_socks(&[0x05, 0x01, 0x00]));
        assert!(is_socks(&valid_sample()));
    }
    #[test]
    fn test_not_socks() {
        assert!(!is_socks(b"GET"));
    }
    #[test]
    fn test_empty() {
        assert!(!is_socks(&[]));
    }
    // 误报探针：旧判定命中、新判定拒绝
    #[test]
    fn test_fp_probe_socks4_bad_cmd() {
        // 首字节 0x04 但 CMD 非法（0xFF），旧判定误报
        assert!(!is_socks(&[0x04, 0xFF, 0x00, 0x50, 0x7F, 0x00, 0x00, 0x01]));
    }
    #[test]
    fn test_fp_probe_socks5_zero_nmethods() {
        // v5 但 NMETHODS=0（RFC 1928 要求至少 1 个方法），旧判定误报
        assert!(!is_socks(&[0x05, 0x00]));
    }
    #[test]
    fn test_fp_probe_socks5_truncated_methods() {
        // v5 声称 4 个方法但载荷被截断，旧判定误报
        assert!(!is_socks(&[0x05, 0x04, 0x00, 0x01]));
    }
}
