pub fn is_whois(data: &[u8]) -> bool {
    // 误报面审计 2026-11-05：旧判定「全部可打印即命中」会把任意可打印文本
    // （HTTP 头、日志行、短词）认领为 Whois。收紧为：总长 5..=1000、全部可打印
    // （graphic/space/CR/LF，保留原判断）、末字节必须为 LF（whois 查询以
    // CR/LF 收尾）、首行（到第一个 CR/LF 为止）长度不超过 255。
    if data.len() < 5 || data.len() > 1000 {
        return false;
    }
    if !data
        .iter()
        .all(|&b| b.is_ascii_graphic() || b == b'\r' || b == b'\n' || b == b' ')
    {
        return false;
    }
    if data[data.len() - 1] != b'\n' {
        return false;
    }
    let first_line = data
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(data.len());
    first_line <= 255
}
pub fn detect(data: &[u8]) -> bool {
    is_whois(data)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    b"example.com\r\n".to_vec()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_match() {
        assert!(is_whois(b"example.com\r\n"));
    }
    #[test]
    fn test_empty() {
        assert!(!is_whois(b""));
    }
    #[test]
    fn test_binary() {
        assert!(!is_whois(&[0x00, 0x01]));
    }
    // 误报探针：旧判定命中、新判定拒绝
    #[test]
    fn test_fp_probe_no_trailing_newline() {
        // 全可打印但无 LF 结尾的短文本（如请求行片段），旧判定误报
        assert!(!is_whois(b"example.com"));
    }
    #[test]
    fn test_fp_probe_first_line_too_long() {
        // 首行超过 255 字节的超长行，旧判定误报
        let mut v = vec![b'a'; 300];
        v.extend_from_slice(b"\r\n");
        assert!(!is_whois(&v));
    }
}
