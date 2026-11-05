pub fn is_syslog(data: &[u8]) -> bool {
    // 误报面审计 2026-11-05：旧判定接受任意位数的 PRI 数字（如 <12345>），对
    // 任意形如 <NN...> 的文本均命中。按 RFC 3164 收紧：PRI 为 1..=3 位数字
    // （i 为数字段结束索引，i>1 至少 1 位、i<=4 至多 3 位）且数值 <=191。
    if data.len() < 5 || data[0] != b'<' {
        return false;
    }
    let mut i = 1;
    while i < data.len() && data[i].is_ascii_digit() {
        i += 1;
    }
    if i <= 1 || i > 4 || i >= data.len() || data[i] != b'>' {
        return false;
    }
    let mut pri: u32 = 0;
    for &b in &data[1..i] {
        pri = pri * 10 + (b - b'0') as u32;
    }
    pri <= 191
}
pub fn detect(data: &[u8]) -> bool {
    is_syslog(data)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    b"<14>Mar  1 12:00 test".to_vec()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_match() {
        assert!(is_syslog(b"<14>Mar 1 12:00 host sshd[1234]: test"));
        assert!(is_syslog(&valid_sample()));
    }
    #[test]
    fn test_pri_boundary() {
        // RFC 3164 PRI 上界 191：3 位数字合法
        assert!(is_syslog(b"<191>Mar 1 12:00 test"));
        assert!(!is_syslog(b"<192>Mar 1 12:00 test"));
    }
    #[test]
    fn test_no_bracket() {
        assert!(!is_syslog(b"hello"));
    }
    #[test]
    fn test_short() {
        assert!(!is_syslog(b"<5>"));
    }
    #[test]
    fn test_no_digit() {
        assert!(!is_syslog(b"<>test"));
    }
    // 误报探针：旧判定命中、新判定拒绝
    #[test]
    fn test_fp_probe_pri_too_many_digits() {
        // PRI 超过 3 位数字，旧判定误报
        assert!(!is_syslog(b"<12345>test msg"));
    }
    #[test]
    fn test_fp_probe_pri_out_of_range() {
        // PRI 为 3 位数字但数值超过 191，旧判定误报
        assert!(!is_syslog(b"<999>test msg"));
    }
}
