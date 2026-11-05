pub fn is_netflow_v5(data: &[u8]) -> bool {
    if data.len() < 4 || data[0] != 0x00 || data[1] != 0x05 {
        return false;
    }
    // 误报面审计 2026-11-05：新增 v5 结构自洽校验（RFC 3954 §5）——
    // count（大端 data[2..4]）必须落在 [1, 30]（v5 单包上限 30 条记录），
    // 且 payload 至少容纳 24 字节头 + count×48 字节流记录，
    // 拒绝仅有版本号前缀的 4 字节载荷。
    let count = u16::from_be_bytes([data[2], data[3]]) as usize;
    (1..=30).contains(&count) && data.len() >= 24 + count * 48
}
pub fn detect(data: &[u8]) -> bool {
    is_netflow_v5(data)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    // 误报面审计 2026-11-05：version=5、count=1，payload = 24 字节头 + 48 字节记录
    let mut v = vec![0u8; 72];
    v[0] = 0x00;
    v[1] = 0x05;
    v[2] = 0x00;
    v[3] = 0x01;
    v
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_match() {
        assert!(is_netflow_v5(&valid_sample()));
    }
    #[test]
    fn test_wrong_version() {
        assert!(!is_netflow_v5(&[0x00, 0x09]));
    }
    #[test]
    fn test_short() {
        assert!(!is_netflow_v5(&[0x00]));
    }
    // ---- 误报面审计 2026-11-05 探针 ----
    #[test]
    fn test_probe_version_prefix_only() {
        // 旧判定命中（version=5、count=1），新判定拒绝：4 字节载荷装不下 24+48 结构
        assert!(!is_netflow_v5(&[0x00, 0x05, 0x00, 0x01]));
    }
    #[test]
    fn test_probe_zero_count() {
        // 旧判定命中（version=5），新判定拒绝：count=0（v5 报文至少含 1 条记录）
        let mut v = vec![0u8; 24];
        v[0] = 0x00;
        v[1] = 0x05;
        v[2] = 0x00;
        v[3] = 0x00;
        assert!(!is_netflow_v5(&v));
    }
}
