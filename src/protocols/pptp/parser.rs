pub fn is_pptp(data: &[u8]) -> bool {
    // 误报面审计 2026-11-05：旧判定 `data[0]==0x00 && data[1]==0x01` 与 RFC 2637
    // 控制报文结构不符——真报文首 2 字节是大端长度字段，Magic Cookie 固定位于
    // data[2..6]=[0x1A,0x2B,0x3C,0x4D]。旧判定永远匹配不到真报文（假阴），同时
    // 任意以 0x00 0x01 开头的二进制载荷均被认领（假阳）。改为校验 Magic Cookie。
    data.len() >= 8 && data[2..6] == [0x1A, 0x2B, 0x3C, 0x4D]
}
pub fn detect(d: &[u8]) -> bool {
    is_pptp(d)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    // 16 字节 Start-Control-Connection-Request：长度字段 0x0010 + Magic Cookie
    // + 控制消息类型 0x0001（Start-Control-Connection-Request）+ 剩余补零
    vec![
        0x00, 0x10, 0x1A, 0x2B, 0x3C, 0x4D, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_match() {
        assert!(is_pptp(&valid_sample()));
    }
    #[test]
    fn test_wrong() {
        assert!(!is_pptp(b"GET"));
    }
    #[test]
    fn test_short() {
        assert!(!is_pptp(&[0x00]));
    }
    // 误报探针：旧判定命中、新判定拒绝
    #[test]
    fn test_fp_probe_header_without_magic() {
        // 旧判定 data[0]==0x00 && data[1]==0x01 即命中；缺 Magic Cookie 应拒绝
        assert!(!is_pptp(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    }
    #[test]
    fn test_fp_probe_wrong_magic() {
        // 以 0x00 0x01 开头但 Cookie 错误的载荷，旧判定误报
        assert!(!is_pptp(&[
            0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x00, 0x00
        ]));
    }
}
