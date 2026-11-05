pub fn is_h323(data: &[u8]) -> bool {
    // 误报面审计 2026-11-05：旧判定 `data[0]==0x08` 误报面极大——任意 0x08 开头
    // 的二进制/文本载荷均被认领。改为 H.225.0 呼叫信令两种形态任一：
    // - TPKT 封装（RFC 1006）：data[0..2]==[0x03,0x00]，TPKT 长度（大端 u16）
    //   >=4 且不超载荷实际长度，其后 data[4]==0x08（TPKT+Q.931）；
    // - 裸 Q.931：data[0]==0x08 且 call reference 长度字段 data[1]<=0x02。
    if data.len() >= 8 && data[0] == 0x03 && data[1] == 0x00 {
        let tpkt_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        return tpkt_len >= 4 && tpkt_len <= data.len() && data[4] == 0x08;
    }
    data.len() >= 6 && data[0] == 0x08 && data[1] <= 0x02
}
pub fn detect(d: &[u8]) -> bool {
    is_h323(d)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    // TPKT 形态：tpkt_len=10，其后为 Q.931（protocol discriminator 0x08）
    vec![0x03, 0x00, 0x00, 0x0A, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_match_tpkt() {
        assert!(is_h323(&valid_sample()));
    }
    #[test]
    fn test_match_bare_q931() {
        // 裸 Q.931：CR 长度字段 0x02
        assert!(is_h323(&[0x08, 0x02, 0x00, 0x00, 0x00, 0x00]));
    }
    #[test]
    fn test_not() {
        assert!(!is_h323(b"GET"));
    }
    #[test]
    fn test_short() {
        assert!(!is_h323(&[0x08]));
    }
    // 误报探针：旧判定命中、新判定拒绝
    #[test]
    fn test_fp_probe_bare_too_short() {
        // 旧判定 0x08 开头即命中；长度不足的裸 Q.931 应拒绝
        assert!(!is_h323(&[0x08, 0x00, 0x00, 0x00]));
    }
    #[test]
    fn test_fp_probe_bad_call_reference_len() {
        // 0x08 开头但 call reference 长度字段 0x05 超界，旧判定误报
        assert!(!is_h323(&[0x08, 0x05, 0x00, 0x00, 0x00, 0x00]));
    }
}
