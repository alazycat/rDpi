//! BGP protocol parser — Marker + message type detection

pub fn parse_bgp(data: &[u8]) -> Option<u8> {
    if data.len() < 19 {
        return None;
    }
    if !data[..16].iter().all(|&b| b == 0xff) {
        return None;
    }
    // 误报面审计 2026-11-05：新增 msg_len 自洽校验（RFC 4271 §4.1）——
    // msg_len（大端 data[16..18]）必须 >= 19（16 字节 Marker + 2 字节 Length
    // + 1 字节 Type 的最小报文），且不得超过实际 payload 长度。
    let msg_len = u16::from_be_bytes([data[16], data[17]]) as usize;
    if msg_len < 19 || msg_len > data.len() {
        return None;
    }
    let msg_type = data[18];
    if !(1..=4).contains(&msg_type) {
        return None;
    }
    Some(msg_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn build_bgp(msg_type: u8) -> Vec<u8> {
        let mut p = vec![0xff; 19];
        p[16..18].copy_from_slice(&[0x00, 0x13]); // length
        p[18] = msg_type;
        p
    }
    #[test]
    fn test_open() {
        assert_eq!(parse_bgp(&build_bgp(1)), Some(1));
    }
    #[test]
    fn test_update() {
        assert_eq!(parse_bgp(&build_bgp(2)), Some(2));
    }
    #[test]
    fn test_no_marker() {
        let mut p = build_bgp(1);
        p[0] = 0;
        assert_eq!(parse_bgp(&p), None);
    }
    #[test]
    fn test_too_short() {
        assert_eq!(parse_bgp(&[0u8; 18]), None);
    }
    // ---- 误报面审计 2026-11-05 探针 ----
    #[test]
    fn test_probe_msg_len_below_min() {
        // 旧判定命中（marker 合法、type=1），新判定拒绝：msg_len=18 < 19
        let mut p = build_bgp(1);
        p[16..18].copy_from_slice(&[0x00, 0x12]);
        assert_eq!(parse_bgp(&p), None);
    }
    #[test]
    fn test_probe_msg_len_exceeds_payload() {
        // 旧判定命中，新判定拒绝：msg_len=256 超出 19 字节 payload
        let mut p = build_bgp(1);
        p[16..18].copy_from_slice(&[0x01, 0x00]);
        assert_eq!(parse_bgp(&p), None);
    }
}
