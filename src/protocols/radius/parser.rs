pub fn is_radius(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    let code = data[0];
    // 误报面审计 2026-11-05：删除 data[1]==0x01 约束——packet id 是客户端随机
    // 取值（RFC 2865 §3），固定 id=1 会漏判约 99.6% 真实流量；
    // 改为长度字段自洽：Length（大端 data[2..4]）必须恰好等于 payload 实际长度
    // （RADIUS 报文按 UDP 数据报定界，二者天然一致）。
    let pkt_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    (1..=50).contains(&code) && pkt_len == data.len()
}
pub fn detect(d: &[u8]) -> bool {
    is_radius(d)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    // 误报面审计 2026-11-05：Access-Request，code=1、随机 id、Length=20 与 payload 自洽
    let mut v = vec![0u8; 20];
    v[0] = 1;
    v[1] = 0xC8; // 随机 packet id，非固定 0x01
    v[2] = 0;
    v[3] = 20;
    v
}
#[cfg(test)]
mod tests {
    use super::*;
    fn pkt() -> Vec<u8> {
        let mut v = vec![0u8; 20];
        v[0] = 1;
        v[1] = 1;
        v[2..4].copy_from_slice(&[0, 20]);
        v
    }
    #[test]
    fn test_match() {
        assert!(is_radius(&pkt()));
    }
    #[test]
    fn test_wrong_code() {
        let mut v = pkt();
        v[0] = 0;
        assert!(!is_radius(&v));
    }
    #[test]
    fn test_short() {
        assert!(!is_radius(&[0u8; 19]));
    }
    // ---- 误报面审计 2026-11-05 探针 ----
    #[test]
    fn test_random_id_hit() {
        // 旧判定拒绝（id != 0x01），新判定命中：真实流量的随机 packet id 不再漏判
        let mut v = pkt();
        v[1] = 0xC8;
        assert!(is_radius(&v));
    }
    #[test]
    fn test_probe_length_field_mismatch() {
        // 旧判定命中（code=1 且 id=1），新判定拒绝：Length 字段声明 100，
        // 与 20 字节 payload 不自洽
        let mut v = pkt();
        v[2..4].copy_from_slice(&[0, 100]);
        assert!(!is_radius(&v));
    }
    #[test]
    fn test_probe_length_shorter_than_payload() {
        // 旧判定命中，新判定拒绝：Length 字段小于 payload 实际长度（粘包/截断样本）
        let mut v = pkt();
        v.push(0x00); // 21 字节 payload，Length 仍为 20
        assert!(!is_radius(&v));
    }
}
