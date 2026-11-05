pub fn is_turn(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let channel = u16::from_be_bytes([data[0], data[1]]);
    // TURN channel: 0x4000-0x7FFE, even only (RFC 5766 §11)
    if !(0x4000..=0x7FFE).contains(&channel) || !channel.is_multiple_of(2) {
        return false;
    }
    // 误报面审计 2026-11-05：新增 RFC 5766 ChannelData 长度自洽校验——
    // msg_len（大端 data[2..4]）必须 >= 1（ChannelData 必携带应用数据），
    // 且 4 字节头 + msg_len 不得超过实际 payload 长度，
    // 拒绝仅有通道号前缀的任意二进制流量（如 QUIC 短头首字节落入 0x40..0x7E 偶数区）。
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    msg_len >= 1 && 4 + msg_len <= data.len()
}
pub fn detect(d: &[u8]) -> bool {
    is_turn(d)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    // 误报面审计 2026-11-05：channel 0x4000 + msg_len=4，携带 4 字节应用数据
    vec![0x40, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_channel() {
        assert!(is_turn(&valid_sample()));
    }
    #[test]
    fn test_not_turn() {
        assert!(!is_turn(b"test"));
    }
    #[test]
    fn test_odd_channel() {
        // 奇数通道号拒绝（RFC 5766 §11 仅允许偶数 channel number）
        assert!(!is_turn(&[0x40, 0x01, 0x00, 0x04]));
    }
    #[test]
    fn test_short() {
        assert!(!is_turn(&[0x40]));
    }
    // ---- 误报面审计 2026-11-05 探针 ----
    #[test]
    fn test_probe_truncated_channel_data() {
        // 旧判定命中（channel 0x4000 偶数），新判定拒绝：msg_len=4 超出 4 字节 payload
        assert!(!is_turn(&[0x40, 0x00, 0x00, 0x04]));
    }
    #[test]
    fn test_probe_zero_msg_len() {
        // 旧判定命中，新判定拒绝：msg_len=0（ChannelData 不允许空数据）
        assert!(!is_turn(&[0x40, 0x00, 0x00, 0x00]));
    }
}
