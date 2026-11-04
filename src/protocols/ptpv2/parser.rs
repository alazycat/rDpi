//! PTPv2 (IEEE 1588-2008) 公共头检测
//!
//! 头部关键字段：
//!   byte 0   : transportSpecific(高 4 位) | messageType(低 4 位)
//!   byte 1   : versionPTP（低 4 位，应为 2）
//!   bytes 2-3: messageLength（大端；须自洽——不超过实际 payload）
//!
//! F10（risks.md）：旧实现仅校验 version nibble == 2，任何第二字节低位为
//! 0x02 的二进制 payload（如 30 02 02 01）都会被认领。现增加 messageType
//! 合法值与 messageLength 自洽校验。

pub fn is_ptpv2(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let version = data[1] & 0x0f;
    let msg_type = data[0] & 0x0f;
    // 合法 messageType：0x0-0x3 事件类（Sync/Delay_Req/Pdelay_Req/Pdelay_Resp），
    // 0x8-0xD 通用类（Follow_Up/Delay_Resp/Pdelay_Resp_Follow_Up/Announce/Signaling/Management）
    let valid_type = matches!(msg_type, 0x00..=0x03 | 0x08..=0x0D);
    // messageLength 至少覆盖公共头（32 字节，保守下界），且不得超过实际 payload
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    version == 0x02 && valid_type && msg_len >= 32 && msg_len <= data.len()
}
pub fn detect(data: &[u8]) -> bool {
    is_ptpv2(data)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    let mut v = vec![0x00, 0x02, 0x00, 0x2C]; // Sync, version 2, messageLength=44
    v.resize(44, 0x00);
    v
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match() {
        // 真实 Sync 消息形态：type=0、version=2、messageLength=44（≤ payload 长度）
        assert!(is_ptpv2(&valid_sample()));
    }
    #[test]
    fn test_wrong_version() {
        assert!(!is_ptpv2(&[0x00, 0x01, 0x00, 0x00]));
    }
    #[test]
    fn test_short() {
        assert!(!is_ptpv2(&[0x00]));
    }
    /// F10 探针 payload：version nibble 命中但 messageLength=514 > 4 字节实际长度
    #[test]
    fn test_inconsistent_length() {
        assert!(!is_ptpv2(&[0x30, 0x02, 0x02, 0x01]));
    }
    /// messageLength 低于公共头下界
    #[test]
    fn test_length_below_header() {
        assert!(!is_ptpv2(&[0x00, 0x02, 0x00, 0x04, 0x00, 0x00]));
    }
    /// 非法 messageType（0x4-0x7 为保留值）
    #[test]
    fn test_invalid_message_type() {
        assert!(!is_ptpv2(&[0x05, 0x02, 0x00, 0x2C]));
    }
}
