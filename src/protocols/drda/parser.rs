//! DRDA 消息头解析（与 nDPI 5.0 `drda.c` 判定一致）

/// DSS/DDM 消息头固定长度
pub const DRDA_HEADER_LEN: usize = 10;
/// DSS 魔数
pub const DRDA_MAGIC: u8 = 0xD0;

/// DRDA 载荷解析结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrdaParsed {
    /// 本载荷中的消息数
    pub message_count: u16,
    /// 首条消息的总长度
    pub message_length: u16,
}

/// 解析 DRDA 载荷（单条或多条严格串联消息）
///
/// 每条消息头（10 字节，网络序）：
/// - `length == length2 + 6`；
/// - `length >= 10`；
/// - `magic == 0xD0`；
/// - 消息长度不得超出载荷；所有消息必须精确消费完载荷。
pub fn parse_drda(payload: &[u8]) -> Option<DrdaParsed> {
    if payload.len() < DRDA_HEADER_LEN {
        return None;
    }
    let mut offset = 0usize;
    let mut message_count = 0u16;
    let mut first_length = 0u16;
    while offset < payload.len() {
        if payload.len() - offset < DRDA_HEADER_LEN {
            return None;
        }
        let length = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let length2 = u16::from_be_bytes([payload[offset + 6], payload[offset + 7]]);
        if payload[offset + 2] != DRDA_MAGIC
            || (length as usize) < DRDA_HEADER_LEN
            || length as usize != length2 as usize + 6
        {
            return None;
        }
        let end = offset.checked_add(length as usize)?;
        if end > payload.len() {
            return None;
        }
        if message_count == 0 {
            first_length = length;
        }
        message_count = message_count.saturating_add(1);
        offset = end;
    }
    Some(DrdaParsed {
        message_count,
        message_length: first_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(length2: u16, body: &[u8]) -> Vec<u8> {
        let length = length2 + 6;
        let mut message = Vec::new();
        message.extend_from_slice(&length.to_be_bytes());
        message.push(DRDA_MAGIC);
        message.push(0x41);
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&length2.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(body);
        message
    }

    #[test]
    fn test_parse_single_message() {
        let payload = message(10, &[0u8; 6]);
        assert_eq!(payload.len(), 16);
        let parsed = parse_drda(&payload).unwrap();
        assert_eq!(parsed.message_count, 1);
        assert_eq!(parsed.message_length, 16);
    }

    #[test]
    fn test_parse_two_messages() {
        let mut payload = message(10, &[0u8; 6]);
        payload.extend_from_slice(&message(10, &[0u8; 6]));
        let parsed = parse_drda(&payload).unwrap();
        assert_eq!(parsed.message_count, 2);
        assert_eq!(parsed.message_length, 16);
    }

    #[test]
    fn test_reject_short_payload() {
        assert!(parse_drda(&[0u8; 9]).is_none());
    }

    #[test]
    fn test_reject_wrong_magic() {
        let mut payload = message(10, &[0u8; 6]);
        payload[2] = 0xD1;
        assert!(parse_drda(&payload).is_none());
    }

    #[test]
    fn test_reject_length_mismatch() {
        let mut payload = message(10, &[0u8; 6]);
        payload[0..2].copy_from_slice(&17u16.to_be_bytes());
        assert!(parse_drda(&payload).is_none());
    }

    #[test]
    fn test_reject_too_short_message() {
        // length=9, length2=3 -> 3+6=9，但 length < 10
        let mut payload = Vec::new();
        payload.extend_from_slice(&9u16.to_be_bytes());
        payload.push(DRDA_MAGIC);
        payload.push(0x41);
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&3u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(payload.len(), 10);
        assert!(parse_drda(&payload).is_none());
    }

    #[test]
    fn test_reject_declared_length_beyond_payload() {
        let mut payload = message(10, &[0u8; 6]);
        payload.truncate(12);
        assert!(parse_drda(&payload).is_none());
    }

    #[test]
    fn test_reject_trailing_partial_header() {
        let mut payload = message(10, &[0u8; 6]);
        payload.extend_from_slice(&[0u8; 5]);
        assert!(parse_drda(&payload).is_none());
    }

    #[test]
    fn test_reject_second_message_bad_magic() {
        let mut payload = message(10, &[0u8; 6]);
        let mut second = message(10, &[0u8; 6]);
        second[2] = 0x00;
        payload.extend_from_slice(&second);
        assert!(parse_drda(&payload).is_none());
    }
}
