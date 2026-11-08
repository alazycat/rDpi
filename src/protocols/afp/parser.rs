//! AFP DSI 报文头解析（与 nDPI 5.0 `afp.c` 判定一致）

/// DSI 报文头固定长度
pub const AFP_DSI_HEADER_LEN: usize = 16;
/// 与 nDPI 一致：>128 字节的载荷不单独作为 AFP 定型依据
pub const AFP_MAX_DETECT_LEN: usize = 128;

/// AFP DSI 报文头解析结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AfpParsed {
    pub flags: u8,
    pub command: u8,
    pub request_id: u16,
    pub length: u32,
}

/// 解析 AFP DSI 报文头
///
/// 命中条件（nDPI 5.0 `afp.c`）：
/// - 载荷长度 16..=128；
/// - `flags <= 1`；
/// - `command ∈ 1..=8`；
/// - `reserved == 0`；
/// - 载荷至少包含 `16 + length` 字节。
pub fn parse_afp_dsi(payload: &[u8]) -> Option<AfpParsed> {
    if payload.len() < AFP_DSI_HEADER_LEN || payload.len() > AFP_MAX_DETECT_LEN {
        return None;
    }
    let flags = payload[0];
    if flags > 1 {
        return None;
    }
    let command = payload[1];
    if !(1..=8).contains(&command) {
        return None;
    }
    let request_id = u16::from_be_bytes([payload[2], payload[3]]);
    let length = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let reserved = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
    if reserved != 0 {
        return None;
    }
    let end = AFP_DSI_HEADER_LEN.checked_add(length as usize)?;
    if payload.len() < end {
        return None;
    }
    Some(AfpParsed {
        flags,
        command,
        request_id,
        length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dsi(flags: u8, command: u8, request_id: u16, length: u32, body: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(flags);
        packet.push(command);
        packet.extend_from_slice(&request_id.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(body);
        packet
    }

    #[test]
    fn test_parse_request_header_only() {
        let parsed = parse_afp_dsi(&dsi(0, 1, 1, 0, b"")).unwrap();
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.command, 1);
        assert_eq!(parsed.request_id, 1);
        assert_eq!(parsed.length, 0);
    }

    #[test]
    fn test_parse_response_with_body() {
        let parsed = parse_afp_dsi(&dsi(1, 2, 7, 4, b"body")).unwrap();
        assert_eq!(parsed.flags, 1);
        assert_eq!(parsed.command, 2);
        assert_eq!(parsed.request_id, 7);
        assert_eq!(parsed.length, 4);
    }

    #[test]
    fn test_all_commands_hit() {
        for command in 1..=8u8 {
            assert!(
                parse_afp_dsi(&dsi(0, command, 1, 0, b"")).is_some(),
                "command {command} 应命中"
            );
        }
    }

    #[test]
    fn test_reject_short_payload() {
        assert!(parse_afp_dsi(&[0u8; 15]).is_none());
    }

    #[test]
    fn test_reject_large_payload() {
        let payload = dsi(0, 1, 1, 113, &[0u8; 113]);
        assert_eq!(payload.len(), 129);
        assert!(parse_afp_dsi(&payload).is_none());
    }

    #[test]
    fn test_reject_bad_flags() {
        assert!(parse_afp_dsi(&dsi(2, 1, 1, 0, b"")).is_none());
    }

    #[test]
    fn test_reject_bad_command() {
        assert!(parse_afp_dsi(&dsi(0, 0, 1, 0, b"")).is_none());
        assert!(parse_afp_dsi(&dsi(0, 9, 1, 0, b"")).is_none());
    }

    #[test]
    fn test_reject_nonzero_reserved() {
        let mut payload = dsi(0, 1, 1, 0, b"");
        payload[12] = 1;
        assert!(parse_afp_dsi(&payload).is_none());
    }

    #[test]
    fn test_reject_body_shorter_than_length() {
        assert!(parse_afp_dsi(&dsi(0, 1, 1, 5, b"body")).is_none());
    }
}
