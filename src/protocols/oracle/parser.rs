//! Oracle TNS Connect 报文头解析（与 nDPI 5.0 `oracle.c` 判定一致）

/// TNS Connect 报文头固定长度
pub const ORACLE_CONNECT_HEADER_LEN: usize = 8;

/// TNS Connect 报文头解析结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleParsed {
    /// TNS 包长度（命中时等于载荷长度）
    pub packet_length: u16,
    /// TNS 包类型（1 = Connect）
    pub packet_type: u8,
}

/// 解析 TNS Connect 报文头
///
/// 命中条件（nDPI 5.0 `oracle.c`）：
/// - 载荷长度 ≥ 8；
/// - `packet_length` 等于载荷总长度；
/// - 包校验和、保留字段、头校验和均为 0；
/// - 包类型为 1（Connect）。
pub fn parse_oracle_connect(payload: &[u8]) -> Option<OracleParsed> {
    if payload.len() < ORACLE_CONNECT_HEADER_LEN {
        return None;
    }
    let packet_length = u16::from_be_bytes([payload[0], payload[1]]);
    if packet_length as usize != payload.len() {
        return None;
    }
    if payload[2] != 0 || payload[3] != 0 {
        return None;
    }
    if payload[4] != 0x01 {
        return None;
    }
    if payload[5] != 0 || payload[6] != 0 || payload[7] != 0 {
        return None;
    }
    Some(OracleParsed {
        packet_length,
        packet_type: payload[4],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect(body: &[u8]) -> Vec<u8> {
        let total = (ORACLE_CONNECT_HEADER_LEN + body.len()) as u16;
        let mut packet = Vec::new();
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.push(0x01);
        packet.push(0x00);
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(body);
        packet
    }

    #[test]
    fn test_parse_connect_header_only() {
        let parsed = parse_oracle_connect(&connect(b"")).unwrap();
        assert_eq!(parsed.packet_length, 8);
        assert_eq!(parsed.packet_type, 1);
    }

    #[test]
    fn test_parse_connect_with_body() {
        let parsed = parse_oracle_connect(&connect(b"\x01\x02\x03\x04")).unwrap();
        assert_eq!(parsed.packet_length, 12);
    }

    #[test]
    fn test_reject_short_payload() {
        assert!(parse_oracle_connect(&[0x00, 0x08, 0x00]).is_none());
    }

    #[test]
    fn test_reject_length_mismatch() {
        let mut payload = connect(b"");
        payload[0..2].copy_from_slice(&9u16.to_be_bytes());
        assert!(parse_oracle_connect(&payload).is_none());
    }

    #[test]
    fn test_reject_nonzero_packet_checksum() {
        let mut payload = connect(b"");
        payload[2] = 1;
        assert!(parse_oracle_connect(&payload).is_none());
    }

    #[test]
    fn test_reject_non_connect_type() {
        let mut payload = connect(b"");
        payload[4] = 2;
        assert!(parse_oracle_connect(&payload).is_none());
    }

    #[test]
    fn test_reject_nonzero_reserved() {
        let mut payload = connect(b"");
        payload[5] = 1;
        assert!(parse_oracle_connect(&payload).is_none());
    }

    #[test]
    fn test_reject_nonzero_header_checksum() {
        let mut payload = connect(b"");
        payload[7] = 1;
        assert!(parse_oracle_connect(&payload).is_none());
    }
}
