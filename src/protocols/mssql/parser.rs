//! MSSQL/TDS 报文头解析（与 nDPI 5.0 `mssql_tds.c` 判定一致）

/// TDS 报文头固定长度
pub const MSSQL_TDS_HEADER_LEN: usize = 8;

/// TDS 报文头解析结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MssqlParsed {
    pub packet_type: u8,
    pub status: u8,
    pub length: u16,
    pub channel: u16,
    pub packet_id: u8,
}

/// 解析 TDS 报文头
///
/// 命中条件（nDPI 5.0 `mssql_tds.c`）：
/// - 载荷长度 ≥ 8；
/// - `length` 字段等于载荷总长度；
/// - `window` 字段为 0；
/// - 类型 1..=8 时 `packet_id > 0`，或类型 14..=18；
/// - status ∈ {0x00,0x01,0x02,0x04,0x08,0x09,0x10}。
pub fn parse_mssql_tds(payload: &[u8]) -> Option<MssqlParsed> {
    if payload.len() < MSSQL_TDS_HEADER_LEN {
        return None;
    }
    let packet_type = payload[0];
    let status = payload[1];
    let length = u16::from_be_bytes([payload[2], payload[3]]);
    let channel = u16::from_be_bytes([payload[4], payload[5]]);
    let packet_id = payload[6];
    let window = payload[7];

    if length as usize != payload.len() || window != 0 {
        return None;
    }
    let type_ok =
        (packet_id > 0 && (1..=8).contains(&packet_type)) || (14..=18).contains(&packet_type);
    let status_ok = matches!(status, 0x00 | 0x01 | 0x02 | 0x04 | 0x08 | 0x09 | 0x10);
    if !type_ok || !status_ok {
        return None;
    }
    Some(MssqlParsed {
        packet_type,
        status,
        length,
        channel,
        packet_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tds(packet_type: u8, status: u8, packet_id: u8, window: u8, body: &[u8]) -> Vec<u8> {
        let total = (MSSQL_TDS_HEADER_LEN + body.len()) as u16;
        let mut packet = vec![packet_type, status];
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.push(packet_id);
        packet.push(window);
        packet.extend_from_slice(body);
        packet
    }

    #[test]
    fn test_parse_prelogin() {
        let parsed = parse_mssql_tds(&tds(0x12, 0x01, 1, 0, b"body")).unwrap();
        assert_eq!(parsed.packet_type, 0x12);
        assert_eq!(parsed.status, 0x01);
        assert_eq!(parsed.length, 12);
        assert_eq!(parsed.channel, 0);
        assert_eq!(parsed.packet_id, 1);
    }

    #[test]
    fn test_reject_sql_batch_with_zero_packet_id() {
        assert!(parse_mssql_tds(&tds(1, 0x01, 0, 0, b"body")).is_none());
    }

    #[test]
    fn test_reject_unknown_type() {
        for packet_type in [0u8, 9, 13, 19] {
            assert!(parse_mssql_tds(&tds(packet_type, 0x01, 1, 0, b"body")).is_none());
        }
    }

    #[test]
    fn test_reject_bad_status() {
        for status in [0x03u8, 0x05, 0x20, 0xff] {
            assert!(parse_mssql_tds(&tds(1, status, 1, 0, b"body")).is_none());
        }
    }

    #[test]
    fn test_reject_length_mismatch() {
        let mut payload = tds(1, 0x01, 1, 0, b"body");
        payload[2..4].copy_from_slice(&9u16.to_be_bytes());
        assert!(parse_mssql_tds(&payload).is_none());
    }

    #[test]
    fn test_reject_nonzero_window() {
        assert!(parse_mssql_tds(&tds(1, 0x01, 1, 1, b"body")).is_none());
    }

    #[test]
    fn test_reject_short_payload() {
        assert!(parse_mssql_tds(&[0x12, 0x01, 0x00]).is_none());
    }
}
