//! Cassandra CQL 解析（internode magic + STARTUP 帧）

/// internode 通信 magic
pub const CASSANDRA_INTERNODE_MAGIC: u32 = 0xCA55_2DFA;
/// internode 通信报文长度
pub const CASSANDRA_INTERNODE_LEN: usize = 19;
/// CQL 请求头固定长度
pub const CQL_STARTUP_HEADER_LEN: usize = 9;
/// STARTUP opcode
pub const CQL_OPCODE_STARTUP: u8 = 0x01;
/// string map 条目数上限
const CQL_MAX_MAP_ENTRIES: usize = 64;

/// Cassandra 解析结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CassandraParsed {
    /// internode 握手 magic
    Internode,
    /// CQL STARTUP 帧
    Cql(CassandraStartupParsed),
}

/// CQL STARTUP 帧解析结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CassandraStartupParsed {
    pub version: u8,
    pub stream_id: u16,
    pub opcode: u8,
    pub cql_version: String,
}

/// 解析 Cassandra 载荷：先尝试 internode magic，再尝试 CQL STARTUP
pub fn parse_cassandra(payload: &[u8]) -> Option<CassandraParsed> {
    if payload.len() == CASSANDRA_INTERNODE_LEN
        && u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
            == CASSANDRA_INTERNODE_MAGIC
    {
        return Some(CassandraParsed::Internode);
    }
    parse_cassandra_startup(payload).map(CassandraParsed::Cql)
}

/// 解析 CQL STARTUP 帧
///
/// 命中条件：
/// - 版本 0x02..=0x05（请求方向）；
/// - flags 仅低 5 位有定义；
/// - opcode 为 STARTUP（0x01）；
/// - 长度字段精确等于 `payload.len() - 9`；
/// - body 是完整 string map（条目数 1..=64，恰好消费完），且包含 `CQL_VERSION`。
pub fn parse_cassandra_startup(payload: &[u8]) -> Option<CassandraStartupParsed> {
    if payload.len() < CQL_STARTUP_HEADER_LEN {
        return None;
    }
    let version = payload[0];
    if !(0x02..=0x05).contains(&version) {
        return None;
    }
    if payload[1] & 0xE0 != 0 {
        return None;
    }
    let stream_id = u16::from_be_bytes([payload[2], payload[3]]);
    let opcode = payload[4];
    if opcode != CQL_OPCODE_STARTUP {
        return None;
    }
    let body_len = u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]) as usize;
    if body_len != payload.len() - CQL_STARTUP_HEADER_LEN {
        return None;
    }
    let cql_version = parse_cql_version(&payload[CQL_STARTUP_HEADER_LEN..])?;
    Some(CassandraStartupParsed {
        version,
        stream_id,
        opcode,
        cql_version,
    })
}

fn parse_cql_version(body: &[u8]) -> Option<String> {
    let mut offset = 0usize;
    let count = read_u16(body, &mut offset)? as usize;
    if count == 0 || count > CQL_MAX_MAP_ENTRIES {
        return None;
    }
    let mut cql_version = None;
    for _ in 0..count {
        let key_len = read_u16(body, &mut offset)? as usize;
        let key_end = offset.checked_add(key_len)?;
        let key = body.get(offset..key_end)?;
        offset = key_end;
        if !key.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            return None;
        }
        let value_len = read_u16(body, &mut offset)? as usize;
        let value_end = offset.checked_add(value_len)?;
        let value = body.get(offset..value_end)?;
        offset = value_end;
        if key == b"CQL_VERSION".as_slice() {
            if !value.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
                return None;
            }
            cql_version = Some(String::from_utf8_lossy(value).into_owned());
        }
    }
    if offset != body.len() {
        return None;
    }
    cql_version
}

fn read_u16(buffer: &[u8], offset: &mut usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = buffer.get(*offset..end)?;
    *offset = end;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn internode() -> Vec<u8> {
        let mut payload = CASSANDRA_INTERNODE_MAGIC.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0u8; 15]);
        payload
    }

    fn startup(version: u8, cql_version: &str, extra: &[(&str, &str)]) -> Vec<u8> {
        let mut entries: Vec<(&str, &str)> = vec![("CQL_VERSION", cql_version)];
        entries.extend_from_slice(extra);
        let mut body = Vec::new();
        body.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for (key, value) in entries {
            body.extend_from_slice(&(key.len() as u16).to_be_bytes());
            body.extend_from_slice(key.as_bytes());
            body.extend_from_slice(&(value.len() as u16).to_be_bytes());
            body.extend_from_slice(value.as_bytes());
        }
        let mut frame = vec![version, 0x00, 0x00, 0x01, CQL_OPCODE_STARTUP];
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    #[test]
    fn test_internode_magic() {
        assert_eq!(
            parse_cassandra(&internode()),
            Some(CassandraParsed::Internode)
        );
    }

    #[test]
    fn test_reject_internode_wrong_length() {
        let mut payload = internode();
        payload.pop();
        assert!(parse_cassandra(&payload).is_none());
        payload.extend_from_slice(&[0, 0]);
        assert!(parse_cassandra(&payload).is_none());
    }

    #[test]
    fn test_reject_internode_wrong_magic() {
        let mut payload = internode();
        payload[0] = 0;
        assert!(parse_cassandra(&payload).is_none());
    }

    #[test]
    fn test_startup_v4() {
        let parsed = parse_cassandra_startup(&startup(0x04, "3.0.0", &[])).unwrap();
        assert_eq!(parsed.version, 0x04);
        assert_eq!(parsed.stream_id, 1);
        assert_eq!(parsed.opcode, CQL_OPCODE_STARTUP);
        assert_eq!(parsed.cql_version, "3.0.0");
    }

    #[test]
    fn test_startup_versions_v2_to_v5() {
        for version in [0x02u8, 0x03, 0x04, 0x05] {
            assert!(
                parse_cassandra_startup(&startup(version, "3.0.0", &[])).is_some(),
                "version 0x{version:02X} 应命中"
            );
        }
    }

    #[test]
    fn test_startup_multiple_entries() {
        let parsed = parse_cassandra_startup(&startup(
            0x04,
            "3.4.5",
            &[("DRIVER_NAME", "DataStax"), ("DRIVER_VERSION", "1.0")],
        ))
        .unwrap();
        assert_eq!(parsed.cql_version, "3.4.5");
    }

    #[test]
    fn test_reject_missing_cql_version() {
        let body = {
            let mut body = Vec::new();
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&9u16.to_be_bytes());
            body.extend_from_slice(b"COMPRESS");
            body.extend_from_slice(&0u16.to_be_bytes());
            body
        };
        let mut frame = vec![0x04, 0x00, 0x00, 0x01, CQL_OPCODE_STARTUP];
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_truncated_map() {
        let mut frame = startup(0x04, "3.0.0", &[]);
        frame.pop();
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_zero_entries() {
        let mut frame = vec![0x04, 0x00, 0x00, 0x01, CQL_OPCODE_STARTUP];
        frame.extend_from_slice(&2u32.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_non_printable_key() {
        let body = {
            let mut body = Vec::new();
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&2u16.to_be_bytes());
            body.extend_from_slice(&[0x01, 0x02]);
            body.extend_from_slice(&2u16.to_be_bytes());
            body.extend_from_slice(b"v1");
            body
        };
        let mut frame = vec![0x04, 0x00, 0x00, 0x01, CQL_OPCODE_STARTUP];
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_non_printable_cql_version_value() {
        let body = {
            let mut body = Vec::new();
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&11u16.to_be_bytes());
            body.extend_from_slice(b"CQL_VERSION");
            body.extend_from_slice(&2u16.to_be_bytes());
            body.extend_from_slice(&[0x01, 0x02]);
            body
        };
        let mut frame = vec![0x04, 0x00, 0x00, 0x01, CQL_OPCODE_STARTUP];
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_non_startup_opcode() {
        let mut frame = startup(0x04, "3.0.0", &[]);
        frame[4] = 0x05;
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_invalid_versions() {
        for version in [0x01u8, 0x06, 0x80, 0x83] {
            assert!(
                parse_cassandra_startup(&startup(version, "3.0.0", &[])).is_none(),
                "version 0x{version:02X} 应拒绝"
            );
        }
    }

    #[test]
    fn test_reject_length_mismatch() {
        let mut frame = startup(0x04, "3.0.0", &[]);
        frame.extend_from_slice(&[0x00]);
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_invalid_flags() {
        let mut frame = startup(0x04, "3.0.0", &[]);
        frame[1] = 0x20;
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_short_payload() {
        assert!(parse_cassandra_startup(&[0x04, 0x00, 0x00]).is_none());
    }

    #[test]
    fn test_parse_cassandra_prefers_startup() {
        let parsed = parse_cassandra(&startup(0x04, "3.0.0", &[])).unwrap();
        assert!(matches!(parsed, CassandraParsed::Cql(_)));
    }
}
