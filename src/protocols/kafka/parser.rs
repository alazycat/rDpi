//! Kafka 请求头解析（与 nDPI 5.0 `kafka.c` 判定一致）

const KAFKA_MIN_LEN: usize = 8;
const KAFKA_MIN_REQUEST_LEN: usize = 14;
const KAFKA_MAX_API_KEY: u16 = 75;
const KAFKA_MAX_API_VERSION: u16 = 16;

/// Kafka 请求头解析结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaParsed {
    pub api_key: u16,
    pub api_version: u16,
    pub correlation_id: u32,
    pub client_id: String,
}

/// 解析 Kafka 请求头
///
/// 命中条件（nDPI 5.0 `kafka.c`）：
/// - 载荷长度 ≥ 8；
/// - BE u32 长度前缀等于载荷长度减 4；
/// - `api_key < 75`、`api_version < 16`、载荷长度 ≥ 14；
/// - `client_id_len + 14 <= payload.len()`；
/// - client_id 全部为可打印 ASCII（0x20..=0x7e）。
pub fn parse_kafka_request(payload: &[u8]) -> Option<KafkaParsed> {
    if payload.len() < KAFKA_MIN_LEN {
        return None;
    }
    let declared = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if declared != payload.len() - 4 {
        return None;
    }
    let api_key = u16::from_be_bytes([payload[4], payload[5]]);
    let api_version = u16::from_be_bytes([payload[6], payload[7]]);
    if api_key >= KAFKA_MAX_API_KEY || api_version >= KAFKA_MAX_API_VERSION {
        return None;
    }
    if payload.len() < KAFKA_MIN_REQUEST_LEN {
        return None;
    }
    let client_id_len = u16::from_be_bytes([payload[12], payload[13]]) as usize;
    let end = KAFKA_MIN_REQUEST_LEN.checked_add(client_id_len)?;
    if end > payload.len() {
        return None;
    }
    let client_id_bytes = &payload[KAFKA_MIN_REQUEST_LEN..end];
    if !client_id_bytes.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        return None;
    }
    let correlation_id = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    Some(KafkaParsed {
        api_key,
        api_version,
        correlation_id,
        client_id: String::from_utf8_lossy(client_id_bytes).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(api_key: u16, api_version: u16, correlation_id: u32, client_id: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&api_key.to_be_bytes());
        body.extend_from_slice(&api_version.to_be_bytes());
        body.extend_from_slice(&correlation_id.to_be_bytes());
        body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        body.extend_from_slice(client_id);
        let mut payload = (body.len() as u32).to_be_bytes().to_vec();
        payload.extend_from_slice(&body);
        payload
    }

    #[test]
    fn test_parse_request() {
        let parsed = parse_kafka_request(&request(3, 1, 42, b"rdpi-test")).unwrap();
        assert_eq!(parsed.api_key, 3);
        assert_eq!(parsed.api_version, 1);
        assert_eq!(parsed.correlation_id, 42);
        assert_eq!(parsed.client_id, "rdpi-test");
    }

    #[test]
    fn test_parse_empty_client_id() {
        assert!(parse_kafka_request(&request(0, 0, 1, b"")).is_some());
    }

    #[test]
    fn test_reject_length_mismatch() {
        let mut payload = request(3, 1, 1, b"rdpi");
        payload[0..4].copy_from_slice(&999u32.to_be_bytes());
        assert!(parse_kafka_request(&payload).is_none());
    }

    #[test]
    fn test_reject_api_key_too_large() {
        assert!(parse_kafka_request(&request(75, 1, 1, b"rdpi")).is_none());
    }

    #[test]
    fn test_reject_api_version_too_large() {
        assert!(parse_kafka_request(&request(3, 16, 1, b"rdpi")).is_none());
    }

    #[test]
    fn test_reject_client_id_overflow() {
        let mut payload = request(3, 1, 1, b"rdpi");
        payload[12..14].copy_from_slice(&1000u16.to_be_bytes());
        assert!(parse_kafka_request(&payload).is_none());
    }

    #[test]
    fn test_reject_non_printable_client_id() {
        assert!(parse_kafka_request(&request(3, 1, 1, b"rd\x1fpi")).is_none());
        assert!(parse_kafka_request(&request(3, 1, 1, b"rd\x7fpi")).is_none());
    }

    #[test]
    fn test_reject_short_payload() {
        assert!(parse_kafka_request(&[0u8; 7]).is_none());
    }
}
