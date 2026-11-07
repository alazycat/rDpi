//! AMQP 0-9-1 帧头与 1.0 协议头解析（与 nDPI 5.0 `amqp.c` 判定一致）

/// 0-9-1 协议头
pub const AMQP_091_PROTOCOL_HEADER: &[u8] = b"AMQP\x00\x00\x09\x01";
/// 1.0 协议头
pub const AMQP_10_PROTOCOL_HEADER: &[u8] = b"AMQP\x00\x01\x00\x00";

const AMQP_FRAME_HEADER_LEN: usize = 11;
const AMQP_MAX_FRAME_LEN: u32 = 32768;
const AMQP_CLASS_MIN: u16 = 10;
const AMQP_CLASS_MAX: u16 = 110;
const AMQP_METHOD_MAX: u16 = 120;

/// AMQP 解析结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmqpParsed {
    pub version: &'static str,
    pub frame_type: Option<u8>,
    pub channel: Option<u16>,
    pub class_id: Option<u16>,
    pub method: Option<u16>,
}

/// 解析 AMQP 协议头或 0-9-1 帧头
pub fn parse_amqp(payload: &[u8]) -> Option<AmqpParsed> {
    if payload.starts_with(AMQP_091_PROTOCOL_HEADER) {
        return Some(AmqpParsed {
            version: "0-9-1",
            frame_type: None,
            channel: None,
            class_id: None,
            method: None,
        });
    }
    if payload.starts_with(AMQP_10_PROTOCOL_HEADER) {
        return Some(AmqpParsed {
            version: "1.0",
            frame_type: None,
            channel: None,
            class_id: None,
            method: None,
        });
    }
    if payload.len() <= AMQP_FRAME_HEADER_LEN {
        return None;
    }
    let frame_type = payload[0];
    if frame_type > 3 {
        return None;
    }
    let length = u32::from_be_bytes([payload[3], payload[4], payload[5], payload[6]]);
    if length >= AMQP_MAX_FRAME_LEN || length as usize + 8 < payload.len() {
        return None;
    }
    let class_id = u16::from_be_bytes([payload[7], payload[8]]);
    if !(AMQP_CLASS_MIN..=AMQP_CLASS_MAX).contains(&class_id) {
        return None;
    }
    let method = u16::from_be_bytes([payload[9], payload[10]]);
    if method > AMQP_METHOD_MAX {
        return None;
    }
    Some(AmqpParsed {
        version: "0-9-1",
        frame_type: Some(frame_type),
        channel: Some(u16::from_be_bytes([payload[1], payload[2]])),
        class_id: Some(class_id),
        method: Some(method),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method_frame(method: u16) -> Vec<u8> {
        vec![
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x04,
            0x00,
            0x0A,
            (method >> 8) as u8,
            method as u8,
            0xCE,
        ]
    }

    #[test]
    fn test_valid_method_frame() {
        let parsed = parse_amqp(&method_frame(10)).expect("frame should match");
        assert_eq!(parsed.version, "0-9-1");
        assert_eq!(parsed.frame_type, Some(1));
        assert_eq!(parsed.channel, Some(0));
        assert_eq!(parsed.class_id, Some(10));
        assert_eq!(parsed.method, Some(10));
    }

    #[test]
    fn test_protocol_headers() {
        let parsed = parse_amqp(b"AMQP\x00\x00\x09\x01").expect("0-9-1 header");
        assert_eq!(parsed.version, "0-9-1");
        assert_eq!(parsed.frame_type, None);
        assert_eq!(parsed.channel, None);
        assert_eq!(parsed.class_id, None);
        assert_eq!(parsed.method, None);

        let parsed = parse_amqp(b"AMQP\x00\x01\x00\x00").expect("1.0 header");
        assert_eq!(parsed.version, "1.0");
        assert_eq!(parsed.frame_type, None);
    }

    #[test]
    fn test_rejects_bad_frame_type() {
        let mut payload = method_frame(10);
        payload[0] = 0x04;
        assert!(parse_amqp(&payload).is_none());
    }

    #[test]
    fn test_rejects_bad_class() {
        let mut payload = method_frame(10);
        payload[7] = 0x00;
        payload[8] = 0x09;
        assert!(parse_amqp(&payload).is_none());

        let mut payload = method_frame(10);
        payload[7] = 0x00;
        payload[8] = 0x6F;
        assert!(parse_amqp(&payload).is_none());
    }

    #[test]
    fn test_rejects_bad_method() {
        let mut payload = method_frame(121);
        payload[9] = 0x00;
        payload[10] = 0x79;
        assert!(parse_amqp(&payload).is_none());
    }

    #[test]
    fn test_rejects_large_frame_length() {
        let mut payload = method_frame(10);
        payload[3..7].copy_from_slice(&32768u32.to_be_bytes());
        assert!(parse_amqp(&payload).is_none());
    }

    #[test]
    fn test_rejects_payload_longer_than_frame() {
        let mut payload = method_frame(10);
        payload.extend_from_slice(&[0u8; 16]);
        assert!(parse_amqp(&payload).is_none());
    }

    #[test]
    fn test_rejects_short_payload() {
        let payload = method_frame(10);
        assert!(parse_amqp(&payload[..11]).is_none());
    }
}
