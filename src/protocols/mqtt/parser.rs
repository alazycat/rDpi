//! MQTT protocol parser for rDpi
//!
//! Parses MQTT CONNECT packets for protocol identification.
//!
//! ## Wire Format
//!
//! Fixed Header:
//! - Byte 0: Message Type (4 bits) + Flags (4 bits, CONNECT = 0)
//! - Byte 1+: Remaining Length (Variable Byte Integer)
//!
//! Variable Header (for CONNECT):
//! - Protocol Name (UTF-8 string prefixed with u16 length)
//! - Protocol Level (u8): 3=3.1, 4=3.1.1, 5=5.0
//! - Connect Flags (u8)
//! - Keep Alive (u16)
//!
//! Payload:
//! - Client ID (UTF-8 string)
//! - Will Topic / Will Message (optional)
//! - Username / Password (optional)

use crate::core::types::MqttMetadata;

/// Decode MQTT Variable Byte Integer
///
/// Each byte uses the lower 7 bits for data and bit 7 as a continuation flag.
/// Maximum 4 bytes, max value 268435455.
fn decode_vbi(data: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    let mut multiplier = 1usize;

    for i in 0..4 {
        if i >= data.len() {
            return None;
        }
        let byte = data[i];
        value += (byte as usize & 0x7F) * multiplier;
        if multiplier > 0x200000 {
            return None;
        }
        multiplier *= 128;

        if (byte & 0x80) == 0 {
            return Some((value, i + 1));
        }
    }

    None // exceeds 4 bytes
}

/// Parse a UTF-8 string prefixed with a big-endian u16 length
fn parse_utf8_string(data: &[u8]) -> Option<(&str, usize)> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + len {
        return None;
    }
    let s = std::str::from_utf8(&data[2..2 + len]).ok()?;
    Some((s, 2 + len))
}

/// Parse MQTT CONNECT packet
///
/// Returns `MqttMetadata` if the payload is a valid MQTT CONNECT message.
pub fn parse_mqtt_connect(data: &[u8]) -> Option<MqttMetadata> {
    // Minimum: fixed header (1+1) + name_len(2) + "M"(1) + level(1) + flags(1) + keepalive(2) = 9
    if data.len() < 10 {
        return None;
    }

    // 1. Fixed header: must be CONNECT type (0x10)
    if (data[0] & 0xF0) != 0x10 {
        return None;
    }

    // 2. Decode Remaining Length
    let (_remaining, hdr_size) = decode_vbi(&data[1..])?;
    let total_size = 1 + hdr_size + _remaining;
    if data.len() < total_size {
        return None;
    }

    // 3. Variable header starts after fixed header
    let mut offset = 1 + hdr_size;

    // 4. Protocol Name (UTF-8 string)
    let (protocol_name, consumed) = parse_utf8_string(&data[offset..])?;
    offset += consumed;

    // Validate protocol name
    if protocol_name != "MQTT" && protocol_name != "MQIsdp" {
        return None;
    }

    // 5. Protocol Level
    if offset >= data.len() {
        return None;
    }
    let protocol_level = data[offset];
    if protocol_level != 3 && protocol_level != 4 && protocol_level != 5 {
        return None;
    }
    offset += 1;

    // 6. Connect Flags
    if offset >= data.len() {
        return None;
    }
    let connect_flags = data[offset];
    // Reserved bit (bit 0) must be 0
    if (connect_flags & 0x01) != 0 {
        return None;
    }
    offset += 1;

    // 7. Keep Alive
    if offset + 2 > data.len() {
        return None;
    }
    let keep_alive = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    // 8. MQTT 5.0 has Properties in the variable header
    if protocol_level == 5 {
        let (prop_len, prop_hdr_size) = decode_vbi(&data[offset..])?;
        offset += prop_hdr_size + prop_len;
    }

    // 9. Payload: Client ID (UTF-8 string, first field)
    if offset >= data.len() {
        return None;
    }
    let (client_id_str, consumed) = parse_utf8_string(&data[offset..])?;
    offset += consumed;

    let client_id = if client_id_str.is_empty() {
        None
    } else {
        Some(client_id_str.to_string())
    };

    // 10. Optional: Will Topic & Will Message
    let will_flag = (connect_flags & 0x04) != 0;
    let will_topic = if will_flag {
        if let Some((topic, _consumed)) = parse_utf8_string(&data[offset..]) {
            if !topic.is_empty() {
                Some(topic.to_string())
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    Some(MqttMetadata {
        protocol_name: protocol_name.to_string(),
        protocol_level,
        connect_flags,
        keep_alive,
        client_id,
        will_topic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a raw MQTT CONNECT packet bytes
    fn build_mqtt_connect(protocol_name: &str, protocol_level: u8,
                          clean_session: bool, keep_alive: u16,
                          client_id: &str, will_topic: Option<&str>) -> Vec<u8> {
        let mut packet = Vec::new();

        // Fixed header: CONNECT type, remaining length placeholder
        packet.push(0x10); // CONNECT

        // Build variable header + payload first to compute remaining length
        let mut var_payload = Vec::new();

        // Protocol Name (UTF-8 string)
        let name_bytes = protocol_name.as_bytes();
        var_payload.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        var_payload.extend_from_slice(name_bytes);

        // Protocol Level
        var_payload.push(protocol_level);

        // Connect Flags
        let mut flags = 0u8;
        if clean_session {
            flags |= 0x02; // Clean Session
        }
        if let Some(_) = will_topic {
            flags |= 0x04; // Will Flag
            flags |= 0x08; // Will QoS = 1
        }
        var_payload.push(flags);

        // Keep Alive
        var_payload.extend_from_slice(&keep_alive.to_be_bytes());

        // MQTT 5.0: Properties (empty for testing)
        if protocol_level == 5 {
            var_payload.push(0x00); // Properties Length = 0
        }

        // Client ID (UTF-8 string)
        let cid_bytes = client_id.as_bytes();
        var_payload.extend_from_slice(&(cid_bytes.len() as u16).to_be_bytes());
        var_payload.extend_from_slice(cid_bytes);

        // Will Topic & Message (if will_flag set)
        if let Some(topic) = will_topic {
            let topic_bytes = topic.as_bytes();
            var_payload.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
            var_payload.extend_from_slice(topic_bytes);
            // Will Message (empty)
            var_payload.extend_from_slice(&[0x00, 0x00]);
        }

        // Encode remaining length
        let remaining = var_payload.len();
        if remaining < 128 {
            packet.push(remaining as u8);
        } else if remaining < 16384 {
            packet.push((remaining as u8 & 0x7F) | 0x80);
            packet.push((remaining as u8 >> 7) & 0x7F);
        } else {
            packet.push((remaining as u8 & 0x7F) | 0x80);
            packet.push(((remaining >> 7) as u8 & 0x7F) | 0x80);
            packet.push(((remaining >> 14) as u8) & 0x7F);
        }

        packet.extend_from_slice(&var_payload);
        packet
    }

    #[test]
    fn test_parse_mqtt_connect_v5() {
        let data = build_mqtt_connect("MQTT", 5, true, 60, "device-001", None);
        let meta = parse_mqtt_connect(&data).unwrap();

        assert_eq!(meta.protocol_name, "MQTT");
        assert_eq!(meta.protocol_level, 5);
        assert_eq!(meta.keep_alive, 60);
        assert_eq!(meta.client_id, Some("device-001".to_string()));
        assert!(meta.will_topic.is_none());
    }

    #[test]
    fn test_parse_mqtt_connect_v311() {
        let data = build_mqtt_connect("MQTT", 4, true, 120, "test-client", None);
        let meta = parse_mqtt_connect(&data).unwrap();

        assert_eq!(meta.protocol_name, "MQTT");
        assert_eq!(meta.protocol_level, 4);
        assert_eq!(meta.keep_alive, 120);
        assert_eq!(meta.client_id, Some("test-client".to_string()));
    }

    #[test]
    fn test_parse_mqtt_connect_v31() {
        let data = build_mqtt_connect("MQIsdp", 3, true, 30, "mqtt31-device", None);
        let meta = parse_mqtt_connect(&data).unwrap();

        assert_eq!(meta.protocol_name, "MQIsdp");
        assert_eq!(meta.protocol_level, 3);
        assert_eq!(meta.client_id, Some("mqtt31-device".to_string()));
    }

    #[test]
    fn test_parse_mqtt_connect_empty_clientid() {
        let data = build_mqtt_connect("MQTT", 4, true, 60, "", None);
        let meta = parse_mqtt_connect(&data).unwrap();

        assert!(meta.client_id.is_none());
    }

    #[test]
    fn test_parse_mqtt_connect_with_will() {
        let data = build_mqtt_connect("MQTT", 4, true, 60, "device-001", Some("sensor/temp"));
        let meta = parse_mqtt_connect(&data).unwrap();

        assert_eq!(meta.protocol_name, "MQTT");
        assert_eq!(meta.client_id, Some("device-001".to_string()));
        assert_eq!(meta.will_topic, Some("sensor/temp".to_string()));
    }

    #[test]
    fn test_parse_mqtt_invalid_type() {
        // PUBLISH type (0x30), not CONNECT
        let mut data = build_mqtt_connect("MQTT", 4, true, 60, "test", None);
        data[0] = 0x30;
        assert!(parse_mqtt_connect(&data).is_none());
    }

    #[test]
    fn test_parse_mqtt_truncated() {
        assert!(parse_mqtt_connect(&[]).is_none());
        assert!(parse_mqtt_connect(&[0x10]).is_none());
        assert!(parse_mqtt_connect(&[0x10, 0x05]).is_none());
    }

    #[test]
    fn test_parse_mqtt_invalid_protocol_name() {
        // Invalid protocol name
        let mut data = build_mqtt_connect("MQTT", 4, true, 60, "test", None);
        // Overwrite protocol name bytes
        let name_offset = 2; // after fixed header (type + remaining len)
        let name_len = 4;
        data[name_offset] = 0x00;
        data[name_offset + 1] = 0x04;
        data[name_offset + 2..name_offset + 2 + name_len].copy_from_slice(b"HTTP");
        assert!(parse_mqtt_connect(&data).is_none());
    }

    #[test]
    fn test_parse_mqtt_invalid_level() {
        let mut data = build_mqtt_connect("MQTT", 4, true, 60, "test", None);
        // Find and corrupt the protocol level byte
        // After: type(1) + remaining_len(1) + name_len(2) + "MQTT"(4) = offset 8
        // Level is at offset 8
        if data.len() > 8 {
            data[8] = 0xFF; // invalid level
        }
        assert!(parse_mqtt_connect(&data).is_none());
    }

    #[test]
    fn test_decode_vbi_single_byte() {
        assert_eq!(decode_vbi(&[0x00]), Some((0, 1)));
        assert_eq!(decode_vbi(&[0x7F]), Some((127, 1)));
    }

    #[test]
    fn test_decode_vbi_multi_byte() {
        assert_eq!(decode_vbi(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(decode_vbi(&[0x80, 0x80, 0x01]), Some((16384, 3)));
    }
}
