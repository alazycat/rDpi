//! SNMP protocol parser for rDpi
//!
//! Parses SNMP v1/v2c packets and extracts metadata.

use crate::asn1::{BerReader, Asn1Value, Asn1Class};
use crate::core::types::*;

/// Parse SNMP message (v1 or v2c)
pub fn parse_snmp_message(data: &[u8]) -> Option<SnmpMetadata> {
    if data.len() < 8 {
        return None;
    }

    let mut reader = BerReader::new(data);

    // SNMP message is a SEQUENCE
    let (tag, seq_bytes) = reader.decode_tlv()?;
    if tag.class != Asn1Class::Universal || tag.number != 0x10 {
        return None;
    }

    // Create sub-reader for the sequence content
    let mut seq_reader = BerReader::new(seq_bytes);

    // Version: INTEGER
    let version_val = seq_reader.decode_value()?;
    let version_int = match version_val {
        Asn1Value::Integer(v) => v as i32,
        _ => return None,
    };

    let version = match version_int {
        0 => SnmpVersion::V1,
        1 => SnmpVersion::V2c,
        _ => return None,
    };

    // Community: OCTET STRING
    let community_val = seq_reader.decode_value()?;
    let community = match community_val {
        Asn1Value::OctetString(ref bytes) => String::from_utf8_lossy(bytes).to_string(),
        _ => return None,
    };

    // PDU: context-specific constructed
    let (pdu_tag, pdu_bytes) = seq_reader.decode_tlv()?;
    if pdu_tag.class != Asn1Class::ContextSpecific || !pdu_tag.constructed {
        return None;
    }

    let pdu_type = parse_pdu_type(pdu_tag.number)?;

    // Parse PDU content
    let pdu_result = if pdu_type == SnmpPduType::Trap && version == SnmpVersion::V1 {
        parse_trap_pdu(pdu_bytes)?
    } else {
        parse_standard_pdu(pdu_type, pdu_bytes)?
    };

    Some(SnmpMetadata {
        version,
        community,
        pdu_type: pdu_result.pdu_type,
        request_id: pdu_result.request_id,
        error_status: pdu_result.error_status,
        error_index: pdu_result.error_index,
        varbinds: pdu_result.varbinds,
        trap_info: pdu_result.trap_info,
    })
}

/// PDU parse result
struct PduParseResult {
    pdu_type: SnmpPduType,
    request_id: i32,
    error_status: u8,
    error_index: u8,
    varbinds: Vec<SnmpVarBind>,
    trap_info: Option<SnmpTrapInfo>,
}

/// Parse standard PDU (GetRequest, GetNext, GetResponse, SetRequest, GetBulk, Inform, TrapV2)
fn parse_standard_pdu(pdu_type: SnmpPduType, data: &[u8]) -> Option<PduParseResult> {
    let mut reader = BerReader::new(data);

    // Request ID: INTEGER
    let request_id = match reader.decode_value()? {
        Asn1Value::Integer(v) => v as i32,
        _ => return None,
    };

    // Error status / Non-repeaters: INTEGER
    let error_status = match reader.decode_value()? {
        Asn1Value::Integer(v) => v as u8,
        _ => return None,
    };

    // Error index / Max-repetitions: INTEGER
    let error_index = match reader.decode_value()? {
        Asn1Value::Integer(v) => v as u8,
        _ => return None,
    };

    // VarBind list: SEQUENCE
    let varbinds = parse_varbind_list(&mut reader)?;

    Some(PduParseResult {
        pdu_type,
        request_id,
        error_status,
        error_index,
        varbinds,
        trap_info: None,
    })
}

/// Parse v1 Trap PDU
fn parse_trap_pdu(data: &[u8]) -> Option<PduParseResult> {
    let mut reader = BerReader::new(data);

    // Enterprise: OID
    let enterprise = match reader.decode_value()? {
        Asn1Value::Oid(oid) => oid,
        _ => return None,
    };

    // Agent-addr: IpAddress (APPLICATION 0)
    let agent_addr = parse_ip_address(&mut reader)?;

    // Generic-trap: INTEGER
    let generic_trap = match reader.decode_value()? {
        Asn1Value::Integer(v) => v as u8,
        _ => return None,
    };

    // Specific-trap: INTEGER
    let specific_trap = match reader.decode_value()? {
        Asn1Value::Integer(v) => v as u8,
        _ => return None,
    };

    // Timestamp: TimeTicks (APPLICATION 3)
    let timestamp = parse_time_ticks(&mut reader)?;

    // VarBind list
    let varbinds = parse_varbind_list(&mut reader)?;

    Some(PduParseResult {
        pdu_type: SnmpPduType::Trap,
        request_id: 0,
        error_status: 0,
        error_index: 0,
        varbinds,
        trap_info: Some(SnmpTrapInfo {
            enterprise,
            agent_addr,
            generic_trap,
            specific_trap,
            timestamp,
        }),
    })
}

/// Parse VarBind list
fn parse_varbind_list(reader: &mut BerReader) -> Option<Vec<SnmpVarBind>> {
    // SEQUENCE of VarBind
    let (seq_tag, seq_data) = reader.decode_tlv()?;
    if seq_tag.class != Asn1Class::Universal || seq_tag.number != 0x10 {
        return None;
    }

    let mut varbinds = Vec::new();
    let mut inner_reader = BerReader::new(seq_data);

    while !inner_reader.is_empty() {
        // VarBind: SEQUENCE { OID, Value }
        let (vb_tag, vb_data) = inner_reader.decode_tlv()?;
        if vb_tag.class != Asn1Class::Universal || vb_tag.number != 0x10 {
            break;
        }

        let mut vb_reader = BerReader::new(vb_data);

        // OID
        let oid = match vb_reader.decode_value()? {
            Asn1Value::Oid(oid) => oid,
            _ => break,
        };

        // Value
        let value = format_asn1_value(&vb_reader.decode_value()?);

        varbinds.push(SnmpVarBind { oid, value });
    }

    Some(varbinds)
}

/// Parse IpAddress (APPLICATION 0)
fn parse_ip_address(reader: &mut BerReader) -> Option<[u8; 4]> {
    let (tag, data) = reader.decode_tlv()?;
    if tag.class != Asn1Class::Application || tag.number != 0 {
        return None;
    }
    if data.len() != 4 {
        return None;
    }
    Some([data[0], data[1], data[2], data[3]])
}

/// Parse TimeTicks (APPLICATION 3)
fn parse_time_ticks(reader: &mut BerReader) -> Option<u32> {
    let (tag, data) = reader.decode_tlv()?;
    if tag.class != Asn1Class::Application || tag.number != 3 {
        return None;
    }

    let mut value: u32 = 0;
    for &byte in data {
        value = (value << 8) | (byte as u32);
    }
    Some(value)
}

/// Parse PDU type from tag number
fn parse_pdu_type(number: u32) -> Option<SnmpPduType> {
    match number {
        0 => Some(SnmpPduType::GetRequest),
        1 => Some(SnmpPduType::GetNextRequest),
        2 => Some(SnmpPduType::GetResponse),
        3 => Some(SnmpPduType::SetRequest),
        4 => Some(SnmpPduType::Trap),
        5 => Some(SnmpPduType::GetBulk),
        6 => Some(SnmpPduType::Inform),
        7 => Some(SnmpPduType::TrapV2),
        8 => Some(SnmpPduType::Report),
        _ => None,
    }
}

/// Format ASN.1 value as string
fn format_asn1_value(value: &Asn1Value) -> String {
    match value {
        Asn1Value::Boolean(b) => b.to_string(),
        Asn1Value::Integer(i) => i.to_string(),
        Asn1Value::OctetString(bytes) => {
            // Try to decode as UTF-8, otherwise show hex
            match String::from_utf8(bytes.clone()) {
                Ok(s) if s.is_ascii() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') => {
                    format!("\"{}\"", s)
                }
                _ => format!("0x{}", hex::encode(bytes)),
            }
        }
        Asn1Value::Null => "NULL".to_string(),
        Asn1Value::Oid(oid) => oid.clone(),
        Asn1Value::Sequence(_) => "SEQUENCE".to_string(),
        Asn1Value::Application(num, data) => {
            match *num {
                0 if data.len() == 4 => {
                    // IpAddress
                    format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3])
                }
                1 => {
                    // Counter
                    let mut val: u32 = 0;
                    for &b in data {
                        val = (val << 8) | (b as u32);
                    }
                    format!("Counter({})", val)
                }
                2 => {
                    // Gauge
                    let mut val: u32 = 0;
                    for &b in data {
                        val = (val << 8) | (b as u32);
                    }
                    format!("Gauge({})", val)
                }
                3 => {
                    // TimeTicks
                    let mut val: u32 = 0;
                    for &b in data {
                        val = (val << 8) | (b as u32);
                    }
                    format!("TimeTicks({})", val)
                }
                4 => {
                    // Opaque
                    format!("Opaque(0x{})", hex::encode(data))
                }
                6 => {
                    // Counter64
                    let mut val: u64 = 0;
                    for &b in data {
                        val = (val << 8) | (b as u64);
                    }
                    format!("Counter64({})", val)
                }
                _ => format!("App[{}]({})", num, hex::encode(data)),
            }
        }
        Asn1Value::ContextSpecific(num, data) => {
            match *num {
                0 => "noSuchObject".to_string(),
                1 => "noSuchInstance".to_string(),
                2 => "endOfMibView".to_string(),
                _ => format!("Context[{}]({})", num, hex::encode(data)),
            }
        }
        _ => "UNKNOWN".to_string(),
    }
}

// Simple hex encoding (avoid adding dependency)
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Detect SNMP protocol from packet
pub fn detect_snmp(data: &[u8]) -> Option<DetectionResult> {
    let metadata = parse_snmp_message(data)?;

    Some(
        DetectionResult::new(Protocol::Snmp)
            .with_metadata(Metadata::Snmp(metadata))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a simple SNMP v1 GetRequest
    fn create_snmp_v1_get_request() -> Vec<u8> {
        // SNMP v1 GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0)
        // Community: "public"
        vec![
            0x30, 0x26,           // SEQUENCE, length 38
            0x02, 0x01, 0x00,     // INTEGER: version 0 (v1)
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, // OCTET STRING: "public"
            0xA0, 0x19,           // GetRequest (context-specific 0, constructed)
            0x02, 0x01, 0x01,     // request-id: 1
            0x02, 0x01, 0x00,     // error-status: 0
            0x02, 0x01, 0x00,     // error-index: 0
            0x30, 0x0E,           // varbind-list SEQUENCE
            0x30, 0x0C,           // varbind SEQUENCE
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: 1.3.6.1.2.1.1.1.0
            0x05, 0x00,           // NULL
        ]
    }

    #[test]
    fn test_parse_snmp_v1_get_request() {
        let data = create_snmp_v1_get_request();
        let metadata = parse_snmp_message(&data).unwrap();

        assert_eq!(metadata.version, SnmpVersion::V1);
        assert_eq!(metadata.community, "public");
        assert_eq!(metadata.pdu_type, SnmpPduType::GetRequest);
        assert_eq!(metadata.request_id, 1);
        assert_eq!(metadata.error_status, 0);
        assert_eq!(metadata.error_index, 0);
        assert_eq!(metadata.varbinds.len(), 1);
        assert_eq!(metadata.varbinds[0].oid, "1.3.6.1.2.1.1.1.0");
    }

    #[test]
    fn test_detect_snmp() {
        let data = create_snmp_v1_get_request();
        let result = detect_snmp(&data).unwrap();

        assert_eq!(result.protocol, Protocol::Snmp);
    }

    #[test]
    fn test_parse_snmp_v2c() {
        // SNMP v2c GetRequest (version 1 in encoding)
        let mut data = create_snmp_v1_get_request();
        data[4] = 0x01; // version 1 = v2c

        let metadata = parse_snmp_message(&data).unwrap();
        assert_eq!(metadata.version, SnmpVersion::V2c);
    }

    #[test]
    fn test_parse_snmp_invalid_version() {
        let mut data = create_snmp_v1_get_request();
        data[4] = 0x02; // version 2 (invalid)

        assert!(parse_snmp_message(&data).is_none());
    }

    #[test]
    fn test_parse_snmp_too_short() {
        let data = [0x30, 0x02, 0x02, 0x01];
        assert!(parse_snmp_message(&data).is_none());
    }

    /// Create SNMP v1 Trap
    fn create_snmp_v1_trap() -> Vec<u8> {
        // SNMP v1 Trap: coldStart (generic-trap 0)
        // PDU content = 28 bytes: enterprise(10) + agent-addr(6) + generic(3) + specific(3) + timestamp(4) + varbind(2)
        vec![
            0x30, 0x29,           // SEQUENCE, length = 41 (version(3) + community(8) + PDU header(2) + content(28))
            0x02, 0x01, 0x00,     // version 0 (v1)
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, // community "public"
            0xA4, 0x1C,           // Trap (context-specific 4), length = 28
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x00, 0x00, 0x00, // enterprise OID: 1.3.6.1.4.1.0.0.0
            0x40, 0x04, 0xC0, 0xA8, 0x01, 0x01, // agent-addr: 192.168.1.1 (IpAddress APPLICATION 0)
            0x02, 0x01, 0x00,     // generic-trap: 0 (coldStart)
            0x02, 0x01, 0x00,     // specific-trap: 0
            0x43, 0x02, 0x00, 0x01, // timestamp: 1 (TimeTicks APPLICATION 3)
            0x30, 0x00,           // empty varbind list
        ]
    }

    #[test]
    fn test_parse_snmp_v1_trap() {
        let data = create_snmp_v1_trap();
        let metadata = parse_snmp_message(&data).unwrap();

        assert_eq!(metadata.pdu_type, SnmpPduType::Trap);
        assert!(metadata.trap_info.is_some());

        let trap = metadata.trap_info.unwrap();
        assert_eq!(trap.generic_trap, 0); // coldStart
        assert_eq!(trap.agent_addr, [192, 168, 1, 1]);
        assert_eq!(trap.timestamp, 1);
    }

    #[test]
    fn test_detect_snmp_v1_trap() {
        let data = create_snmp_v1_trap();
        let result = detect_snmp(&data).unwrap();

        assert_eq!(result.protocol, Protocol::Snmp);

        if let Metadata::Snmp(meta) = result.metadata {
            assert_eq!(meta.pdu_type, SnmpPduType::Trap);
        } else {
            panic!("Expected Snmp metadata");
        }
    }
}
