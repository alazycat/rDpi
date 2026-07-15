//! MongoDB wire protocol parser for rDpi
//!
//! Parses MongoDB isMaster/hello handshake messages using BSON scanning.
//!
//! ## Wire Format
//!
//! Standard Message Header (16 bytes):
//! - messageLength (int32, LE)
//! - requestID (int32, LE)
//! - responseTo (int32, LE)
//! - opCode (int32, LE): 2012=OP_MSG, 2004=OP_QUERY, 1=OP_REPLY
//!
//! BSON scanning approach: sequentially scan BSON elements looking for
//! isMaster/hello field with ok != 0, without building a full BSON tree.

use crate::core::types::MongodbMetadata;

/// Parse MongoDB handshake response (isMaster/hello)
///
/// Scans the BSON payload for isMaster/hello fields and extracts
/// server_version, max_wire_version, and max_msg_size.
pub fn parse_mongodb_handshake(data: &[u8]) -> Option<MongodbMetadata> {
    // Minimum: header(16) + minimal BSON(5)
    if data.len() < 21 {
        return None;
    }

    // Extract opCode
    let op_code = i32::from_le_bytes([data[12], data[13], data[14], data[15]]);

    // Find BSON body based on opCode
    let body = match op_code {
        2012 => {
            // OP_MSG: skip flags(1) + section kind(1)
            if data.len() < 18 { return None; }
            let _flags = data[16];
            let section_kind = data[17];
            if section_kind != 0 { return None; } // Body section only
            &data[18..]
        }
        2004 => {
            // OP_QUERY: skip flags(4) + fullCollectionName(null-term) + numToSkip(4) + numToReturn(4)
            let mut pos: usize = 16 + 4;
            while pos < data.len() && data[pos] != 0 { pos += 1; }
            if pos >= data.len() { return None; }
            pos += 1; // skip null
            pos += 8; // numberToSkip(4) + numberToReturn(4)
            if pos >= data.len() { return None; }
            &data[pos..]
        }
        1 => {
            // OP_REPLY: skip responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4)
            let pos = 16 + 20;
            if pos >= data.len() { return None; }
            &data[pos..]
        }
        _ => return None,
    };

    scan_bson_for_handshake(body)
}

/// Scan BSON document for isMaster/hello handshake fields
///
/// Performs a sequential scan of BSON elements without building a full tree.
/// Returns MongodbMetadata if isMaster/hello is found with ok != 0.
fn scan_bson_for_handshake(body: &[u8]) -> Option<MongodbMetadata> {
    if body.len() < 5 { return None; }

    let doc_len = i32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if doc_len > body.len() || doc_len < 5 { return None; }
    if body[doc_len - 1] != 0x00 { return None; } // terminator

    let elements = &body[4..doc_len - 1];
    let mut pos = 0;

    let mut found_cmd = false;
    let mut server_version: Option<String> = None;
    let mut max_wire_version: Option<i32> = None;
    let mut max_msg_size: Option<i32> = None;

    while pos + 1 < elements.len() {
        let el_type = elements[pos];
        pos += 1;

        // Read element name (C string)
        let name_start = pos;
        while pos < elements.len() && elements[pos] != 0 { pos += 1; }
        if pos >= elements.len() { break; }
        let name = std::str::from_utf8(&elements[name_start..pos]).ok()?;
        pos += 1; // skip null

        match el_type {
            0x01 => { // Double (8 bytes)
                if pos + 8 > elements.len() { break; }
                let value = f64::from_le_bytes([
                    elements[pos], elements[pos+1], elements[pos+2], elements[pos+3],
                    elements[pos+4], elements[pos+5], elements[pos+6], elements[pos+7],
                ]);
                pos += 8;
                if name == "isMaster" || name == "hello" || name == "ismaster" { found_cmd = value != 0.0; }
            }
            0x02 => { // String (int32 length + data + null)
                if pos + 4 > elements.len() { break; }
                let str_len = i32::from_le_bytes([elements[pos], elements[pos+1], elements[pos+2], elements[pos+3]]) as usize;
                pos += 4;
                if str_len > 0 && str_len <= elements.len() - pos {
                    let s = std::str::from_utf8(&elements[pos..pos + str_len - 1]).ok()?; // -1 for trailing null
                    if name == "version" { server_version = Some(s.to_string()); }
                    pos += str_len;
                } else { break; }
            }
            0x03 | 0x04 => { // Document / Array — skip
                if pos + 4 > elements.len() { break; }
                let sub_len = i32::from_le_bytes([elements[pos], elements[pos+1], elements[pos+2], elements[pos+3]]) as usize;
                if sub_len == 0 || sub_len > elements.len() - pos { break; }
                if name == "isMaster" || name == "hello" || name == "ismaster" {
                    found_cmd = true;
                }
                pos += sub_len;
            }
            0x08 => { // Boolean (1 byte)
                if pos >= elements.len() { break; }
                let value = elements[pos] != 0;
                pos += 1;
                if name == "isMaster" || name == "hello" || name == "ismaster" {
                    found_cmd = value;
                }
            }
            0x10 => { // Int32 (4 bytes)
                if pos + 4 > elements.len() { break; }
                let value = i32::from_le_bytes([elements[pos], elements[pos+1], elements[pos+2], elements[pos+3]]);
                pos += 4;
                match name {
                    "isMaster" | "hello" | "ismaster" => found_cmd = value != 0,
                    "maxWireVersion" => max_wire_version = Some(value),
                    "maxMsgSizeBytes" => max_msg_size = Some(value),
                    "maxBsonObjectSize" => if max_msg_size.is_none() { max_msg_size = Some(value); },
                    _ => {}
                }
            }
            0x12 => { // Int64 (8 bytes)
                if pos + 8 > elements.len() { break; }
                pos += 8;
            }
            _ => {
                // Unknown type: attempt to skip based on fixed-size types
                // Types 0x07(ObjectId=12), 0x11(Timestamp=8), 0x13(Decimal128=16)
                let skip = match el_type {
                    0x00 => 0,        // terminator
                    0x05 => 5,        // binary: len(4)+type(1) + data, approximate
                    0x06 => 0,        // undefined
                    0x07 => 12,       // ObjectId
                    0x09 => 8,        // UTC datetime
                    0x0A => 0,        // null
                    0x0B => 2,        // regex: cstring+cstring
                    0x0C => 0,        // DBPointer
                    0x0D => 1,        // JavaScript code
                    0x0E => 0,        // Symbol (deprecated)
                    0x0F => 4,        // code_w_s: len(4)+str+scope_doc
                    0x11 => 8,        // Timestamp
                    0x13 => 16,       // Decimal128
                    0x7F => 0,        // MaxKey
                    0xFF => 0,        // MinKey
                    _ => 0,
                };
                if skip > 0 { pos += skip; }
                else { break; } // can't determine size, stop scanning
            }
        }
    }

    if found_cmd {
        Some(MongodbMetadata {
            server_version,
            max_wire_version,
            max_msg_size,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a BSON document with isMaster=true and ok=1
    fn build_isMaster_bson(version: &str, max_wire: i32, max_msg: i32) -> Vec<u8> {
        let mut bson = Vec::new();

        // isMaster: Boolean true (0x08), name="isMaster\0", value=1
        bson.push(0x08);
        bson.extend_from_slice(b"isMaster");
        bson.push(0x00);
        bson.push(0x01);

        // ok: Double (0x01), name="ok\0", value=1.0
        bson.push(0x01);
        bson.extend_from_slice(b"ok");
        bson.push(0x00);
        bson.extend_from_slice(&1.0f64.to_le_bytes());

        // version: String (0x02), name="version\0"
        bson.push(0x02);
        bson.extend_from_slice(b"version");
        bson.push(0x00);
        let ver_bytes = version.as_bytes();
        bson.extend_from_slice(&((ver_bytes.len() + 1) as i32).to_le_bytes());
        bson.extend_from_slice(ver_bytes);
        bson.push(0x00);

        // maxWireVersion: Int32 (0x10)
        bson.push(0x10);
        bson.extend_from_slice(b"maxWireVersion");
        bson.push(0x00);
        bson.extend_from_slice(&max_wire.to_le_bytes());

        // maxMsgSizeBytes: Int32 (0x10)
        bson.push(0x10);
        bson.extend_from_slice(b"maxMsgSizeBytes");
        bson.push(0x00);
        bson.extend_from_slice(&max_msg.to_le_bytes());

        // Prepend document length + append terminator
        let doc_len = (4 + bson.len() + 1) as i32;
        let mut doc = Vec::new();
        doc.extend_from_slice(&doc_len.to_le_bytes());
        doc.extend_from_slice(&bson);
        doc.push(0x00); // terminator
        doc
    }

    /// Build a complete OP_MSG packet with BSON body
    fn build_op_msg_isMaster(version: &str, max_wire: i32, max_msg: i32) -> Vec<u8> {
        let bson = build_isMaster_bson(version, max_wire, max_msg);
        let body_len = 1 + 1 + bson.len(); // flags(1) + kind(1) + bson
        let msg_len = (16 + body_len) as i32;

        let mut packet = Vec::new();
        packet.extend_from_slice(&msg_len.to_le_bytes());    // messageLength
        packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // requestID
        packet.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // responseTo
        packet.extend_from_slice(&[0xDC, 0x07, 0x00, 0x00]); // opCode = 2012 (OP_MSG)
        packet.push(0x00);                                     // flags
        packet.push(0x00);                                     // section kind = 0 (Body)
        packet.extend_from_slice(&bson);
        packet
    }

    /// Build a complete OP_QUERY packet with isMaster BSON query
    fn build_op_query_isMaster() -> Vec<u8> {
        let mut bson = Vec::new();
        // isMaster: Int32 1
        bson.push(0x10);
        bson.extend_from_slice(b"isMaster");
        bson.push(0x00);
        bson.extend_from_slice(&1i32.to_le_bytes());

        let doc_len = (4 + bson.len() + 1) as i32;
        let mut doc = Vec::new();
        doc.extend_from_slice(&doc_len.to_le_bytes());
        doc.extend_from_slice(&bson);
        doc.push(0x00);

        let collection = b"admin.$cmd\0";
        let body_len = 4 + collection.len() + 8 + doc.len();
        let msg_len = (16 + body_len) as i32;

        let mut packet = Vec::new();
        packet.extend_from_slice(&msg_len.to_le_bytes());
        packet.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // requestID
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // responseTo
        packet.extend_from_slice(&[0xD4, 0x07, 0x00, 0x00]); // opCode = 2004 (OP_QUERY)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags
        packet.extend_from_slice(collection);                  // fullCollectionName
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);  // numberToSkip
        packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);  // numberToReturn
        packet.extend_from_slice(&doc);
        packet
    }

    #[test]
    fn test_mongodb_isMaster_op_msg() {
        let data = build_op_msg_isMaster("6.0.0", 17, 48000000);
        let meta = parse_mongodb_handshake(&data).unwrap();

        assert_eq!(meta.server_version, Some("6.0.0".to_string()));
        assert_eq!(meta.max_wire_version, Some(17));
        assert_eq!(meta.max_msg_size, Some(48000000));
    }

    #[test]
    fn test_mongodb_hello_op_query() {
        let data = build_op_query_isMaster();
        let meta = parse_mongodb_handshake(&data).unwrap();

        assert!(meta.server_version.is_none()); // OP_QUERY request has no version
    }

    #[test]
    fn test_mongodb_short_payload() {
        assert!(parse_mongodb_handshake(&[]).is_none());
        assert!(parse_mongodb_handshake(&[0u8; 20]).is_none());
    }

    #[test]
    fn test_mongodb_not_handshake() {
        // Valid BSON but no isMaster/hello
        let mut bson = Vec::new();
        bson.push(0x01);
        bson.extend_from_slice(b"count");
        bson.push(0x00);
        bson.extend_from_slice(&1.0f64.to_le_bytes());

        let doc_len = (4 + bson.len() + 1) as i32;
        let mut doc = Vec::new();
        doc.extend_from_slice(&doc_len.to_le_bytes());
        doc.extend_from_slice(&bson);
        doc.push(0x00);

        let msg_len = (16 + 1 + 1 + doc.len()) as i32;
        let mut packet = Vec::new();
        packet.extend_from_slice(&msg_len.to_le_bytes());
        packet.extend_from_slice(&[0x00; 8]);
        packet.extend_from_slice(&[0xDC, 0x07, 0x00, 0x00]); // OP_MSG
        packet.push(0x00);
        packet.push(0x00);
        packet.extend_from_slice(&doc);

        assert!(parse_mongodb_handshake(&packet).is_none());
    }

    #[test]
    fn test_mongodb_op_reply() {
        // OP_REPLY with isMaster BSON
        let bson = build_isMaster_bson("7.0.0", 21, 48000000);
        let msg_len = (16 + 20 + bson.len()) as i32;

        let mut packet = Vec::new();
        packet.extend_from_slice(&msg_len.to_le_bytes());
        packet.extend_from_slice(&[0x00; 8]); // requestID + responseTo
        packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // opCode = 1 (OP_REPLY)
        packet.extend_from_slice(&[0x00; 20]); // reply header fields
        packet.extend_from_slice(&bson);

        let meta = parse_mongodb_handshake(&packet).unwrap();
        assert_eq!(meta.server_version, Some("7.0.0".to_string()));
    }

    #[test]
    fn test_mongodb_unknown_opcode() {
        let mut packet = vec![0u8; 24];
        packet[12..16].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // unknown opCode
        assert!(parse_mongodb_handshake(&packet).is_none());
    }
}
