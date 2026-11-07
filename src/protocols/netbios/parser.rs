//! NetBIOS parsers (NBNS/NBDS/NBSS).

use crate::core::types::NetBiosService;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetBiosParsed {
    pub service: NetBiosService,
    pub name: Option<String>,
    pub suffix: Option<u8>,
}

fn trim_name(bytes: &[u8]) -> Option<String> {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0 || byte == b' ')
        .unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&bytes[..end]).ok().map(str::to_string)
}

fn decode_nbns_name(encoded: &[u8]) -> Option<[u8; 16]> {
    if encoded.len() != 32 {
        return None;
    }
    let mut decoded = [0u8; 16];
    for (index, pair) in encoded.as_chunks::<2>().0.iter().enumerate() {
        let hi = pair[0].checked_sub(b'A')?;
        let lo = pair[1].checked_sub(b'A')?;
        if hi > 15 || lo > 15 {
            return None;
        }
        decoded[index] = (hi << 4) | lo;
    }
    Some(decoded)
}

pub(crate) fn parse_nbns(payload: &[u8]) -> Option<NetBiosParsed> {
    if payload.len() < 50 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let nscount = u16::from_be_bytes([payload[8], payload[9]]);
    let arcount = u16::from_be_bytes([payload[10], payload[11]]);
    let query = qdcount == 1 && ancount == 0 && nscount == 0 && arcount <= 1;
    let response = ancount >= 1 && qdcount <= 1 && nscount == 0;
    if !query && !response {
        return None;
    }
    if payload[12] != 0x20 {
        return None;
    }
    let decoded = decode_nbns_name(&payload[13..45])?;
    if payload[45] != 0x00 {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[46], payload[47]]);
    let qclass = u16::from_be_bytes([payload[48], payload[49]]);
    if !matches!(qtype, 0x0020 | 0x0002) || qclass != 0x0001 {
        return None;
    }
    Some(NetBiosParsed {
        service: NetBiosService::NameService,
        name: trim_name(&decoded[..15]),
        suffix: Some(decoded[15]),
    })
}

pub(crate) fn parse_nbds(payload: &[u8]) -> Option<NetBiosParsed> {
    if payload.len() < 46 {
        return None;
    }
    if !(0x10..=0x16).contains(&payload[0]) {
        return None;
    }
    let dgm_len = u16::from_be_bytes([payload[10], payload[11]]) as usize;
    if dgm_len != payload.len() - 14 {
        return None;
    }
    Some(NetBiosParsed {
        service: NetBiosService::DatagramService,
        name: trim_name(&payload[14..30]),
        suffix: None,
    })
}

pub(crate) fn parse_nbss(payload: &[u8]) -> Option<NetBiosParsed> {
    if payload.len() < 37 || payload[0] != 0x81 {
        return None;
    }
    let length = u16::from_be_bytes([payload[2], payload[3]]) & 0x3FFF;
    if length < 33 {
        return None;
    }
    // RFC 1002 名字段：1 字节长度（0x20）+ 32 字符编码 + 终止字节
    if payload.len() < 38 || payload[4] != 0x20 {
        return None;
    }
    let decoded = decode_nbns_name(&payload[5..37])?;
    Some(NetBiosParsed {
        service: NetBiosService::SessionService,
        name: trim_name(&decoded[..15]),
        suffix: Some(decoded[15]),
    })
}

pub(crate) fn parse_nbss_session_message(payload: &[u8]) -> Option<NetBiosParsed> {
    if payload.len() < 8 || payload[0] != 0x00 {
        return None;
    }
    let signature = &payload[4..8];
    if signature != &b"\xFFSMB"[..] && signature != &b"\xFESMB"[..] {
        return None;
    }
    Some(NetBiosParsed {
        service: NetBiosService::SessionService,
        name: None,
        suffix: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_name(name: &str, suffix: u8) -> Vec<u8> {
        let mut padded = name.as_bytes().iter().copied().take(15).collect::<Vec<_>>();
        padded.resize(15, b' ');
        padded.push(suffix);
        let mut out = Vec::with_capacity(32);
        for byte in padded {
            out.push(b'A' + (byte >> 4));
            out.push(b'A' + (byte & 0x0F));
        }
        out
    }

    fn nbns_query() -> Vec<u8> {
        let mut payload = vec![
            0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        payload.push(0x20);
        payload.extend(encode_name("SERVER", 0x20));
        payload.push(0x00);
        payload.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);
        payload
    }

    fn nbds_datagram() -> Vec<u8> {
        let mut payload = vec![0x10, 0x00, 0x12, 0x34, 192, 168, 1, 1, 0x00, 0x8A];
        let body_len = 16 + 16 + 13;
        payload.extend_from_slice(&(body_len as u16).to_be_bytes());
        payload.extend_from_slice(&[0x00, 0x00]);
        payload.extend_from_slice(b"SERVER          ");
        payload.extend_from_slice(b"CLIENT          ");
        payload.extend_from_slice(b"hello netbios");
        payload
    }

    fn nbss_session_request() -> Vec<u8> {
        let mut payload = vec![0x81, 0x00, 0x00, 0x44];
        payload.push(0x20);
        payload.extend(encode_name("SERVER", 0x20));
        payload.push(0x00);
        payload.push(0x20);
        payload.extend(encode_name("CLIENT", 0x20));
        payload.push(0x00);
        payload
    }

    #[test]
    fn parses_nbns_query() {
        let parsed = parse_nbns(&nbns_query()).unwrap();
        assert_eq!(parsed.service, NetBiosService::NameService);
        assert_eq!(parsed.name.as_deref(), Some("SERVER"));
        assert_eq!(parsed.suffix, Some(0x20));
    }

    #[test]
    fn rejects_malformed_nbns() {
        assert!(parse_nbns(b"").is_none());
        let mut payload = nbns_query();
        payload[13] = b'Z'; // 非 'A'..='P'
        assert!(parse_nbns(&payload).is_none());
        let mut payload = nbns_query();
        payload[4] = 0;
        payload[5] = 2; // qdcount=2
        assert!(parse_nbns(&payload).is_none());
    }

    #[test]
    fn parses_nbds_datagram() {
        let parsed = parse_nbds(&nbds_datagram()).unwrap();
        assert_eq!(parsed.service, NetBiosService::DatagramService);
        assert_eq!(parsed.name.as_deref(), Some("SERVER"));
        assert_eq!(parsed.suffix, None);
    }

    #[test]
    fn rejects_nbds_length_mismatch() {
        let mut payload = nbds_datagram();
        payload[10] = 0xFF;
        assert!(parse_nbds(&payload).is_none());
    }

    #[test]
    fn parses_nbss_session_request() {
        let payload = nbss_session_request();
        assert_eq!(payload.len(), 72);
        let parsed = parse_nbss(&payload).unwrap();
        assert_eq!(parsed.service, NetBiosService::SessionService);
        assert_eq!(parsed.name.as_deref(), Some("SERVER"));
        assert_eq!(parsed.suffix, Some(0x20));
    }

    #[test]
    fn parses_nbss_session_message_with_smb() {
        let payload = [0x00, 0x00, 0x00, 0x20, 0xFF, b'S', b'M', b'B'];
        let parsed = parse_nbss_session_message(&payload).unwrap();
        assert_eq!(parsed.service, NetBiosService::SessionService);
        assert!(parsed.name.is_none());
        assert!(
            parse_nbss_session_message(&[0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00]).is_none()
        );
    }
}
