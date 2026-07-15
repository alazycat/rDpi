//! TLS Certificate message parser
//!
//! Extracts subject, issuer, and validity from X.509 certificates
//! in TLS Certificate handshake messages.

use crate::asn1::ber::BerReader;

/// Extracted certificate metadata
#[derive(Debug, Clone, Default)]
pub struct CertInfo {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<u64>,  // Unix timestamp
    pub not_after: Option<u64>,   // Unix timestamp
}

/// Check if a TLS record contains a Certificate handshake message (type 0x0B)
pub fn is_certificate_message(data: &[u8]) -> bool {
    if data.len() < 6 { return false; }
    // TLS Record: ContentType(1) + Version(2) + Length(2)
    // Handshake: HandshakeType(1) + Length(3)
    data[0] == 0x16 && data[5] == 0x0B // Handshake + Certificate
}

/// Parse TLS Certificate message and extract first certificate's metadata
pub fn parse_certificate(data: &[u8]) -> Option<CertInfo> {
    if !is_certificate_message(data) { return None; }

    // Skip TLS record header (5 bytes) + Handshake header (4 bytes)
    // Handshake header: type(1) + length(3)
    let mut offset: usize = 5 + 4;

    // Certificate list length (3 bytes)
    if offset + 3 > data.len() { return None; }
    let cert_list_len = u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
    offset += 3;
    if offset + cert_list_len > data.len() { return None; }

    // First certificate: length (3 bytes) + data
    if offset + 3 > data.len() { return None; }
    let cert_len = u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
    offset += 3;
    if offset + cert_len > data.len() { return None; }

    let cert_data = &data[offset..offset + cert_len];
    parse_x509_certificate(cert_data)
}

/// Parse X.509 DER certificate and extract key fields
fn parse_x509_certificate(data: &[u8]) -> Option<CertInfo> {
    let mut reader = BerReader::new(data);

    // Outer SEQUENCE (Certificate)
    let (_, cert_value) = reader.decode_tlv()?;
    let mut cert = BerReader::new(cert_value);

    // Inner SEQUENCE (TBSCertificate)
    let (_, tbs_value) = cert.decode_tlv()?;
    let mut tbs = BerReader::new(tbs_value);

    // We need to navigate TBSCertificate to find:
    // version [0] EXPLICIT (optional, context-specific tag 0)
    // serialNumber INTEGER
    // signature SEQUENCE
    // issuer SEQUENCE
    // validity SEQUENCE
    // subject SEQUENCE

    // Check if version's EXPLICIT tag [0] is present (bit 6 = constructed, tag 0)
    // This is indicated by byte 0 having tag 0xa0 = 0x80 | 0x20 | 0x00
    let has_version = tbs.peek_byte().map_or(false, |b| b == 0xA0);

    if has_version {
        // Skip version [0] EXPLICIT INTEGER
        tbs.decode_tlv()?;
    }

    // Skip serialNumber INTEGER
    tbs.decode_tlv()?;
    // Skip signature SEQUENCE
    tbs.decode_tlv()?;

    // 4. issuer — SEQUENCE of SET of SEQUENCE
    let issuer = extract_dn(&mut tbs);

    // 5. validity — SEQUENCE { Time, Time }
    let (not_before, not_after) = extract_validity(&mut tbs)?;

    // 6. subject — SEQUENCE of SET of SEQUENCE
    let subject = extract_dn(&mut tbs);

    Some(CertInfo {
        subject,
        issuer,
        not_before,
        not_after,
    })
}

/// Extract Distinguished Name (CN=..., O=...) from a SEQUENCE of SETs
fn extract_dn(reader: &mut BerReader) -> Option<String> {
    let (_, dn_value) = reader.decode_tlv()?;
    let mut dn_reader = BerReader::new(dn_value);

    let mut parts = Vec::new();

    // Name is SEQUENCE of SET (each SET contains one SEQUENCE { OID, value })
    while !dn_reader.is_empty() {
        // SET
        if let Some((_, set_value)) = dn_reader.decode_tlv() {
            let mut set_reader = BerReader::new(set_value);
            // SEQUENCE { OID, value }
            if let Some((_, attr_value)) = set_reader.decode_tlv() {
                let mut attr_reader = BerReader::new(attr_value);
                // OID
                if let Some(_oid) = attr_reader.decode_value() {
                    // Value: PrintableString, UTF8String, T61String, etc.
                    if let Some((val_tag, val_data)) = attr_reader.decode_tlv() {
                        if val_tag.class == crate::asn1::types::Asn1Class::Universal {
                            match val_tag.number {
                                0x0C | 0x13 => { // UTF8String (0x0C) or PrintableString (0x13)
                                    if let Ok(s) = std::str::from_utf8(val_data) {
                                        parts.push(s.to_string());
                                    }
                                }
                                0x14 => { // T61String / TeletexString
                                    if let Ok(s) = std::str::from_utf8(val_data) {
                                        parts.push(s.to_string());
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        } else {
            break;
        }
    }

    if parts.is_empty() { None } else { Some(parts.join(", ")) }
}

/// Extract validity (notBefore, notAfter) as Unix timestamps
fn extract_validity(reader: &mut BerReader) -> Option<(Option<u64>, Option<u64>)> {
    let (_, validity_value) = reader.decode_tlv()?;
    let mut val_reader = BerReader::new(validity_value);

    // notBefore
    let not_before = parse_time(&mut val_reader);
    // notAfter
    let not_after = parse_time(&mut val_reader);

    Some((not_before, not_after))
}

/// Parse Time (UTCTime or GeneralizedTime) to Unix timestamp
fn parse_time(reader: &mut BerReader) -> Option<u64> {
    let (tag, value) = reader.decode_tlv()?;
    if tag.class != crate::asn1::types::Asn1Class::Universal {
        return None;
    }

    match tag.number {
        0x17 => parse_utc_time(value),      // UTCTime
        0x18 => parse_generalized_time(value), // GeneralizedTime
        _ => None,
    }
}

/// Parse UTCTime (YYMMDDHHMMSSZ) to Unix timestamp
fn parse_utc_time(data: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(data).ok()?;
    // UTCTime: YYMMDDHHMMSSZ
    if s.len() < 13 || !s.ends_with('Z') { return None; }
    let year: u64 = 2000 + s[0..2].parse::<u64>().ok()?;
    let month: u64 = s[2..4].parse().ok()?;
    let day: u64 = s[4..6].parse().ok()?;
    let hour: u64 = s[6..8].parse().ok()?;
    let min: u64 = s[8..10].parse().ok()?;
    let sec: u64 = s[10..12].parse().ok()?;
    timestamp(year, month, day, hour, min, sec)
}

/// Parse GeneralizedTime (YYYYMMDDHHMMSSZ) to Unix timestamp
fn parse_generalized_time(data: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(data).ok()?;
    if s.len() < 15 || !s.ends_with('Z') { return None; }
    let year: u64 = s[0..4].parse().ok()?;
    let month: u64 = s[4..6].parse().ok()?;
    let day: u64 = s[6..8].parse().ok()?;
    let hour: u64 = s[8..10].parse().ok()?;
    let min: u64 = s[10..12].parse().ok()?;
    let sec: u64 = s[12..14].parse().ok()?;
    timestamp(year, month, day, hour, min, sec)
}

/// Simple Unix timestamp calculation (not timezone-aware)
fn timestamp(year: u64, month: u64, day: u64, hour: u64, min: u64, sec: u64) -> Option<u64> {
    if year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 { return None; }
    if hour > 23 || min > 59 || sec > 59 { return None; }

    // Days from 1970-01-01
    let days_since_epoch = || -> u64 {
        let mut y = 1970u64;
        let mut days = 0u64;
        while y < year {
            days += if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) { 366 } else { 365 };
            y += 1;
        }
        let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        for m in 1..month {
            days += month_days[m as usize];
            if m == 2 && is_leap { days += 1; }
        }
        days + day - 1
    };

    Some(days_since_epoch() * 86400 + hour * 3600 + min * 60 + sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS Certificate message with a self-signed X.509-like structure
    fn build_tls_cert(subject_cn: &str, issuer_cn: &str, days_valid: u64) -> Vec<u8> {
        let mut cert = Vec::new();
        // Simplified: real X.509 would be complex
        // For testing, we create a parsable DER structure
        cert.push(0x30); // SEQUENCE (Certificate)
        cert.push(0x00); // length placeholder

        // TBSCertificate SEQUENCE
        let tbs = build_tbs_cert(subject_cn, issuer_cn, days_valid);
        cert.extend_from_slice(&tbs);

        cert[1] = (cert.len() - 2) as u8; // fix length

        // Wrap in TLS Certificate message
        let mut msg = Vec::new();
        // TLS Record: Handshake(0x16), TLS 1.2(0x0303), length
        msg.push(0x16); msg.push(0x03); msg.push(0x03);
        msg.extend_from_slice(&((cert.len() + 7) as u16).to_be_bytes()); // record length
        // Handshake: Certificate(0x0B), 3-byte length
        msg.push(0x0B);
        msg.extend_from_slice(&[0x00, 0x00, (cert.len() + 3) as u8]); // handshake length
        // Certificate list length (3 bytes)
        msg.extend_from_slice(&[0x00, 0x00, cert.len() as u8]);
        // Certificate length (3 bytes) + data
        msg.extend_from_slice(&[0x00, 0x00, cert.len() as u8]);
        msg.extend_from_slice(&cert);
        msg
    }

    fn build_tbs_cert(subject_cn: &str, issuer_cn: &str, _days_valid: u64) -> Vec<u8> {
        let mut tbs = Vec::new();
        tbs.push(0x30); tbs.push(0x00); // placeholder SEQUENCE
        let inner = build_tbs_inner(subject_cn, issuer_cn);
        tbs.extend_from_slice(&inner);
        tbs[1] = (tbs.len() - 2) as u8;
        tbs
    }

    fn build_tbs_inner(subject_cn: &str, issuer_cn: &str) -> Vec<u8> {
        let mut inner = Vec::new();
        // version [0] EXPLICIT INTEGER { 2 }
        inner.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);
        // serialNumber INTEGER 1
        inner.extend_from_slice(&[0x02, 0x01, 0x01]);
        // signature SEQUENCE { OID 1.2.840.113549.1.1.11 }
        inner.extend_from_slice(&[0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00]);
        // issuer SEQUENCE
        append_dn(&mut inner, issuer_cn);
        // validity SEQUENCE
        append_validity(&mut inner);
        // subject SEQUENCE
        append_dn(&mut inner, subject_cn);
        inner
    }

    fn append_dn(data: &mut Vec<u8>, cn: &str) {
        let mut attr = Vec::new();
        // OID 2.5.4.3 = commonName
        attr.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]);
        // PrintableString or UTF8String
        attr.push(0x0C); // UTF8String
        attr.push(cn.len() as u8);
        attr.extend_from_slice(cn.as_bytes());

        let mut set = Vec::new();
        set.push(0x30); // SEQUENCE
        set.push(attr.len() as u8);
        set.extend_from_slice(&attr);

        let mut dn = Vec::new();
        dn.push(0x31); // SET
        dn.push(set.len() as u8);
        dn.extend_from_slice(&set);

        let mut seq = Vec::new();
        seq.push(0x30); // SEQUENCE
        seq.push(dn.len() as u8);
        seq.extend_from_slice(&dn);

        data.extend_from_slice(&seq);
    }

    fn append_validity(data: &mut Vec<u8>) {
        let now = 1710000000u64; // 2024-03-09 approx
        let later = now + 365 * 86400;
        // UTCTime format: YYMMDDHHMMSSZ
        let from = b"240309120000Z";
        let to = b"250309120000Z";

        let mut validity = Vec::new();
        validity.push(0x17); // UTCTime
        validity.push(from.len() as u8);
        validity.extend_from_slice(from);
        validity.push(0x17); // UTCTime
        validity.push(to.len() as u8);
        validity.extend_from_slice(to);

        data.push(0x30); // SEQUENCE
        data.push(validity.len() as u8);
        data.extend_from_slice(&validity);
    }

    #[test]
    fn test_is_certificate_message() {
        let data = build_tls_cert("example.com", "CA Inc", 365);
        assert!(is_certificate_message(&data));
    }

    #[test]
    fn test_parse_certificate_subject() {
        let data = build_tls_cert("example.com", "CA Inc", 365);
        let info = parse_certificate(&data).unwrap();
        assert_eq!(info.subject.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_parse_certificate_issuer() {
        let data = build_tls_cert("example.com", "CA Inc", 365);
        let info = parse_certificate(&data).unwrap();
        assert_eq!(info.issuer.as_deref(), Some("CA Inc"));
    }

    #[test]
    fn test_not_certificate() {
        assert!(parse_certificate(b"GET / HTTP/1.1").is_none());
    }

    #[test]
    fn test_is_self_signed() {
        let data = build_tls_cert("myserver.local", "myserver.local", 365);
        let info = parse_certificate(&data).unwrap();
        assert_eq!(info.subject, info.issuer);
    }
}
