//! OID (Object Identifier) encoding/decoding
//!
//! OIDs use a special encoding:
//! - First two components are combined into one byte: x*40 + y
//! - Remaining components use variable-length encoding (base-128)

/// Decode an OID from BER encoding to dot-separated string
///
/// # Example
///
/// ```
/// // OID 1.3.6.1: encoded as 0x2A 0x06 0x01
/// // First byte: 1*40 + 3 = 43 = 0x2B
/// let data = [0x2B, 0x06, 0x01];
/// let oid = rdpi::asn1::oid::decode_oid(&data).unwrap();
/// assert_eq!(oid, "1.3.6.1");
/// ```
pub fn decode_oid(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }

    let mut components = Vec::new();

    // First byte encodes first two components: first*40 + second
    let first_byte = bytes[0];
    let first = first_byte / 40;
    let second = first_byte % 40;

    // Handle edge case: some OIDs have first component > 3
    // In that case, the second component can be >= 40
    components.push(first as u64);
    components.push(second as u64);

    // Remaining bytes use variable-length encoding
    let mut i = 1;
    while i < bytes.len() {
        let (value, consumed) = decode_varint(&bytes[i..])?;
        components.push(value);
        i += consumed;
    }

    // Convert to dot-separated string
    let result = components
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(".");

    Some(result)
}

/// Decode a variable-length integer (base-128 encoding)
///
/// Each byte has continuation bit in MSB, 7 bits of value
fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut i = 0;

    loop {
        if i >= bytes.len() {
            return None;
        }

        let byte = bytes[i];
        value = (value << 7) | ((byte & 0x7F) as u64);
        i += 1;

        if (byte & 0x80) == 0 {
            break;
        }

        // Prevent overflow
        if i > 9 {
            return None;
        }
    }

    Some((value, i))
}

/// Encode an OID string to BER encoding
///
/// # Example
///
/// ```
/// let oid = "1.3.6.1";
/// let encoded = rdpi::asn1::oid::encode_oid(oid).unwrap();
/// assert_eq!(encoded, vec![0x2B, 0x06, 0x01]);
/// ```
pub fn encode_oid(oid: &str) -> Option<Vec<u8>> {
    let components: Vec<u64> = oid
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();

    if components.len() < 2 {
        return None;
    }

    let mut bytes = Vec::new();

    // First two components are combined
    let first = components[0];
    let second = components[1];

    if first > 2 {
        return None;
    }

    bytes.push((first * 40 + second) as u8);

    // Remaining components use variable-length encoding
    for &comp in &components[2..] {
        encode_varint(comp, &mut bytes);
    }

    Some(bytes)
}

/// Encode a number as variable-length integer (base-128)
fn encode_varint(value: u64, bytes: &mut Vec<u8>) {
    if value == 0 {
        bytes.push(0);
        return;
    }

    // Calculate how many bytes we need
    let mut temp = value;
    let mut needed = 0;
    while temp > 0 {
        needed += 1;
        temp >>= 7;
    }

    // Encode from most significant to least significant
    for i in (0..needed).rev() {
        let shift = i * 7;
        let mut byte = ((value >> shift) & 0x7F) as u8;
        if i > 0 {
            byte |= 0x80; // Continuation bit
        }
        bytes.push(byte);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_oid_simple() {
        // OID 1.3.6.1
        let data = [0x2B, 0x06, 0x01];
        let oid = decode_oid(&data).unwrap();
        assert_eq!(oid, "1.3.6.1");
    }

    #[test]
    fn test_decode_oid_system() {
        // OID 1.3.6.1.2.1.1.1.0 (sysDescr.0)
        let data = [0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
        let oid = decode_oid(&data).unwrap();
        assert_eq!(oid, "1.3.6.1.2.1.1.1.0");
    }

    #[test]
    fn test_decode_oid_with_varint() {
        // OID 1.3.6.1.2.1.25.3.3.1.2.196 (CPU load on CPU 196)
        // 196 = 0xC4 = 128 + 68, encoded as 0x81 0x44
        let data = [0x2B, 0x06, 0x01, 0x02, 0x01, 0x19, 0x03, 0x03, 0x01, 0x02, 0x81, 0x44];
        let oid = decode_oid(&data).unwrap();
        assert_eq!(oid, "1.3.6.1.2.1.25.3.3.1.2.196");
    }

    #[test]
    fn test_decode_oid_enterprise() {
        // OID 1.3.6.1.4.1.9 (Cisco enterprise)
        let data = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x09];
        let oid = decode_oid(&data).unwrap();
        assert_eq!(oid, "1.3.6.1.4.1.9");
    }

    #[test]
    fn test_decode_oid_large_number() {
        // OID with component > 127
        // 128 = 0x81 0x00
        let data = [0x2B, 0x06, 0x01, 0x81, 0x00];
        let oid = decode_oid(&data).unwrap();
        assert_eq!(oid, "1.3.6.1.128");
    }

    #[test]
    fn test_encode_oid_simple() {
        let encoded = encode_oid("1.3.6.1").unwrap();
        assert_eq!(encoded, vec![0x2B, 0x06, 0x01]);
    }

    #[test]
    fn test_encode_oid_system() {
        let encoded = encode_oid("1.3.6.1.2.1.1.1.0").unwrap();
        assert_eq!(encoded, vec![0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = "1.3.6.1.2.1.1.1.0";
        let encoded = encode_oid(original).unwrap();
        let decoded = decode_oid(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_oid_large_number() {
        let encoded = encode_oid("1.3.6.1.128").unwrap();
        assert_eq!(encoded, vec![0x2B, 0x06, 0x01, 0x81, 0x00]);
    }

    #[test]
    fn test_decode_varint_single_byte() {
        let data = [0x7F];
        let (value, consumed) = decode_varint(&data).unwrap();
        assert_eq!(value, 127);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_varint_two_bytes() {
        // 128 = 0x81 0x00
        let data = [0x81, 0x00];
        let (value, consumed) = decode_varint(&data).unwrap();
        assert_eq!(value, 128);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_decode_varint_large() {
        // 16383: encoded as [0xFF, 0x7F] (127*128 + 127)
        // First byte: 0xFF = 0x80 | 127 (continuation + value 127)
        // Second byte: 0x7F = 127 (no continuation)
        let data = [0xFF, 0x7F];
        let (value, consumed) = decode_varint(&data).unwrap();
        assert_eq!(value, 16383);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_decode_oid_empty() {
        let data = [];
        assert!(decode_oid(&data).is_none());
    }

    #[test]
    fn test_encode_oid_too_short() {
        assert!(encode_oid("1").is_none());
        assert!(encode_oid("").is_none());
    }
}
