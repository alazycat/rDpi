//! BER (Basic Encoding Rules) decoder for ASN.1
//!
//! This module provides a BER decoder for parsing ASN.1-encoded data.

use super::types::*;
use super::oid::decode_oid;

/// BER reader that tracks position in the byte buffer
pub struct BerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BerReader<'a> {
    /// Create a new BER reader
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Get current position
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Check if at end
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Read a single byte
    pub fn read_byte(&mut self) -> Option<u8> {
        if self.pos < self.data.len() {
            let byte = self.data[self.pos];
            self.pos += 1;
            Some(byte)
        } else {
            None
        }
    }

    /// Read multiple bytes
    pub fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n <= self.data.len() {
            let bytes = &self.data[self.pos..self.pos + n];
            self.pos += n;
            Some(bytes)
        } else {
            None
        }
    }

    /// Peek at next byte without advancing
    pub fn peek_byte(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Advance position by n bytes
    pub fn advance(&mut self, n: usize) -> bool {
        if self.pos + n <= self.data.len() {
            self.pos += n;
            true
        } else {
            false
        }
    }

    /// Decode a tag
    pub fn decode_tag(&mut self) -> Option<Asn1Tag> {
        let first_byte = self.read_byte()?;

        // Class: bits 6-7
        let class = match (first_byte >> 6) & 0x03 {
            0 => Asn1Class::Universal,
            1 => Asn1Class::Application,
            2 => Asn1Class::ContextSpecific,
            3 => Asn1Class::Private,
            _ => unreachable!(),
        };

        // Constructed: bit 5
        let constructed = (first_byte & 0x20) != 0;

        // Tag number: bits 0-4, or long form if all 1s
        let number = if (first_byte & 0x1F) == 0x1F {
            // Long form: subsequent bytes, each has continuation bit
            let mut num: u32 = 0;
            loop {
                let byte = self.read_byte()?;
                num = (num << 7) | ((byte & 0x7F) as u32);
                if (byte & 0x80) == 0 {
                    break;
                }
            }
            num
        } else {
            (first_byte & 0x1F) as u32
        };

        Some(Asn1Tag {
            class,
            constructed,
            number,
        })
    }

    /// Decode length
    pub fn decode_length(&mut self) -> Option<usize> {
        let first_byte = self.read_byte()?;

        if (first_byte & 0x80) == 0 {
            // Short form: 0-127
            Some(first_byte as usize)
        } else if first_byte == 0x80 {
            // Indefinite length (not supported)
            None
        } else {
            // Long form: first byte indicates number of length bytes
            let num_bytes = (first_byte & 0x7F) as usize;
            if num_bytes > 4 {
                return None; // Too long
            }

            let mut length: usize = 0;
            for _ in 0..num_bytes {
                let byte = self.read_byte()?;
                length = (length << 8) | (byte as usize);
            }
            Some(length)
        }
    }

    /// Decode TLV (Tag-Length-Value)
    pub fn decode_tlv(&mut self) -> Option<(Asn1Tag, &'a [u8])> {
        let tag = self.decode_tag()?;
        let length = self.decode_length()?;
        let value = self.read_bytes(length)?;
        Some((tag, value))
    }

    /// Decode a complete ASN.1 value
    pub fn decode_value(&mut self) -> Option<Asn1Value> {
        let start_pos = self.pos;
        let (tag, value_bytes) = self.decode_tlv()?;

        // Create a sub-reader for the value
        let mut value_reader = BerReader::new(value_bytes);

        match tag.class {
            Asn1Class::Universal => {
                match tag.number {
                    universal_tags::BOOLEAN => {
                        if value_bytes.len() != 1 {
                            return None;
                        }
                        Some(Asn1Value::Boolean(value_bytes[0] != 0))
                    }
                    universal_tags::INTEGER => {
                        decode_integer(value_bytes)
                    }
                    universal_tags::BIT_STRING => {
                        if value_bytes.is_empty() {
                            return None;
                        }
                        let unused_bits = value_bytes[0];
                        let data = value_bytes[1..].to_vec();
                        Some(Asn1Value::BitString(unused_bits, data))
                    }
                    universal_tags::OCTET_STRING => {
                        Some(Asn1Value::OctetString(value_bytes.to_vec()))
                    }
                    universal_tags::NULL => {
                        if !value_bytes.is_empty() {
                            return None;
                        }
                        Some(Asn1Value::Null)
                    }
                    universal_tags::OBJECT_IDENTIFIER => {
                        decode_oid(value_bytes).map(Asn1Value::Oid)
                    }
                    universal_tags::UTF8_STRING => {
                        String::from_utf8(value_bytes.to_vec())
                            .ok()
                            .map(Asn1Value::Utf8String)
                    }
                    universal_tags::SEQUENCE => {
                        decode_sequence(&mut value_reader)
                    }
                    universal_tags::SET => {
                        decode_set(&mut value_reader)
                    }
                    universal_tags::PRINTABLE_STRING => {
                        String::from_utf8(value_bytes.to_vec())
                            .ok()
                            .map(Asn1Value::PrintableString)
                    }
                    universal_tags::IA5_STRING => {
                        String::from_utf8(value_bytes.to_vec())
                            .ok()
                            .map(Asn1Value::Ia5String)
                    }
                    universal_tags::UTC_TIME => {
                        String::from_utf8(value_bytes.to_vec())
                            .ok()
                            .map(Asn1Value::UtcTime)
                    }
                    universal_tags::GENERALIZED_TIME => {
                        String::from_utf8(value_bytes.to_vec())
                            .ok()
                            .map(Asn1Value::GeneralizedTime)
                    }
                    _ => {
                        // Reset to read raw value
                        self.pos = start_pos;
                        let (tag, raw_bytes) = self.decode_tlv()?;
                        Some(Asn1Value::Raw(tag, raw_bytes.to_vec()))
                    }
                }
            }
            Asn1Class::Application => {
                Some(Asn1Value::Application(tag.number, value_bytes.to_vec()))
            }
            Asn1Class::ContextSpecific => {
                Some(Asn1Value::ContextSpecific(tag.number, value_bytes.to_vec()))
            }
            Asn1Class::Private => {
                Some(Asn1Value::Raw(tag, value_bytes.to_vec()))
            }
        }
    }
}

/// Decode an integer from BER encoding
fn decode_integer(bytes: &[u8]) -> Option<Asn1Value> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }

    // Handle sign extension
    let mut value: i64 = if (bytes[0] & 0x80) != 0 {
        -1i64
    } else {
        0i64
    };

    for &byte in bytes {
        value = (value << 8) | (byte as i64);
    }

    Some(Asn1Value::Integer(value))
}

/// Decode a SEQUENCE of values
fn decode_sequence(reader: &mut BerReader) -> Option<Asn1Value> {
    let mut values = Vec::new();
    while !reader.is_empty() {
        values.push(reader.decode_value()?);
    }
    Some(Asn1Value::Sequence(values))
}

/// Decode a SET of values
fn decode_set(reader: &mut BerReader) -> Option<Asn1Value> {
    let mut values = Vec::new();
    while !reader.is_empty() {
        values.push(reader.decode_value()?);
    }
    Some(Asn1Value::Set(values))
}

/// Parse a complete BER-encoded value from bytes
pub fn parse_ber(data: &[u8]) -> Option<Asn1Value> {
    let mut reader = BerReader::new(data);
    reader.decode_value()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_tag_short_form() {
        // Universal SEQUENCE (tag 0x30)
        let data = [0x30];
        let mut reader = BerReader::new(&data);
        let tag = reader.decode_tag().unwrap();
        assert_eq!(tag.class, Asn1Class::Universal);
        assert!(tag.constructed);
        assert_eq!(tag.number, 0x10); // SEQUENCE
    }

    #[test]
    fn test_decode_length_short() {
        let data = [0x7F];
        let mut reader = BerReader::new(&data);
        assert_eq!(reader.decode_length(), Some(127));
    }

    #[test]
    fn test_decode_length_long() {
        // Length 128: 0x81 0x80
        let data = [0x81, 0x80];
        let mut reader = BerReader::new(&data);
        assert_eq!(reader.decode_length(), Some(128));
    }

    #[test]
    fn test_decode_length_two_bytes() {
        // Length 256: 0x82 0x01 0x00
        let data = [0x82, 0x01, 0x00];
        let mut reader = BerReader::new(&data);
        assert_eq!(reader.decode_length(), Some(256));
    }

    #[test]
    fn test_decode_integer_zero() {
        // INTEGER 0: 0x02 0x01 0x00
        let data = [0x02, 0x01, 0x00];
        let mut reader = BerReader::new(&data);
        let (tag, value) = reader.decode_tlv().unwrap();
        assert_eq!(tag.number, universal_tags::INTEGER);
        assert_eq!(value, &[0x00]);
    }

    #[test]
    fn test_decode_integer_positive() {
        // INTEGER 42: 0x02 0x01 0x2A
        let data = [0x02, 0x01, 0x2A];
        let mut reader = BerReader::new(&data);
        let (tag, value) = reader.decode_tlv().unwrap();
        assert_eq!(tag.number, universal_tags::INTEGER);
        let int_val = decode_integer(value).unwrap();
        assert_eq!(int_val, Asn1Value::Integer(42));
    }

    #[test]
    fn test_decode_integer_negative() {
        // INTEGER -1: 0x02 0x01 0xFF
        let data = [0x02, 0x01, 0xFF];
        let mut reader = BerReader::new(&data);
        let (_tag, value) = reader.decode_tlv().unwrap();
        let int_val = decode_integer(value).unwrap();
        assert_eq!(int_val, Asn1Value::Integer(-1));
    }

    #[test]
    fn test_decode_null() {
        // NULL: 0x05 0x00
        let data = [0x05, 0x00];
        let mut reader = BerReader::new(&data);
        let (tag, value) = reader.decode_tlv().unwrap();
        assert_eq!(tag.number, universal_tags::NULL);
        assert!(value.is_empty());
    }

    #[test]
    fn test_decode_octet_string() {
        // OCTET STRING "test": 0x04 0x04 0x74 0x65 0x73 0x74
        let data = [0x04, 0x04, 0x74, 0x65, 0x73, 0x74];
        let mut reader = BerReader::new(&data);
        let (tag, value) = reader.decode_tlv().unwrap();
        assert_eq!(tag.number, universal_tags::OCTET_STRING);
        assert_eq!(value, b"test");
    }

    #[test]
    fn test_decode_sequence() {
        // SEQUENCE { INTEGER 1, INTEGER 2 }: 0x30 0x06 0x02 0x01 0x01 0x02 0x01 0x02
        let data = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let mut reader = BerReader::new(&data);
        let (tag, _) = reader.decode_tlv().unwrap();
        assert_eq!(tag.number, universal_tags::SEQUENCE);
        assert!(tag.constructed);
    }

    #[test]
    fn test_parse_ber_full() {
        // INTEGER 127: 0x02 0x01 0x7F
        let data = [0x02, 0x01, 0x7F];
        let value = parse_ber(&data).unwrap();
        assert_eq!(value, Asn1Value::Integer(127));
    }

    #[test]
    fn test_decode_context_specific() {
        // Context-specific [0] with content: 0xA0 0x02 0x05 0x00
        let data = [0xA0, 0x02, 0x05, 0x00];
        let mut reader = BerReader::new(&data);
        let (tag, _) = reader.decode_tlv().unwrap();
        assert_eq!(tag.class, Asn1Class::ContextSpecific);
        assert_eq!(tag.number, 0);
    }

    #[test]
    fn test_decode_application() {
        // Application [1] IpAddress: 0x41 0x04 0x7F 0x00 0x00 0x01
        let data = [0x41, 0x04, 0x7F, 0x00, 0x00, 0x01];
        let mut reader = BerReader::new(&data);
        let (tag, _) = reader.decode_tlv().unwrap();
        assert_eq!(tag.class, Asn1Class::Application);
        assert_eq!(tag.number, 1);
    }
}
