//! ASN.1 type definitions for BER decoding
//!
//! This module provides the core types used in ASN.1/BER encoding.

/// ASN.1 tag class
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asn1Class {
    /// Universal class (defined by ASN.1 standard)
    Universal,
    /// Application class (application-specific)
    Application,
    /// Context-specific class (context-dependent)
    ContextSpecific,
    /// Private class (private use)
    Private,
}

/// ASN.1 tag structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asn1Tag {
    /// Tag class
    pub class: Asn1Class,
    /// Constructed (true) or primitive (false)
    pub constructed: bool,
    /// Tag number
    pub number: u32,
}

/// Universal ASN.1 tag numbers
pub mod universal_tags {
    pub const BOOLEAN: u32 = 0x01;
    pub const INTEGER: u32 = 0x02;
    pub const BIT_STRING: u32 = 0x03;
    pub const OCTET_STRING: u32 = 0x04;
    pub const NULL: u32 = 0x05;
    pub const OBJECT_IDENTIFIER: u32 = 0x06;
    pub const UTF8_STRING: u32 = 0x0C;
    pub const SEQUENCE: u32 = 0x10;
    pub const SET: u32 = 0x11;
    pub const PRINTABLE_STRING: u32 = 0x13;
    pub const IA5_STRING: u32 = 0x16;
    pub const UTC_TIME: u32 = 0x17;
    pub const GENERALIZED_TIME: u32 = 0x18;
}

/// ASN.1 value representation
#[derive(Debug, Clone, PartialEq)]
pub enum Asn1Value {
    /// Boolean value
    Boolean(bool),
    /// Integer value
    Integer(i64),
    /// Bit string (unused bits, data)
    BitString(u8, Vec<u8>),
    /// Octet string
    OctetString(Vec<u8>),
    /// Null
    Null,
    /// Object identifier (OID) as dot-separated string
    Oid(String),
    /// UTF-8 string
    Utf8String(String),
    /// Sequence of values
    Sequence(Vec<Asn1Value>),
    /// Set of values
    Set(Vec<Asn1Value>),
    /// Printable string
    PrintableString(String),
    /// IA5 string
    Ia5String(String),
    /// UTC time
    UtcTime(String),
    /// Generalized time
    GeneralizedTime(String),
    /// Application-specific value (tag number, raw bytes)
    Application(u32, Vec<u8>),
    /// Context-specific value (tag number, raw bytes)
    ContextSpecific(u32, Vec<u8>),
    /// Unknown/unparsed value (tag, raw bytes)
    Raw(Asn1Tag, Vec<u8>),
}
