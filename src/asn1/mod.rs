//! ASN.1/BER encoding support for rDpi
//!
//! This module provides BER (Basic Encoding Rules) decoding for ASN.1 data,
//! used by protocols like SNMP, LDAP, and X.509 certificates.
//!
//! # Example
//!
//! ```
//! use rdpi::asn1::{parse_ber, Asn1Value};
//!
//! // Decode an INTEGER
//! let data = [0x02, 0x01, 0x42]; // INTEGER 66
//! let value = parse_ber(&data).unwrap();
//! assert_eq!(value, Asn1Value::Integer(66));
//! ```
//!
//! # OID Decoding
//!
//! ```
//! use rdpi::asn1::oid::decode_oid;
//!
//! // Decode OID 1.3.6.1 (iso.org.dod.internet)
//! let data = [0x2B, 0x06, 0x01];
//! let oid = decode_oid(&data).unwrap();
//! assert_eq!(oid, "1.3.6.1");
//! ```

mod ber;
pub mod oid;
mod types;

pub use ber::{parse_ber, BerReader};
pub use types::*;
