//! RTP/RTCP header parser for rDpi
//!
//! Parses the 12-byte fixed header of Real-time Transport Protocol (RTP)
//! and RTP Control Protocol (RTCP) packets.

/// Parsed RTP/RTCP header fields
#[derive(Debug, Clone)]
pub struct RtpHeader {
    /// RTP version (must be 2)
    pub version: u8,
    /// Padding flag
    pub padding: bool,
    /// Extension flag
    pub extension: bool,
    /// CSRC count (number of contributing sources)
    pub csrc_count: u8,
    /// Marker bit
    pub marker: bool,
    /// Payload type (PT)
    pub payload_type: u8,
    /// Sequence number
    pub sequence_number: u16,
    /// Timestamp
    pub timestamp: u32,
    /// Synchronization source identifier
    pub ssrc: u32,
    /// Whether this is an RTCP packet (PT 200-209)
    pub is_rtcp: bool,
}

/// Parse an RTP/RTCP 12-byte fixed header from raw bytes.
///
/// Returns `None` if:
/// - Data is shorter than 12 bytes
/// - RTP version is not 2
/// - SSRC is zero (invalid for real traffic)
pub fn parse_rtp_header(data: &[u8]) -> Option<RtpHeader> {
    if data.len() < 12 {
        return None;
    }

    let first = data[0];
    let second = data[1];
    let version = first >> 6;

    // RTP version must be 2
    if version != 2 {
        return None;
    }

    // RTP: second byte = M (bit 7) | PT (bits 6-0, 7-bit)
    // RTCP: second byte = PT (full 8-bit, values 200-209)
    let is_rtcp = (200..=209).contains(&second);
    let pt = if is_rtcp { second } else { second & 0x7F };

    let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    // SSRC must not be zero
    if ssrc == 0 {
        return None;
    }

    Some(RtpHeader {
        version,
        padding: (first >> 5) & 1 == 1,
        extension: (first >> 4) & 1 == 1,
        csrc_count: first & 0x0F,
        marker: (second >> 7) & 1 == 1,
        payload_type: pt,
        sequence_number: u16::from_be_bytes([data[2], data[3]]),
        timestamp: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        ssrc,
        is_rtcp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rtp_payload() -> Vec<u8> {
        let mut pkt = vec![0x80, 0x00]; // V=2, PT=0
        pkt.extend_from_slice(&[0x00, 0x01]); // seq=1
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]); // ts=100
        pkt.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // SSRC=0x12345678
        pkt
    }

    #[test]
    fn test_parse_rtp_header_valid() {
        let data = make_rtp_payload();
        let hdr = parse_rtp_header(&data).unwrap();
        assert!(!hdr.is_rtcp);
        assert_eq!(hdr.version, 2);
        assert_eq!(hdr.payload_type, 0);
        assert_eq!(hdr.ssrc, 0x12345678);
        assert_eq!(hdr.sequence_number, 1);
    }

    #[test]
    fn test_parse_rtp_wrong_version() {
        let mut data = make_rtp_payload();
        data[0] = 0x00;
        assert!(parse_rtp_header(&data).is_none());
    }

    #[test]
    fn test_parse_rtcp() {
        let mut data = make_rtp_payload();
        data[1] = 200; // PT=200 (SR)
        let hdr = parse_rtp_header(&data).unwrap();
        assert!(hdr.is_rtcp);
    }

    #[test]
    fn test_parse_rtp_short() {
        assert!(parse_rtp_header(&[0x80]).is_none());
    }

    #[test]
    fn test_parse_rtp_zero_ssrc() {
        let mut data = make_rtp_payload();
        data[8..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        assert!(parse_rtp_header(&data).is_none());
    }
}
