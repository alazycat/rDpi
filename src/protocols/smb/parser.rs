//! SMB parsers (NBSS + SMB1/SMB2 headers).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SmbVersion {
    V1,
    V23,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SmbHeader {
    pub version: SmbVersion,
    pub command: Option<u16>,
    pub status: Option<u32>,
}

pub(crate) fn parse_nbss_length(payload: &[u8]) -> Option<usize> {
    if payload.len() < 4 || payload[0] != 0x00 {
        return None;
    }
    let length = ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | payload[3] as usize;
    if length < 4 {
        return None;
    }
    Some(length)
}

pub(crate) fn parse_smb(payload: &[u8]) -> Option<SmbHeader> {
    parse_nbss_length(payload)?;
    if payload.len() < 8 {
        return None;
    }
    let signature = &payload[4..8];
    if signature == &b"\xFFSMB"[..] {
        let command = payload.get(8).copied()? as u16;
        let status = payload
            .get(9..13)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        Some(SmbHeader {
            version: SmbVersion::V1,
            command: Some(command),
            status,
        })
    } else if signature == &b"\xFESMB"[..] {
        let status = payload
            .get(12..16)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        let command = payload
            .get(16..18)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]));
        Some(SmbHeader {
            version: SmbVersion::V23,
            command,
            status,
        })
    } else {
        None
    }
}

pub(crate) fn is_smb1_trans(payload: &[u8]) -> bool {
    parse_smb(payload)
        .is_some_and(|header| header.version == SmbVersion::V1 && header.command == Some(0x25))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nbss(payload: &[u8]) -> Vec<u8> {
        let length = payload.len();
        let mut out = vec![0x00, (length >> 16) as u8, (length >> 8) as u8, length as u8];
        out.extend_from_slice(payload);
        out
    }

    fn smb1(command: u8) -> Vec<u8> {
        let mut smb = b"\xFFSMB".to_vec();
        smb.push(command);
        smb.extend_from_slice(&0u32.to_le_bytes());
        smb.resize(32, 0);
        nbss(&smb)
    }

    fn smb2(command: u16) -> Vec<u8> {
        let mut smb = b"\xFESMB".to_vec();
        smb.extend_from_slice(&64u16.to_le_bytes());
        smb.extend_from_slice(&1u16.to_le_bytes());
        smb.extend_from_slice(&0u32.to_le_bytes());
        smb.extend_from_slice(&command.to_le_bytes());
        smb.resize(64, 0);
        nbss(&smb)
    }

    #[test]
    fn parses_smb1() {
        let payload = smb1(0x73);
        let header = parse_smb(&payload).unwrap();
        assert_eq!(header.version, SmbVersion::V1);
        assert_eq!(header.command, Some(0x73));
    }

    #[test]
    fn parses_smb23() {
        let payload = smb2(0x0000);
        let header = parse_smb(&payload).unwrap();
        assert_eq!(header.version, SmbVersion::V23);
        assert_eq!(header.command, Some(0x0000));
        assert_eq!(header.status, Some(0));
    }

    #[test]
    fn rejects_unknown_signature() {
        let payload = nbss(b"XXXX");
        assert!(parse_smb(&payload).is_none());
    }

    #[test]
    fn detects_smb1_trans() {
        assert!(is_smb1_trans(&smb1(0x25)));
        assert!(!is_smb1_trans(&smb1(0x73)));
        assert!(!is_smb1_trans(&smb2(0x0000)));
    }
}
