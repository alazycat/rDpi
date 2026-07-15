//! RDP protocol parser — TPKT + T.125 Connect-Initial detection

pub fn is_rdp_connect(data: &[u8]) -> bool {
    if data.len() < 7 { return false; }
    if data[0] != 0x03 || data[1] != 0x00 { return false; } // TPKT version=3
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < len { return false; }
    data[4..7] == [0x0e, 0xe0, 0x00] // T.125 Connect-Initial
}

#[cfg(test)]
mod tests {
    use super::*;
    fn build_rdp() -> Vec<u8> {
        let mut p = vec![0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00];
        p.extend(vec![0u8; 12]);
        p
    }
    #[test] fn test_rdp() { assert!(is_rdp_connect(&build_rdp())); }
    #[test] fn test_not_rdp() { assert!(!is_rdp_connect(b"HTTP")); }
    #[test] fn test_too_short() { assert!(!is_rdp_connect(&[0u8;6])); }
}
