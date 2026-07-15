pub fn is_pptp(data: &[u8]) -> bool {
    if data.len() < 8 { return false; }
    // PPTP control message: GRE flag 0x00, 0x01
    data[0] == 0x00 && data[1] == 0x01
}
pub fn detect(d: &[u8]) -> bool { is_pptp(d) }
pub fn valid_sample() -> Vec<u8> { vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] }
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_match() { assert!(is_pptp(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); }
    #[test] fn test_wrong() { assert!(!is_pptp(b"GET")); }
    #[test] fn test_short() { assert!(!is_pptp(&[0x00])); }
}
