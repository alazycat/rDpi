pub fn is_h323(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    // Q.931: 0x08 = Q.931 call setup
    data[0] == 0x08
}
pub fn detect(d: &[u8]) -> bool { is_h323(d) }
pub fn valid_sample() -> Vec<u8> { vec![0x08, 0x00, 0x00, 0x00] }
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_match() { assert!(is_h323(&[0x08, 0x00, 0x00, 0x00])); }
    #[test] fn test_not() { assert!(!is_h323(b"GET")); }
    #[test] fn test_short() { assert!(!is_h323(&[0x08])); }
}
