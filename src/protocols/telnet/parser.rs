pub fn is_telnet(data: &[u8]) -> bool {
    data.len() >= 3 && data[0] == 0xFF
}
pub fn detect(d: &[u8]) -> bool { is_telnet(d) }
pub fn valid_sample() -> Vec<u8> { vec![0xFF, 0xFB, 0x18] }
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_match() { assert!(is_telnet(&[0xFF, 0xFB, 0x18])); }
    #[test] fn test_not_telnet() { assert!(!is_telnet(b"HTTP")); }
    #[test] fn test_short() { assert!(!is_telnet(&[0xFF])); }
}
