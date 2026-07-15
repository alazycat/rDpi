pub fn is_mgcp(data: &[u8]) -> bool {
    let s = match std::str::from_utf8(data) { Ok(s) => s, _ => return false };
    s.starts_with("MGCP ") || s.starts_with("AUEP ") || s.starts_with("CRCX ")
}
pub fn detect(d: &[u8]) -> bool { is_mgcp(d) }
pub fn valid_sample() -> Vec<u8> { b"MGCP 1.0\x0d\x0a".to_vec() }
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_mgcp() { assert!(is_mgcp(b"MGCP 1.0\r\n")); }
    #[test] fn test_auep() { assert!(is_mgcp(b"AUEP 120\x0d\x0a")); }
    #[test] fn test_not() { assert!(!is_mgcp(b"GET /")); }
}
