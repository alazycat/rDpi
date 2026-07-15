pub fn is_vnc(data: &[u8]) -> bool {
    data.len() >= 12 && &data[..3] == b"RFB"
}
pub fn detect(d: &[u8]) -> bool { is_vnc(d) }
pub fn valid_sample() -> Vec<u8> { b"RFB 003.008\n".to_vec() }
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_match() { assert!(is_vnc(b"RFB 003.008\n")); }
    #[test] fn test_not_vnc() { assert!(!is_vnc(b"HTTP/1.1")); }
    #[test] fn test_short() { assert!(!is_vnc(b"RF")); }
}
