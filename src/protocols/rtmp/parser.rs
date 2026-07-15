pub fn is_rtmp_handshake(data: &[u8]) -> bool {
    if data.len() < 1 { return false; }
    data[0] == 0x03
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_match() { assert!(is_rtmp_handshake(&[0x03])); }
    #[test] fn test_not_rtmp() { assert!(!is_rtmp_handshake(b"GET")); }
    #[test] fn test_empty() { assert!(!is_rtmp_handshake(&[])); }
}
pub fn sample_data() -> Vec<u8> { vec![0x03, 0x00, 0x00, 0x00] }
pub fn detect(data: &[u8]) -> bool { is_rtmp_handshake(data) }
pub fn valid_sample() -> Vec<u8> { vec![0x03, 0x00, 0x00, 0x00] }
