pub fn is_socks(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    data[0] == 0x04 || data[0] == 0x05
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_socks4() { assert!(is_socks(&[0x04, 0x01])); }
    #[test] fn test_socks5() { assert!(is_socks(&[0x05, 0x01])); }
    #[test] fn test_not_socks() { assert!(!is_socks(b"GET")); }
    #[test] fn test_empty() { assert!(!is_socks(&[])); }
}
pub fn sample_data() -> Vec<u8> { vec![0x05, 0x01, 0x00] }
pub fn detect(data: &[u8]) -> bool { is_socks(data) }
pub fn valid_sample() -> Vec<u8> { vec![0x05, 0x01, 0x00] }
