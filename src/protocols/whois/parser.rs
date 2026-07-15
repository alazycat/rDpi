pub fn is_whois(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    data.iter().all(|&b| b.is_ascii_graphic() || b == b'\r' || b == b'\n' || b == b' ')
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_match() { assert!(is_whois(b"example.com\r\n")); }
    #[test] fn test_empty() { assert!(!is_whois(b"")); }
    #[test] fn test_binary() { assert!(!is_whois(&[0x00, 0x01])); }
}
pub fn sample_data() -> Vec<u8> { b"example.com".to_vec() }
pub fn detect(data: &[u8]) -> bool { is_whois(data) }
pub fn valid_sample() -> Vec<u8> { b"example.com\r\n".to_vec() }
