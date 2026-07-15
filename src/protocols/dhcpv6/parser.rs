pub fn is_dhcpv6(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    let mt = data[0];
    (1..=13).contains(&mt) && data[1] == 0x01 // Solicit/Advertise etc.
}
pub fn detect(d: &[u8]) -> bool { is_dhcpv6(d) }
pub fn valid_sample() -> Vec<u8> { vec![0x01, 0x01, 0x00, 0x00] } // Solicit
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_match() { assert!(is_dhcpv6(&[0x01, 0x01, 0x00, 0x00])); }
    #[test] fn test_wrong_type() { assert!(!is_dhcpv6(&[0xFF, 0x01, 0x00, 0x00])); }
    #[test] fn test_short() { assert!(!is_dhcpv6(&[0x01])); }
}
