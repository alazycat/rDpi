pub fn is_vxlan(data: &[u8]) -> bool {
    if data.len() < 8 { return false; }
    data[0] == 0x08 && data[1] == 0x00 // flags + reserved
}
pub fn detect(d: &[u8]) -> bool { is_vxlan(d) }
pub fn valid_sample() -> Vec<u8> { vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] }
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_match() { assert!(is_vxlan(&[0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); }
    #[test] fn test_wrong() { assert!(!is_vxlan(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); }
    #[test] fn test_short() { assert!(!is_vxlan(&[0x08])); }
}
