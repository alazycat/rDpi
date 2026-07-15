pub fn is_l2tp(data: &[u8]) -> bool {
    if data.len() < 6 { return false; }
    // L2TP: T(1)+L(1)+reserved(2)=4, version should be 0x02
    let ver_field = u16::from_be_bytes([data[4], data[5]]);
    (ver_field & 0x000F) == 0x0002
}
pub fn detect(d: &[u8]) -> bool { is_l2tp(d) }
pub fn valid_sample() -> Vec<u8> { vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x02] }
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_match() { assert!(is_l2tp(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02])); }
    #[test] fn test_wrong() { assert!(!is_l2tp(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); }
    #[test] fn test_short() { assert!(!is_l2tp(&[0u8; 4])); }
}
