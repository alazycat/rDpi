pub fn is_turn(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    let channel = u16::from_be_bytes([data[0], data[1]]);
    // TURN channel: 0x4000-0x7FFE, even only (RFC 5766 §11)
    channel >= 0x4000 && channel <= 0x7FFE && channel % 2 == 0
}
pub fn detect(d: &[u8]) -> bool { is_turn(d) }
pub fn valid_sample() -> Vec<u8> { vec![0x40, 0x00, 0x00, 0x04] }
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_channel() { assert!(is_turn(&[0x40, 0x00, 0x00, 0x04])); }
    #[test] fn test_not_turn() { assert!(!is_turn(b"test")); }
    #[test] fn test_odd_channel() { assert!(!is_turn(&[0x40, 0x01, 0x00, 0x04])); }
    #[test] fn test_short() { assert!(!is_turn(&[0x40])); }
}
