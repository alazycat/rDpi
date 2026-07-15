//! TFTP: opcode-based detection
pub fn is_tftp(data: &[u8]) -> bool {
    if data.len() < 6 { return false; }
    let opcode = u16::from_be_bytes([data[0], data[1]]);
    (1..=5).contains(&opcode)
}
pub fn detect(data: &[u8]) -> bool { is_tftp(data) }
pub fn valid_sample() -> Vec<u8> { vec![0x00, 0x01, b'a', 0x00, b'b', 0x00] }
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_rrq() { assert!(is_tftp(&[0x00, 0x01, b'a', 0x00, b'b', 0x00])); }
    #[test] fn test_ack() { assert!(is_tftp(&[0x00, 0x04, 0x00, 0x01, 0x00, 0x00])); }
    #[test] fn test_too_short() { assert!(!is_tftp(&[0x00, 0x01, 0x00])); }
}
