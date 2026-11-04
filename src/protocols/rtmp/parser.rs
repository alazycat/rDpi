pub fn is_rtmp_handshake(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    data[0] == 0x03
}
pub fn detect(data: &[u8]) -> bool {
    is_rtmp_handshake(data)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    vec![0x03, 0x00, 0x00, 0x00]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_match() {
        assert!(is_rtmp_handshake(&[0x03]));
    }
    #[test]
    fn test_not_rtmp() {
        assert!(!is_rtmp_handshake(b"GET"));
    }
    #[test]
    fn test_empty() {
        assert!(!is_rtmp_handshake(&[]));
    }
}
