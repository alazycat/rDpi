pub fn is_rsync(data: &[u8]) -> bool { data.len() >= 7 && data[..7] == *b"@RSYNCD" }
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_match() { assert!(is_rsync(b"@RSYNCD: 30.0")); }
    #[test] fn test_no_match() { assert!(!is_rsync(b"HTTP/1.1")); }
    #[test] fn test_short() { assert!(!is_rsync(b"@RSYNC")); }
}
pub fn sample_data() -> Vec<u8> { b"@RSYNCD: 30.0".to_vec() }
pub fn detect(data: &[u8]) -> bool { is_rsync(data) }
pub fn valid_sample() -> Vec<u8> { b"@RSYNCD: 30.0".to_vec() }
