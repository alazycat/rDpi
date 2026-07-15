pub fn is_syslog(data: &[u8]) -> bool {
    if data.len() < 5 { return false; }
    if data[0] != b'<' { return false; }
    let mut i = 1;
    while i < data.len() && data[i].is_ascii_digit() { i += 1; }
    i > 1 && i < data.len() && data[i] == b'>'
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_match() { assert!(is_syslog(b"<14>Mar 1 12:00 host sshd[1234]: test")); }
    #[test] fn test_no_bracket() { assert!(!is_syslog(b"hello")); }
    #[test] fn test_short() { assert!(!is_syslog(b"<5>")); }
    #[test] fn test_no_digit() { assert!(!is_syslog(b"<>test")); }
}
pub fn sample_data() -> Vec<u8> { b"<14>Mar 1 12:00 test".to_vec() }
pub fn detect(data: &[u8]) -> bool { is_syslog(data) }
pub fn valid_sample() -> Vec<u8> { b"<14>Mar  1 12:00 test".to_vec() }
