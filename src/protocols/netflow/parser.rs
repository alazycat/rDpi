pub fn is_netflow_v5(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x00 && data[1] == 0x05
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_match() { assert!(is_netflow_v5(&[0x00, 0x05, 0x00, 0x01])); }
    #[test] fn test_wrong_version() { assert!(!is_netflow_v5(&[0x00, 0x09])); }
    #[test] fn test_short() { assert!(!is_netflow_v5(&[0x00])); }
}
pub fn sample_data() -> Vec<u8> { vec![0x00, 0x05, 0x00, 0x01] }
pub fn detect(data: &[u8]) -> bool { is_netflow_v5(data) }
pub fn valid_sample() -> Vec<u8> { vec![0x00, 0x05, 0x00, 0x01] }
