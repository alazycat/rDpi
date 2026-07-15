pub fn is_ptpv2(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    // PTPv2: transportSpecific(4 bits) + messageType(4 bits),  then versionPTP = 2
    // Byte 1: versionPTP should be 2
    // Byte 0: messageLength field first nibble
    // Byte 1: versionPTP (lower 4 bits = version, should be 2)
    let version = data[1] & 0x0f;
    version == 0x02
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_match() { assert!(is_ptpv2(&[0x00, 0x02, 0x00, 0x00])); }
    #[test] fn test_wrong_version() { assert!(!is_ptpv2(&[0x00, 0x01, 0x00, 0x00])); }
    #[test] fn test_short() { assert!(!is_ptpv2(&[0x00])); }
}
pub fn detect(data: &[u8]) -> bool { is_ptpv2(data) }
pub fn valid_sample() -> Vec<u8> { vec![0x00, 0x02, 0x00, 0x00] }
