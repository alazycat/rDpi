pub fn is_isakmp(data: &[u8]) -> bool {
    if data.len() < 20 { return false; }
    // ISAKMP header offset 17: version byte
    // bit 7-4: major version, bit 3-0: minor version
    // IKEv1 = 0x10, IKEv2 = 0x20
    let ver = data[17];
    let major = ver >> 4;
    major == 1 || major == 2
}
pub fn detect(data: &[u8]) -> bool { is_isakmp(data) }
pub fn valid_sample() -> Vec<u8> {
    let mut v = vec![0u8; 20];
    v[17] = 0x10; // IKEv1 major=1
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ike_pkt() -> Vec<u8> { let mut v=vec![0u8;20]; v[17]=0x10; v }
    #[test] fn test_match() { assert!(is_isakmp(&ike_pkt())); }
    #[test] fn test_wrong_ver() { let mut v=vec![0u8;20]; v[17]=0x30; assert!(!is_isakmp(&v)); }
    #[test] fn test_short() { assert!(!is_isakmp(&[0u8; 19])); }
}
