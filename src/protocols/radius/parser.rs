pub fn is_radius(data: &[u8]) -> bool {
    if data.len() < 20 { return false; }
    let code = data[0];
    (1..=50).contains(&code) && data[1] == 0x01 // code valid + id=1 for simplicity
}
pub fn detect(d: &[u8]) -> bool { is_radius(d) }
pub fn valid_sample() -> Vec<u8> { let mut v=vec![0u8;20]; v[0]=1; v[1]=1; v[2]=0; v[3]=20; v }
#[cfg(test)] mod tests {
    use super::*;
    fn pkt() -> Vec<u8> { let mut v=vec![0u8;20]; v[0]=1; v[1]=1; v[2..4].copy_from_slice(&[0,20]); v }
    #[test] fn test_match() { assert!(is_radius(&pkt())); }
    #[test] fn test_wrong_code() { let mut v=pkt(); v[0]=0; assert!(!is_radius(&v)); }
    #[test] fn test_short() { assert!(!is_radius(&[0u8; 19])); }
}
