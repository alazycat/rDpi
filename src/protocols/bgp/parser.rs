//! BGP protocol parser — Marker + message type detection

pub fn parse_bgp(data: &[u8]) -> Option<u8> {
    if data.len() < 19 { return None; }
    if !data[..16].iter().all(|&b| b == 0xff) { return None; }
    let msg_type = data[18];
    if msg_type < 1 || msg_type > 4 { return None; }
    Some(msg_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn build_bgp(msg_type: u8) -> Vec<u8> {
        let mut p = vec![0xff; 19];
        p[16..18].copy_from_slice(&[0x00, 0x13]); // length
        p[18] = msg_type;
        p
    }
    #[test] fn test_open() { assert_eq!(parse_bgp(&build_bgp(1)), Some(1)); }
    #[test] fn test_update() { assert_eq!(parse_bgp(&build_bgp(2)), Some(2)); }
    #[test] fn test_no_marker() { let mut p=build_bgp(1); p[0]=0; assert_eq!(parse_bgp(&p), None); }
    #[test] fn test_too_short() { assert_eq!(parse_bgp(&[0u8;18]), None); }
}
