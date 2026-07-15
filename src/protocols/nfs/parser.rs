pub fn is_nfs_rpc(data: &[u8]) -> bool {
    if data.len() < 16 { return false; }
    // RPC header: xid(4) + msg_type(4) + rpc_vers(4) = 12
    // RPC version should be 2
    // msg_type: 0=call, 1=reply
    data[12] == 0x00 && data[13] == 0x00 && data[14] == 0x00 && data[15] == 0x02
}
#[cfg(test)]
mod tests {
    use super::*;
    fn rpc_call() -> Vec<u8> { let mut v = vec![0u8; 16]; v[12..16].copy_from_slice(&[0,0,0,2]); v }
    fn rpc_reply() -> Vec<u8> { let mut v = vec![0u8; 16]; v[8]=1; v[12..16].copy_from_slice(&[0,0,0,2]); v }
    #[test] fn test_call() { assert!(is_nfs_rpc(&rpc_call())); }
    #[test] fn test_short() { assert!(!is_nfs_rpc(&[0u8; 12])); }
    #[test] fn test_wrong_vers() { let mut v = vec![0u8; 16]; v[15]=3; assert!(!is_nfs_rpc(&v)); }
}
pub fn sample_data() -> Vec<u8> { let mut v=vec![0u8;20]; v[12..16].copy_from_slice(&[0,0,0,2]); v }
pub fn detect(data: &[u8]) -> bool { is_nfs_rpc(data) }
pub fn valid_sample() -> Vec<u8> { let mut v=vec![0u8;20]; v[12..16].copy_from_slice(&[0,0,0,2]); v }
