pub fn is_vxlan(data: &[u8]) -> bool {
    // 误报面审计 2026-11-05：旧判定仅看 Flags=0x08 与 data[1]==0，未校验保留位。
    // RFC 7348 VXLAN 头为 Flags(1B, 0x08) + Reserved(3B, 全 0) + VNI(3B) +
    // Reserved(1B)。收紧为 data[1..4] 三个保留位字节必须全 0。
    data.len() >= 8 && data[0] == 0x08 && data[1..4] == [0x00, 0x00, 0x00]
}
pub fn detect(d: &[u8]) -> bool {
    is_vxlan(d)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_match() {
        assert!(is_vxlan(&[0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
        assert!(is_vxlan(&valid_sample()));
    }
    #[test]
    fn test_wrong() {
        assert!(!is_vxlan(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    }
    #[test]
    fn test_short() {
        assert!(!is_vxlan(&[0x08]));
    }
    // 误报探针：旧判定命中、新判定拒绝
    #[test]
    fn test_fp_probe_reserved_byte2_set() {
        // Flags=0x08 但保留位第 2 字节非 0，旧判定误报
        assert!(!is_vxlan(&[0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]));
    }
    #[test]
    fn test_fp_probe_reserved_byte4_set() {
        // Flags=0x08 但保留位第 4 字节非 0，旧判定误报
        assert!(!is_vxlan(&[0x08, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00]));
    }
}
