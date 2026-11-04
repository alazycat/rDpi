//! OpenVPN protocol parser — control channel opcode detection

/// Check if payload is an OpenVPN control channel message
///
/// F9（risks.md）：旧实现仅看 `data[0] >> 3 ∈ 7..=10`，大写 ASCII 文本
/// （如 HTTP 请求 `GET ...`，'G'=0x47 → opcode 8）被误判为 OpenVPN 并
/// 抢先于 HttpDetector（注册顺序 openvpn 早于 http）。
/// 真实控制消息的 bytes 1-8 是 8 字节随机 session_id，可打印占比极低；
/// 故对可打印 ASCII 占比 ≥ 90% 的 payload 直接拒绝。
pub fn parse_openvpn(data: &[u8]) -> bool {
    if data.len() < 14 {
        return false;
    }
    let opcode = data[0] >> 3;
    // P_CONTROL_HARD_RESET_CLIENT_V2(7), _SERVER_V2(8),
    // P_CONTROL_SOFT_RESET_V1(9), P_CONTROL_V1(10)
    if !(7..=10).contains(&opcode) {
        return false;
    }
    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || b == b'\r' || b == b'\n' || b == b'\t')
        .count();
    printable * 100 < 90 * data.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ovpn(opcode: u8) -> Vec<u8> {
        let mut p = vec![opcode << 3 | 0x01]; // opcode + key_id=1
        p.extend_from_slice(&[0u8; 13]); // peer_id + session_id
        p
    }

    #[test]
    fn test_openvpn_hard_reset_client() {
        assert!(parse_openvpn(&build_ovpn(7)));
    }

    #[test]
    fn test_openvpn_hard_reset_server() {
        assert!(parse_openvpn(&build_ovpn(8)));
    }

    #[test]
    fn test_openvpn_invalid_opcode() {
        assert!(!parse_openvpn(&build_ovpn(3)));
    }

    #[test]
    fn test_openvpn_too_short() {
        assert!(!parse_openvpn(&[0u8; 10]));
        assert!(!parse_openvpn(&[]));
    }

    /// F9：可打印 ASCII 文本（opcode nibble 碰巧命中）必须拒绝
    #[test]
    fn test_openvpn_rejects_printable_text() {
        assert!(!parse_openvpn(
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ));
        assert!(!parse_openvpn(b"POST /api/v1/upload HTTP/1.1\r\n"));
    }
}
