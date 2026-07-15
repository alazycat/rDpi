//! OpenVPN protocol parser — control channel opcode detection

/// Check if payload is an OpenVPN control channel message
pub fn parse_openvpn(data: &[u8]) -> bool {
    if data.len() < 14 { return false; }
    let opcode = data[0] >> 3;
    // P_CONTROL_HARD_RESET_CLIENT_V2(7), _SERVER_V2(8),
    // P_CONTROL_SOFT_RESET_V1(9), P_CONTROL_V1(10)
    (7..=10).contains(&opcode)
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
}
