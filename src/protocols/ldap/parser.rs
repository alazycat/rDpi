//! LDAP protocol parser — ASN.1 SEQUENCE + BindRequest detection

/// Check if payload appears to be an LDAP BindRequest
pub fn is_ldap_bind(data: &[u8]) -> bool {
    // 误报面审计 2026-11-05：旧判定 `data[0]==0x30 && data.contains(&0x60)` 对任意
    // 含 0x60 字节的 SEQUENCE 开头载荷误报（其它 BER 编码协议、恰含该字节的文本
    // 均可命中），且不校验长度字段自洽。改为按 RFC 4511 BindRequest 的 BER 结构
    // 逐字段校验：外层 SEQUENCE 短格式长度自洽（len+2 不超载荷实际长度）+
    // msgID INTEGER (0x02 0x01 <val>，占 data[2..5]) + BindRequest [APPLICATION 0]
    // tag (0x60，data[5]) + version INTEGER tag/len (0x02 0x01，data[7..9])。
    data.len() >= 8
        && data[0] == 0x30
        && (data[1] as usize) + 2 <= data.len()
        && data[2] == 0x02
        && data[3] == 0x01
        && data[5] == 0x60
        && data[7] == 0x02
        && data[8] == 0x01
}

#[cfg(test)]
mod tests {
    use super::*;
    fn build_ldap() -> Vec<u8> {
        // 误报面审计 2026-11-05：长度字段改为与实际字节数自洽——外层 SEQUENCE
        // 0x12=18（msgID 3 + BindRequest 15），内层 BindRequest 0x0B=11
        // （version 3 + name 2+8）。
        let mut p = vec![0x30, 0x12]; // SEQUENCE, len=18
        p.extend_from_slice(&[0x02, 0x01, 0x01]); // INTEGER msgID=1
        p.extend_from_slice(&[0x60, 0x0B]); // BindRequest [APPLICATION 0], len=11
        p.extend_from_slice(&[0x02, 0x01, 0x03]); // version=3
        p.extend_from_slice(&[0x04, 0x08]); // OCTET STRING "cn=admin"
        p.extend_from_slice(b"cn=admin");
        p
    }
    #[test]
    fn test_ldap_bind() {
        assert!(is_ldap_bind(&build_ldap()));
    }
    #[test]
    fn test_not_ldap() {
        assert!(!is_ldap_bind(b"GET / HTTP"));
    }
    #[test]
    fn test_too_short() {
        assert!(!is_ldap_bind(&[0x30]));
    }
    // 误报探针：旧判定命中、新判定拒绝
    #[test]
    fn test_fp_probe_inconsistent_length() {
        // 旧判定只看 0x30 开头 + 含 0x60：外层长度字段与实际不符（声称 0x20，
        // 实际仅 20 字节）仍命中，新判定拒绝
        let mut p = vec![0x30, 0x20];
        p.extend_from_slice(&[0x02, 0x01, 0x01, 0x60, 0x18, 0x02, 0x01, 0x03, 0x04, 0x04]);
        p.extend_from_slice(b"cn=admin");
        assert!(!is_ldap_bind(&p));
    }
    #[test]
    fn test_fp_probe_0x60_not_bind_tag() {
        // 0x30 开头且中部含 0x60 字节，但结构上不是 msgID+BindRequest，旧判定误报
        assert!(!is_ldap_bind(&[
            0x30, 0x08, b'a', b'b', 0x60, b'c', b'd', b'e', b'f', b'g'
        ]));
    }
}
