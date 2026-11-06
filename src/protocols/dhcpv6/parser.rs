pub fn is_dhcpv6(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let mt = data[0];
    // 误报面审计 2026-11-05：删除 data[1]==0x01 约束——data[1] 是 3 字节随机
    // 事务 ID 的最高位（RFC 8415 §8），固定 0x01 会漏判约 99.6% 真实流量；
    // 改为按 RFC 8415 报文结构做长度下界校验：
    // - type 1..=11（Solicit/Advertise/.../Confirm）：4 字节头 + 至少一个
    //   Client-ID option（code 2 + len 2 + DUID >= 2）=> len >= 10；
    // - type 12（Relay-forward）：type+hop+link-address(16)+peer-address(16)
    //   + 至少一个 option（code 2 + len 2 + >= 2）=> len >= 40；
    // - type 13（Relay-reply）：type+peer-address(16)+option >= 6 => len >= 23。
    match mt {
        1..=11 => data.len() >= 10,
        12 => data.len() >= 40,
        13 => data.len() >= 23,
        _ => false,
    }
}

/// DHCPv6 报文信息（JA4D6 指纹输入，F37）
#[derive(Debug, Clone, Default)]
pub struct Dhcpv6Info {
    /// RFC 8415 报文类型（1-13）
    pub msg_type: u8,
    /// Client Identifier（option 1）或 Server Identifier（option 2）的
    /// DUID 字节长度（取首个出现者；均缺省 → JA4D6 尺寸段 "0000"）
    pub duid_len: Option<u16>,
    /// option 4（IA_TA）出现标志 → JA4D6 第 3 段 'i'
    pub has_iata: bool,
    /// option 39（Client FQDN）出现标志 → JA4D6 第 4 段 'd'
    pub has_client_fqdn: bool,
    /// 选项码列表（按包内出现序，**不剔除任何选项**——官方行为）
    pub option_codes: Vec<u16>,
    /// option 6（Option Request）内 2 字节大端选项号列表（按序）
    pub oro: Vec<u16>,
}

/// 解析 DHCPv6 报文选项，提取 JA4D6 指纹所需字段
///
/// 仅解析最外层选项：Relay 消息（12/13）不递归 option 9 内层报文
/// （登记于 risks.md F37 边界）。畸形输入（长度越界）就地停止。
pub fn parse_dhcpv6_info(data: &[u8]) -> Option<Dhcpv6Info> {
    if !is_dhcpv6(data) {
        return None;
    }
    let msg_type = data[0];
    // 选项起始偏移（RFC 8415 §7.3）：type 1..=11 → 4（报文头）；
    // Relay 消息（12/13，同构：type+hop-count+link-address(16)+peer-address(16)）→ 34
    let start = if (1..=11).contains(&msg_type) { 4 } else { 34 };
    let mut info = Dhcpv6Info {
        msg_type,
        ..Dhcpv6Info::default()
    };
    let mut i = start;
    while i + 4 <= data.len() {
        let code = u16::from_be_bytes([data[i], data[i + 1]]);
        let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        i += 4;
        if i + len > data.len() {
            break; // 值被截断，停止解析
        }
        let value = &data[i..i + len];
        match code {
            1 | 2 => {
                if info.duid_len.is_none() {
                    info.duid_len = Some(len as u16);
                }
            }
            4 => info.has_iata = true,
            6 => {
                for chunk in value.as_chunks::<2>().0 {
                    info.oro.push(u16::from_be_bytes(*chunk));
                }
            }
            39 => info.has_client_fqdn = true,
            _ => {}
        }
        info.option_codes.push(code);
        i += len;
    }
    Some(info)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    // 误报面审计 2026-11-05：Solicit（type=1）+ 事务 ID + Client-ID option
    // （code 0x0001、len 0x0002、DUID 2 字节），共 10 字节满足结构下界
    vec![
        0x01, 0x00, 0x00, 0x00, // type=1 Solicit + 事务 ID 0x000000
        0x00, 0x01, // option code: OPTION_CLIENTID
        0x00, 0x02, // option len: 2
        0x01, 0x02, // DUID
    ]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_match() {
        assert!(is_dhcpv6(&valid_sample()));
    }
    #[test]
    fn test_wrong_type() {
        // type=0x00 非 RFC 8415 合法报文类型
        assert!(!is_dhcpv6(&[
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x01, 0x02
        ]));
        // type=14 超出 1..=13
        assert!(!is_dhcpv6(&[
            0x0E, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x01, 0x02
        ]));
    }
    #[test]
    fn test_short() {
        assert!(!is_dhcpv6(&[0x01]));
    }
    // ---- 误报面审计 2026-11-05 探针 ----
    #[test]
    fn test_probe_header_only_no_option() {
        // 旧判定命中（type=1 且 data[1]==0x01），新判定拒绝：
        // 4 字节报文无 Client-ID option，低于 RFC 8415 结构下界 10 字节
        assert!(!is_dhcpv6(&[0x01, 0x01, 0x00, 0x00]));
    }
    #[test]
    fn test_probe_truncated_option() {
        // 新判定拒绝：9 字节 Solicit，Client-ID option 的 DUID 被截断（len 9 < 10）
        assert!(!is_dhcpv6(&[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x01
        ]));
    }
    #[test]
    fn test_random_transaction_id_hit() {
        // 旧判定拒绝（data[1] != 0x01），新判定命中：
        // 随机事务 ID 的真实 Solicit 不再漏判
        assert!(is_dhcpv6(&[
            0x01, 0xA5, 0x24, 0xEF, // type=1 + 随机事务 ID
            0x00, 0x01, 0x00, 0x02, 0x01, 0x02, // Client-ID option
        ]));
    }
    #[test]
    fn test_relay_forward_hit() {
        // type=12 Relay-forward：type+hop+link-address(16)+peer-address(16)
        // + Client-ID option(6) = 40 字节，命中结构下界
        let mut v = vec![0u8; 40];
        v[0] = 12;
        v[1] = 1; // hop-count
        assert!(is_dhcpv6(&v));
    }
    #[test]
    fn test_relay_forward_too_short() {
        // 旧判定命中（type=12 且 data[1]==0x01），新判定拒绝：
        // Relay-forward 低于 40 字节结构下界（缺 link/peer address）
        assert!(!is_dhcpv6(&[0x0C, 0x01, 0x00, 0x00]));
    }
}
