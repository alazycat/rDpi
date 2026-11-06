use crate::core::TransportProto;
use crate::error::{Error, Result};
use crate::parser::ParsedPacket;
use std::net::IpAddr;

/// TCP 头部关键字段（F33：JA4T 指纹所需）
///
/// 固定容量栈结构：解析阶段零堆分配（detect 热路径铁律 2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeaderInfo {
    /// 标志位原样字节（SYN=0x02、ACK=0x10 等）
    pub flags: u8,
    /// 窗口大小（TCP 头原始值，未按缩放因子换算）
    pub window: u16,
    /// 选项 kind 序列长度（按出现顺序，含 NOP=1；EOL=0 终止走查）
    pub option_kinds_len: usize,
    /// 选项 kind 序列（选项区最长 40 字节 → kind 至多 40 个）
    pub option_kinds: [u8; 40],
    /// MSS 选项值（kind=2；缺省 0）
    pub mss: u16,
    /// 窗口缩放因子 shift（kind=3；缺省 0）
    pub window_scale: u8,
    /// IP TTL / IPv6 hop limit（F35：JA4L 时延指纹所需）
    pub ttl: u8,
}

// 手写 Default：[u8; 40] 超出 derive 支持的数组长度上限（32）
impl Default for TcpHeaderInfo {
    fn default() -> Self {
        Self {
            flags: 0,
            window: 0,
            option_kinds_len: 0,
            option_kinds: [0; 40],
            mss: 0,
            window_scale: 0,
            ttl: 0,
        }
    }
}

pub fn parse(data: &[u8], src_ip: IpAddr, dst_ip: IpAddr, ttl: u8) -> Result<ParsedPacket> {
    if data.len() < 20 {
        return Err(Error::TruncatedHeader);
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let data_offset = ((data[12] >> 4) as usize) * 4;

    // F33：提取 JA4T 所需头部字段。选项区逐选项走查一遍即得 kind 序列，
    // 无堆分配；畸形长度立即终止走查（payload 切分不受影响）。
    let mut tcp = TcpHeaderInfo {
        flags: data[13],
        window: u16::from_be_bytes([data[14], data[15]]),
        ttl,
        ..Default::default()
    };
    if data_offset > 20 && data_offset <= data.len() {
        let opts = &data[20..data_offset];
        let mut i = 0;
        while i < opts.len() {
            let kind = opts[i];
            if kind == 0 {
                // EOL：选项区结束，其余为填充
                break;
            }
            let len = if kind == 1 {
                // NOP：单字节，无长度字段
                1
            } else if i + 1 < opts.len()
                && opts[i + 1] >= 2
                && i + opts[i + 1] as usize <= opts.len()
            {
                opts[i + 1] as usize
            } else {
                break; // 畸形长度，终止
            };
            if kind == 2 && len >= 4 && i + 4 <= opts.len() {
                tcp.mss = u16::from_be_bytes([opts[i + 2], opts[i + 3]]);
            } else if kind == 3 && len == 3 {
                tcp.window_scale = opts[i + 2];
            }
            if tcp.option_kinds_len < tcp.option_kinds.len() {
                tcp.option_kinds[tcp.option_kinds_len] = kind;
                tcp.option_kinds_len += 1;
            }
            i += len;
        }
    }

    let payload = if data.len() > data_offset {
        data[data_offset..].to_vec()
    } else {
        vec![]
    };

    Ok(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        transport: TransportProto::Tcp,
        payload,
        tcp: Some(tcp),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造 TCP 头字节（20B 基础头 + 选项，data_offset 按 4 字节对齐）
    fn tcp_head(flags: u8, window: u16, options: &[u8]) -> Vec<u8> {
        let opt_padded = options.len() + (4 - options.len() % 4) % 4;
        let data_offset = 5 + opt_padded / 4;
        let mut h = Vec::with_capacity(data_offset * 4);
        h.extend_from_slice(&[0x00, 0x50]); // src_port
        h.extend_from_slice(&[0x01, 0xbb]); // dst_port
        h.extend_from_slice(&[0x00; 8]); // seq + ack
        h.push((data_offset as u8) << 4); // data offset
        h.push(flags);
        h.extend_from_slice(&window.to_be_bytes());
        h.extend_from_slice(&[0x00; 4]); // checksum + urgent
        h.extend_from_slice(options);
        h.resize(data_offset * 4, 0x00); // EOL 填充
        h
    }

    fn parse_head(flags: u8, window: u16, options: &[u8]) -> TcpHeaderInfo {
        parse(
            &tcp_head(flags, window, options),
            "1.1.1.1".parse().unwrap(),
            "2.2.2.2".parse().unwrap(),
            64,
        )
        .unwrap()
        .tcp
        .unwrap()
    }

    #[test]
    fn test_tcp_header_info_extraction() {
        // MSS(2/4) + NOP + WS(3/3) + NOP + NOP + SACK-Permitted(4/2)
        let info = parse_head(0x02, 64240, &[2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2]);
        assert_eq!(info.flags, 0x02);
        assert_eq!(info.window, 64240);
        assert_eq!(
            &info.option_kinds[..info.option_kinds_len],
            &[2, 1, 3, 1, 1, 4]
        );
        assert_eq!(info.mss, 1460);
        assert_eq!(info.window_scale, 8);
    }

    #[test]
    fn test_tcp_header_no_options() {
        let info = parse_head(0x02, 8192, &[]);
        assert_eq!(info.option_kinds_len, 0);
        assert_eq!(info.mss, 0);
        assert_eq!(info.window_scale, 0);
    }

    #[test]
    fn test_tcp_header_eol_padding_ignored() {
        // EOL(0) 之后的填充 0 不计入 kind 序列
        let info = parse_head(0x02, 5744, &[2, 4, 0x05, 0x9c, 0, 0, 0, 0]);
        assert_eq!(&info.option_kinds[..info.option_kinds_len], &[2]);
        assert_eq!(info.mss, 1436);
    }

    #[test]
    fn test_tcp_header_malformed_option_length() {
        // kind=2 声称长度 0（非法）→ 走查立即终止，不记录该 kind、不 panic
        let info = parse_head(0x02, 8192, &[2, 0, 1, 1, 0, 0, 0, 0]);
        assert_eq!(info.option_kinds_len, 0);
        assert_eq!(info.mss, 0);
    }

    #[test]
    fn test_tcp_header_truncated() {
        assert!(
            parse(
                &[0u8; 19],
                "1.1.1.1".parse().unwrap(),
                "2.2.2.2".parse().unwrap(),
                64
            )
            .is_err()
        );
    }
}
