//! TFTP: opcode + RRQ/WRQ 结构校验
//!
//! F10（risks.md）：旧实现仅校验 opcode ∈ 1..=5，任意以 0x00 0x01 开头的
//! 二进制 payload 碰巧命中 RRQ 即被认领。RRQ/WRQ 必须携带可打印的
//! filename\0 + mode\0；DATA/ACK/ERROR 结构固定，opcode 校验足够。

pub fn is_tftp(data: &[u8]) -> bool {
    if data.len() < 6 {
        return false;
    }
    let opcode = u16::from_be_bytes([data[0], data[1]]);
    match opcode {
        1 | 2 => is_rw_request(data),
        3..=5 => true,
        _ => false,
    }
}

fn is_printable(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(|&c| (0x20..=0x7e).contains(&c))
}

/// RRQ/WRQ：opcode + filename + 0 + mode + 0（filename/mode 均须可打印且非空）
fn is_rw_request(data: &[u8]) -> bool {
    let Some(nul1) = data[2..].iter().position(|&b| b == 0) else {
        return false;
    };
    if !is_printable(&data[2..2 + nul1]) {
        return false;
    }
    let rest = &data[2 + nul1 + 1..];
    let Some(nul2) = rest.iter().position(|&b| b == 0) else {
        return false;
    };
    is_printable(&rest[..nul2])
}
pub fn detect(data: &[u8]) -> bool {
    is_tftp(data)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    vec![0x00, 0x01, b'a', 0x00, b'b', 0x00]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rrq() {
        assert!(is_tftp(&[0x00, 0x01, b'a', 0x00, b'b', 0x00]));
    }
    #[test]
    fn test_ack() {
        assert!(is_tftp(&[0x00, 0x04, 0x00, 0x01, 0x00, 0x00]));
    }
    #[test]
    fn test_too_short() {
        assert!(!is_tftp(&[0x00, 0x01, 0x00]));
    }
    /// F10 探针 payload：opcode 碰巧为 RRQ，但 filename 为空二进制
    #[test]
    fn test_binary_rrq_rejected() {
        assert!(!is_tftp(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x01]));
    }
    /// filename 含不可打印字节
    #[test]
    fn test_non_printable_filename_rejected() {
        assert!(!is_tftp(&[0x00, 0x01, 0x01, 0x02, 0x00, b'b', 0x00]));
    }
    /// 缺 mode 字段
    #[test]
    fn test_missing_mode_rejected() {
        assert!(!is_tftp(&[0x00, 0x01, b'a', 0x00]));
    }
}
