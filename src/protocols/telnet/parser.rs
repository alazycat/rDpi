pub fn is_telnet(data: &[u8]) -> bool {
    // 误报面审计 2026-11-05：旧判定 `data[0]==0xFF && len>=3` 把任意 0xFF 开头的
    // 二进制载荷（JPEG 0xFF 转义序列、MP3 帧同步字等）误报为 Telnet。收紧为
    // IAC(0xFF) 后必须跟协商命令 SB(0xFA)/WILL(0xFB)/WONT(0xFC)/DO(0xFD)/
    // DONT(0xFE)。
    data.len() >= 3 && data[0] == 0xFF && (0xFA..=0xFE).contains(&data[1])
}
pub fn detect(d: &[u8]) -> bool {
    is_telnet(d)
}
#[cfg(test)]
pub fn valid_sample() -> Vec<u8> {
    vec![0xFF, 0xFB, 0x18]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_match() {
        assert!(is_telnet(&[0xFF, 0xFB, 0x18]));
        assert!(is_telnet(&valid_sample()));
    }
    #[test]
    fn test_not_telnet() {
        assert!(!is_telnet(b"HTTP"));
    }
    #[test]
    fn test_short() {
        assert!(!is_telnet(&[0xFF]));
    }
    // 误报探针：旧判定命中、新判定拒绝
    #[test]
    fn test_fp_probe_iac_nop() {
        // IAC 后跟 0x00（NOP）而非协商命令，旧判定误报
        assert!(!is_telnet(&[0xFF, 0x00, 0x00]));
    }
    #[test]
    fn test_fp_probe_iac_subend() {
        // IAC 后跟 0xF0（SE，子协商结束标记）而非协商命令，旧判定误报
        assert!(!is_telnet(&[0xFF, 0xF0, 0x18]));
    }
}
