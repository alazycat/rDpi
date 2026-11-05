//! QUIC protocol parser for rDpi
//!
//! Parses QUIC Initial packets for protocol detection.
//!
//! QUIC v1 Long Header first byte format (bits 7-0):
//! - Bit 7: Header Form (1 = Long Header)
//! - Bit 6: Fixed Bit (1 = QUIC v1 compliant)
//! - Bits 5-4: Packet Type (00 = Initial)
//! - Bits 3-2: Reserved
//! - Bits 1-0: Packet Number Length
//!
//! Initial packet detection: (first_byte & 0xF0) == 0xC0
//! This checks for Long Header (bit 7=1), Fixed Bit (bit 6=1), and Initial type (bits 5-4=00)

use super::crypto;

/// QUIC version constants (32-bit, big-endian on wire)
pub const QUIC_VERSION_1: u32 = 0x00000001;
pub const QUIC_VERSION_2: u32 = 0x6b3343cf;
pub const QUIC_VERSION_DRAFT29: u32 = 0xff00001d;
pub const QUIC_VERSION_DRAFT28: u32 = 0xff00001c;

/// QUIC Initial packet info extracted from the header
#[derive(Debug, Clone)]
pub struct QuicInitialInfo {
    /// QUIC version number
    pub version: u32,
    /// Destination Connection ID length
    pub dcid_len: u8,
    /// Destination Connection ID bytes
    pub dcid: Vec<u8>,
    /// Source Connection ID length
    pub scid_len: u8,
    /// Source Connection ID bytes
    pub scid: Vec<u8>,
    /// Token length (varint)
    pub token_len: u64,
    /// Token bytes
    pub token: Vec<u8>,
}

/// Check if the packet is a QUIC Initial packet
///
/// Returns true if:
/// - First byte indicates Long Header with Initial type
/// - (first_byte & 0xF0) == 0xC0
///
/// This means:
/// - Bit 7 (Header Form) = 1 (Long Header)
/// - Bit 6 (Fixed Bit) = 1 (QUIC v1 compliant)
/// - Bits 5-4 (Packet Type) = 00 (Initial)
pub fn is_quic_initial(data: &[u8]) -> bool {
    !data.is_empty() && (data[0] & 0xF0) == 0xC0
}

/// 判断是否为 QUIC 长包头（Header Form bit = 1）
///
/// 覆盖 Initial/0-RTT/Handshake/Retry/Version Negotiation 全部长包头类型。
/// VN 包 version=0 且不要求 Fixed Bit；其余类型由调用方结合 version 判定。
pub fn is_quic_long_header(data: &[u8]) -> bool {
    data.len() >= 5 && (data[0] & 0x80) != 0
}

/// 解析长包头 DCID（offset 5：1 字节长度 + DCID，0-20 字节）
///
/// Initial/0-RTT/Handshake/Retry/VN 共用此前缀。
pub fn parse_long_header_dcid(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 6 {
        return None;
    }
    let len = data[5] as usize;
    if len > 20 || data.len() < 6 + len {
        return None;
    }
    Some(data[6..6 + len].to_vec())
}

/// Parse QUIC version from packet
///
/// For Long Header packets, version is at offset 1-4 (4 bytes, big-endian).
/// Returns None if packet is too short.
pub fn parse_quic_version(data: &[u8]) -> Option<u32> {
    if data.len() < 5 {
        return None;
    }

    // Version is bytes 1-4 for Long Header
    Some(u32::from_be_bytes([data[1], data[2], data[3], data[4]]))
}

/// Parse a QUIC varint from the data
///
/// QUIC varint format:
/// | Prefix | Length | Value range |
/// |--------|--------|-------------|
/// | 00     | 1 byte | 0-63        |
/// | 01     | 2 bytes| 0-16383     |
/// | 10     | 4 bytes| 0-1073741823|
/// | 11     | 8 bytes| 0-4611686018427387903|
///
/// Returns (value, bytes_consumed) on success, None on failure.
pub fn parse_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }

    let first_byte = data[0];
    let prefix = (first_byte >> 6) & 0x03;
    let length = 1 << prefix; // 1, 2, 4, or 8 bytes

    if data.len() < length {
        return None;
    }

    let value = match prefix {
        0 => {
            // 1 byte: lower 6 bits
            u64::from(first_byte & 0x3F)
        }
        1 => {
            // 2 bytes: lower 6 bits + next byte
            u64::from(first_byte & 0x3F) << 8 | u64::from(data[1])
        }
        2 => {
            // 4 bytes: lower 6 bits + next 3 bytes
            u64::from(first_byte & 0x3F) << 24
                | u64::from(data[1]) << 16
                | u64::from(data[2]) << 8
                | u64::from(data[3])
        }
        3 => {
            // 8 bytes: lower 6 bits + next 7 bytes
            u64::from(first_byte & 0x3F) << 56
                | u64::from(data[1]) << 48
                | u64::from(data[2]) << 40
                | u64::from(data[3]) << 32
                | u64::from(data[4]) << 24
                | u64::from(data[5]) << 16
                | u64::from(data[6]) << 8
                | u64::from(data[7])
        }
        _ => unreachable!(), // prefix is always 0-3
    };

    Some((value, length))
}

/// Parse a QUIC Initial packet
///
/// Long Header format:
/// - First byte: Header Form + Packet Type + Reserved + Packet Number Length
/// - Version (4 bytes)
/// - DCID Length (1 byte) + DCID (0-20 bytes)
/// - SCID Length (1 byte) + SCID (0-20 bytes)
/// - Token Length (varint) + Token
/// - Packet Number + Payload
///
/// Note: This parser only extracts header information, not the encrypted payload.
/// Use [`decrypt_initial`] for payload decryption.
pub fn parse_quic_initial(data: &[u8]) -> Option<QuicInitialInfo> {
    parse_initial_header(data).map(|(info, _, _)| info)
}

/// 解析 Initial 包头部，返回头部信息与 packet number 字段偏移
///
/// packet number 字段紧随 Token 之后，偏移即受保护载荷的起点。
fn parse_initial_header(data: &[u8]) -> Option<(QuicInitialInfo, usize, u64)> {
    if !is_quic_initial(data) {
        return None;
    }

    // Minimum: 1 (type) + 4 (version) + 1 (dcid_len) + 1 (scid_len) + 1 (token_len min)
    if data.len() < 8 {
        return None;
    }

    // Parse version
    let version = parse_quic_version(data)?;

    // Offset after version (byte 5)
    let mut offset = 5;

    // Parse DCID length and DCID
    let dcid_len = data[offset];
    offset += 1;

    if offset + dcid_len as usize > data.len() {
        return None;
    }

    let dcid = data[offset..offset + dcid_len as usize].to_vec();
    offset += dcid_len as usize;

    // Parse SCID length and SCID
    if offset >= data.len() {
        return None;
    }

    let scid_len = data[offset];
    offset += 1;

    if offset + scid_len as usize > data.len() {
        return None;
    }

    let scid = data[offset..offset + scid_len as usize].to_vec();
    offset += scid_len as usize;

    // Parse token length (varint)
    if offset >= data.len() {
        return None;
    }

    let (token_len, varint_len) = parse_varint(&data[offset..])?;
    offset += varint_len;

    // Check token length doesn't overflow
    if token_len > usize::MAX as u64 {
        return None;
    }

    let token_len_usize = token_len as usize;

    if offset + token_len_usize > data.len() {
        return None;
    }

    let token = data[offset..offset + token_len_usize].to_vec();
    offset += token_len_usize;

    // Length 字段（varint）：Packet Number + Payload 的总长度（RFC 9000 §17.2）
    if offset >= data.len() {
        return None;
    }
    let (packet_len, varint_len) = parse_varint(&data[offset..])?;
    offset += varint_len;

    let info = QuicInitialInfo {
        version,
        dcid_len,
        dcid,
        scid_len,
        scid,
        token_len,
        token,
    };

    // offset 此刻即 packet number 字段偏移；携带 Length 供解密确定包边界
    Some((info, offset, packet_len))
}

/// Convert QUIC version number to human-readable string
pub fn version_to_string(version: u32) -> Option<String> {
    match version {
        QUIC_VERSION_1 => Some("QUIC v1".to_string()),
        QUIC_VERSION_2 => Some("QUIC v2".to_string()),
        QUIC_VERSION_DRAFT29 => Some("QUIC Draft-29".to_string()),
        QUIC_VERSION_DRAFT28 => Some("QUIC Draft-28".to_string()),
        0 => None, // Version negotiation packet
        v => Some(format!("QUIC 0x{:08x}", v)),
    }
}

/// 解密客户端方向 QUIC Initial 包，返回明文帧数据（RFC 9001 §5）
///
/// 派生客户端 Initial 密钥（"client in"），移除头保护并做 AES-128-GCM 认证解密。
/// 服务端 Initial 或标签校验失败返回 None（调用方降级为仅头部信息）。
///
/// 注意：仅对 Initial 包调用（每流至多数个包），内部有少量堆分配（约 1-2 KiB）。
pub fn decrypt_initial(data: &[u8]) -> Option<Vec<u8>> {
    let (info, pn_offset, packet_len) = parse_initial_header(data)?;
    // 包边界：Length 覆盖 Packet Number + Payload；越界/异常长度按实际数据截断
    let packet_len = usize::try_from(packet_len).ok()?;
    let end = (pn_offset + packet_len).min(data.len());
    crypto::decrypt_initial_payload(
        &data[..end],
        pn_offset,
        info.version,
        &info.dcid,
        crypto::Side::Client,
    )
}

/// 解密服务端方向 QUIC Initial 包，返回明文帧数据（RFC 9001 §5）
///
/// 服务端 Initial 的 DCID 字段即 ODCID（客户端所选 CID），因此直接从包头
/// DCID 用 "server in" secret 派生密钥即可解密；其 CRYPTO 帧载荷为 ServerHello。
/// 解密失败返回 None。
pub fn decrypt_initial_server(data: &[u8]) -> Option<Vec<u8>> {
    let (info, pn_offset, packet_len) = parse_initial_header(data)?;
    let packet_len = usize::try_from(packet_len).ok()?;
    let end = (pn_offset + packet_len).min(data.len());
    crypto::decrypt_initial_payload(
        &data[..end],
        pn_offset,
        info.version,
        &info.dcid,
        crypto::Side::Server,
    )
}

/// 从解密后的 QUIC 帧数据中提取 CRYPTO 帧（帧类型 0x06）载荷
///
/// 遍历识别 PADDING(0x00)/PING(0x01)/CRYPTO(0x06) 三种帧；遇到其他帧（如 ACK）
/// 保守停止扫描。客户端 Initial 载荷即为这三种帧的组合，CRYPTO 载荷是裸 TLS
/// 握手消息（无 5 字节 record 头）。
pub fn parse_crypto_frames(plaintext: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;
    let mut crypto = Vec::new();
    while offset < plaintext.len() {
        let (frame_type, n) = parse_varint(&plaintext[offset..])?;
        match frame_type {
            0x00 | 0x01 => {
                // PADDING / PING：无载荷
                offset += n;
            }
            0x06 => {
                // CRYPTO：offset(varint) + length(varint) + data
                offset += n;
                let (_crypto_offset, n1) = parse_varint(&plaintext[offset..])?;
                offset += n1;
                let (length, n2) = parse_varint(&plaintext[offset..])?;
                offset += n2;
                let length = usize::try_from(length).ok()?;
                if offset + length > plaintext.len() {
                    return None;
                }
                crypto.extend_from_slice(&plaintext[offset..offset + length]);
                offset += length;
            }
            _ => break,
        }
    }
    if crypto.is_empty() {
        None
    } else {
        Some(crypto)
    }
}

/// 解密 QUIC v1 Initial 包并提取其中的 TLS ClientHello（需要 tls feature）
///
/// CRYPTO 帧载荷是裸握手消息；套上一个合成的 TLS record 头后复用现有
/// `tls::parse_client_hello`（SNI/ALPN/版本全套提取），ClientHello 跨包截断时
/// 返回 None（尽力而为，不做跨包重组）。
#[cfg(feature = "tls")]
pub fn decrypt_client_hello(data: &[u8]) -> Option<crate::protocols::tls::ClientHelloInfo> {
    let plaintext = decrypt_initial(data)?;
    let crypto = parse_crypto_frames(&plaintext)?;

    // 裸握手消息：type(1B) + length(3B)，ClientHello type = 0x01
    if crypto.len() < 4 || crypto[0] != 0x01 {
        return None;
    }
    // 合成 record 头：Handshake + legacy_version + length（握手消息长度可表达于 u16）
    let hs_len = crypto.len();
    if hs_len > 0xffff {
        return None;
    }
    let mut record = Vec::with_capacity(5 + hs_len);
    record.extend_from_slice(&[0x16, 0x03, 0x03, (hs_len >> 8) as u8, (hs_len & 0xff) as u8]);
    record.extend_from_slice(&crypto);

    crate::protocols::tls::parse_client_hello(&record)
}

/// 解密服务端 Initial 包并从 CRYPTO 帧的 ServerHello 提取 ALPN（需要 tls feature）
///
/// 服务端 Initial 的 CRYPTO 帧载荷为 ServerHello（RFC 9000 §7.2：QUIC 握手强制
/// 携带 ALPN）；ServerHello 无 SNI，故本函数仅返回 ALPN。
#[cfg(feature = "tls")]
pub fn decrypt_server_alpn(data: &[u8]) -> Option<String> {
    let plaintext = decrypt_initial_server(data)?;
    let crypto = parse_crypto_frames(&plaintext)?;

    // 裸握手消息：type(1B) + length(3B)，ServerHello type = 0x02
    if crypto.len() < 4 || crypto[0] != 0x02 {
        return None;
    }
    let hs_len = crypto.len();
    if hs_len > 0xffff {
        return None;
    }
    let mut record = Vec::with_capacity(5 + hs_len);
    record.extend_from_slice(&[0x16, 0x03, 0x03, (hs_len >> 8) as u8, (hs_len & 0xff) as u8]);
    record.extend_from_slice(&crypto);

    crate::protocols::tls::parse_server_hello_alpn(&record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_quic_initial_valid() {
        // Initial packet: Long Header (1) + Fixed Bit (1) + Initial (00) = 0xC0
        let data = [0xC0, 0x00, 0x00, 0x00, 0x01];
        assert!(is_quic_initial(&data));
    }

    #[test]
    fn test_is_quic_initial_invalid_short_header() {
        // Short header: bit 7 = 0
        let data = [0x40, 0x00, 0x00, 0x00, 0x01];
        assert!(!is_quic_initial(&data));
    }

    #[test]
    fn test_is_quic_initial_invalid_not_initial() {
        // Long Header but not Initial (e.g., 0xD0 = 0b11010000 = Handshake)
        let data = [0xD0, 0x00, 0x00, 0x00, 0x01];
        assert!(!is_quic_initial(&data));
    }

    #[test]
    fn test_is_quic_initial_empty() {
        let data: [u8; 0] = [];
        assert!(!is_quic_initial(&data));
    }

    #[test]
    fn test_parse_quic_version_valid() {
        // QUIC v1
        let data = [0xC0, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert_eq!(parse_quic_version(&data), Some(QUIC_VERSION_1));
    }

    #[test]
    fn test_parse_quic_version_v2() {
        // QUIC v2: 0x6b3343cf
        let data = [0xC0, 0x6b, 0x33, 0x43, 0xcf, 0x00];
        assert_eq!(parse_quic_version(&data), Some(QUIC_VERSION_2));
    }

    #[test]
    fn test_parse_quic_version_too_short() {
        let data = [0xC0, 0x00, 0x00];
        assert_eq!(parse_quic_version(&data), None);
    }

    #[test]
    fn test_parse_varint_1_byte() {
        // Prefix 00: 1 byte, value in lower 6 bits
        let data = [0x25]; // 0b00100101 = 37
        assert_eq!(parse_varint(&data), Some((37, 1)));
    }

    #[test]
    fn test_parse_varint_2_bytes() {
        // Prefix 01: 2 bytes
        let data = [0x40, 0x10]; // 16
        assert_eq!(parse_varint(&data), Some((16, 2)));
    }

    #[test]
    fn test_parse_varint_4_bytes() {
        // Prefix 10: 4 bytes
        let data = [0x80, 0x01, 0x00, 0x00]; // 65536
        assert_eq!(parse_varint(&data), Some((65536, 4)));
    }

    #[test]
    fn test_parse_varint_8_bytes() {
        // Prefix 11: 8 bytes
        let data = [
            0xC0 | 0x01, // Lower 6 bits = 1
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        // Value = 1 << 56
        assert_eq!(parse_varint(&data), Some((72057594037927936, 8)));
    }

    #[test]
    fn test_parse_varint_max_1_byte() {
        // Max 1-byte varint: 63 (0x3F)
        let data = [0x3F];
        assert_eq!(parse_varint(&data), Some((63, 1)));
    }

    #[test]
    fn test_parse_varint_empty() {
        let data: [u8; 0] = [];
        assert_eq!(parse_varint(&data), None);
    }

    #[test]
    fn test_parse_varint_too_short() {
        // Needs 2 bytes but only 1 provided
        let data = [0x40];
        assert_eq!(parse_varint(&data), None);
    }

    /// Helper to construct a minimal QUIC Initial packet for testing
    fn make_minimal_quic_initial() -> Vec<u8> {
        let mut data = vec![
            0xC0, // Long Header + Initial
            0x00, 0x00, 0x00, 0x01, // Version: QUIC v1
            0x08, // DCID Length: 8
        ];
        // DCID: 8 bytes
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        data.push(0x00); // SCID Length: 0
        data.push(0x00); // Token Length: 0 (1-byte varint)
        data.push(0x02); // Packet Number Length: 2 bytes (encoded in first byte bits 1-0)
        data.extend_from_slice(&[0x00, 0x01]); // Minimal payload placeholder
        data
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// RFC 9001 附录 A.2 官方样例：客户端 Initial 包中的 CRYPTO 帧
    /// （含完整 ClientHello，SNI = "example.com"，ALPN = "alpn"，共 245 字节）
    const A2_CLIENT_CRYPTO_FRAME: &str = concat!(
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868",
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578",
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005",
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba",
        "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400",
        "0d0010000e0403050306030203080408050806002d00020101001c0002400100",
        "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000",
        "75300901100f088394c8f03e51570806048000ffff",
    );

    /// 用 RFC 9001 A.2 样例材料构造完整受保护 Initial 包
    ///
    /// 帧后补零至 1182 字节载荷（对齐官方样例 Length=0x449e、pn=2），
    /// 复现出的包与 RFC 9001 A.2 的输入完全一致。
    fn make_a2_sample_packet() -> Vec<u8> {
        let dcid = hex("8394c8f03e515708");
        let frame = hex(A2_CLIENT_CRYPTO_FRAME);
        assert_eq!(frame.len(), 245);
        // 官方样例：Length = 0x449e = 1182 = pn(4) + 载荷 + tag(16)
        let pad_len = 1182 - 4 - 16 - frame.len();
        let frames = [frame, vec![0u8; pad_len]].concat();
        crypto::build_initial_packet(QUIC_VERSION_1, &dcid, 2, &frames, crypto::Side::Client)
    }

    #[test]
    fn test_decrypt_rfc9001_a2_sample() {
        let packet = make_a2_sample_packet();

        // 解密即完整验证：头保护移除错误 → AAD 错误 → tag 校验失败
        let plaintext = decrypt_initial(&packet).expect("RFC 9001 A.2 样例应能成功解密");

        // 官方样例载荷 = CRYPTO 帧 + 零填充；验证 CRYPTO 帧提取
        let crypto = parse_crypto_frames(&plaintext).expect("应提取出 CRYPTO 帧载荷");
        assert_eq!(crypto.len(), 241);
        assert_eq!(&to_hex(&crypto)[..16], "010000ed0303ebf8"); // ClientHello 开头

        // 端到端：解密 → CRYPTO 帧 → TLS ClientHello → SNI/ALPN
        #[cfg(feature = "tls")]
        {
            let ch = decrypt_client_hello(&packet).expect("应解析出 ClientHello");
            assert_eq!(ch.sni.as_deref(), Some("example.com"));
            assert_eq!(ch.alpn.as_deref(), Some("alpn"));
        }
    }

    /// 打印 A.2 样例受保护包的 hex（用于生成 tests/test_quic.rs 集成测试夹具）
    #[test]
    fn test_print_a2_fixture() {
        let packet = make_a2_sample_packet();
        println!("A2_FIXTURE_LEN={}", packet.len());
        println!("A2_FIXTURE={}", to_hex(&packet));
    }

    /// 构造最小 ServerHello（RFC 8446 §4.1.3，QUIC 形态：32B session_id_echo，
    /// compression 0x00，仅 ALPN 扩展携带 "h3"）
    fn make_server_hello() -> Vec<u8> {
        let mut sh = Vec::new();
        sh.push(0x02); // msg_type ServerHello
        sh.extend_from_slice(&[0x00, 0x00, 0x00]); // 握手长度占位，最后回填
        sh.extend_from_slice(&[0x03, 0x03]); // legacy_version
        sh.extend_from_slice(&[0x11u8; 32]); // random
        sh.push(32); // legacy_session_id_echo 长度
        sh.extend_from_slice(&[0x22u8; 32]);
        sh.extend_from_slice(&[0x13, 0x01]); // cipher_suite TLS_AES_128_GCM_SHA256
        sh.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods: 1 种，0x00
        // 扩展区：总长(2B) + ALPN 扩展（type 0x0010 + len 5 + 数据）
        let ext_data: [u8; 5] = [0x00, 0x03, 0x02, 0x68, 0x33]; // list_len=3, name_len=2, "h3"
        let exts_len = (4 + ext_data.len()) as u16;
        sh.extend_from_slice(&exts_len.to_be_bytes());
        sh.extend_from_slice(&[0x00, 0x10]);
        sh.extend_from_slice(&[0x00, 0x05]);
        sh.extend_from_slice(&ext_data);

        // 回填握手长度（3 字节大端）
        let hs_len = sh.len() - 4;
        sh[1..4].copy_from_slice(&[(hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8]);
        sh
    }

    /// 构造服务端 Initial 包（服务端密钥加密，CRYPTO 帧 = ServerHello）
    fn make_server_initial_packet() -> Vec<u8> {
        let dcid = hex("8394c8f03e515708"); // 即 ODCID（服务端包 DCID = 客户端所选 CID）
        let sh = make_server_hello();
        // CRYPTO 帧：type 0x06 + offset(0x00) + length varint + ServerHello
        let mut frame = vec![0x06, 0x00];
        let hs_len = sh.len();
        if hs_len < 64 {
            frame.push(hs_len as u8);
        } else {
            // 2 字节 varint（hs_len < 16383）
            frame.push(0x40 | ((hs_len >> 8) as u8));
            frame.push((hs_len & 0xff) as u8);
        }
        frame.extend_from_slice(&sh);
        crypto::build_initial_packet(QUIC_VERSION_1, &dcid, 1, &frame, crypto::Side::Server)
    }

    #[test]
    fn test_decrypt_server_initial_and_extract_alpn() {
        let packet = make_server_initial_packet();

        // 客户端密钥无法解密服务端包（tag 校验失败）
        assert!(decrypt_initial(&packet).is_none());

        // 服务端密钥解密成功，CRYPTO 帧 = ServerHello
        let plaintext =
            decrypt_initial_server(&packet).expect("服务端 Initial 应能以服务端密钥解密");
        let crypto = parse_crypto_frames(&plaintext).expect("应提取出 CRYPTO 帧载荷");
        assert_eq!(crypto[0], 0x02); // ServerHello

        // 端到端：解密 → CRYPTO 帧 → TLS ServerHello → ALPN
        #[cfg(feature = "tls")]
        {
            let alpn = decrypt_server_alpn(&packet).expect("应解析出 ServerHello ALPN");
            assert_eq!(alpn, "h3");
        }
    }

    /// 检测器级：服务端 Initial 经 detect() 富化出 ALPN（sni 保持 None）
    #[test]
    #[cfg(feature = "tls")]
    fn test_detect_server_initial_yields_alpn() {
        use super::super::QuicDetector;
        use crate::core::types::{Confidence, Metadata, Protocol};
        use crate::protocols::ProtocolDetector;

        let packet = make_server_initial_packet();
        let result = QuicDetector::new().detect(&packet).expect("应识别为 QUIC");
        assert_eq!(result.protocol, Protocol::Quic);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Quic(meta) => {
                assert!(meta.sni.is_none(), "ServerHello 无 SNI");
                assert_eq!(meta.alpn.as_deref(), Some("h3"));
            }
            other => panic!("期望 Quic 元数据，实际 {:?}", other),
        }
    }

    #[test]
    #[cfg(feature = "tls")]
    fn test_parse_server_hello_alpn_standalone() {
        let sh = make_server_hello();
        let mut record = vec![0x16, 0x03, 0x03, (sh.len() >> 8) as u8, sh.len() as u8];
        record.extend_from_slice(&sh);
        assert_eq!(
            crate::protocols::tls::parse_server_hello_alpn(&record).as_deref(),
            Some("h3")
        );

        // 非 ServerHello（ClientHello type 0x01）拒绝
        let mut ch = sh;
        ch[0] = 0x01;
        let mut rec2 = vec![0x16, 0x03, 0x03, (ch.len() >> 8) as u8, ch.len() as u8];
        rec2.extend_from_slice(&ch);
        assert!(crate::protocols::tls::parse_server_hello_alpn(&rec2).is_none());
    }

    #[test]
    fn test_parse_quic_initial_minimal() {
        let data = make_minimal_quic_initial();
        assert!(is_quic_initial(&data));

        let result = parse_quic_initial(&data);
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.version, QUIC_VERSION_1);
        assert_eq!(info.dcid_len, 8);
        assert_eq!(
            info.dcid,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(info.scid_len, 0);
        assert!(info.scid.is_empty());
        assert_eq!(info.token_len, 0);
        assert!(info.token.is_empty());
    }

    #[test]
    fn test_parse_quic_initial_with_token() {
        let mut data = vec![
            0xC0, // Long Header + Initial
            0x00, 0x00, 0x00, 0x01, // Version: QUIC v1
            0x00, // DCID Length: 0
            0x00, // SCID Length: 0
            0x05, // Token Length: 5 (1-byte varint)
        ];
        data.extend_from_slice(b"token"); // Token
        data.extend_from_slice(&[0x00, 0x01]); // Minimal payload placeholder

        let result = parse_quic_initial(&data);
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.version, QUIC_VERSION_1);
        assert_eq!(info.token_len, 5);
        assert_eq!(info.token, b"token".to_vec());
    }

    #[test]
    fn test_parse_quic_initial_with_scid() {
        let mut data = vec![
            0xC0, // Long Header + Initial
            0x00, 0x00, 0x00, 0x01, // Version: QUIC v1
            0x00, // DCID Length: 0
            0x04, // SCID Length: 4
        ];
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // SCID
        data.push(0x00); // Token Length: 0
        data.extend_from_slice(&[0x00, 0x01]); // Minimal payload placeholder

        let result = parse_quic_initial(&data);
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.scid_len, 4);
        assert_eq!(info.scid, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_parse_quic_initial_quic_v2() {
        let data = vec![
            0xC0, // Long Header + Initial
            0x6b, 0x33, 0x43, 0xcf, // Version: QUIC v2
            0x00, // DCID Length: 0
            0x00, // SCID Length: 0
            0x00, // Token Length: 0
            0x00, 0x01, // Minimal payload
        ];

        let result = parse_quic_initial(&data);
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.version, QUIC_VERSION_2);
    }

    #[test]
    fn test_parse_quic_initial_too_short() {
        // Too short for parsing
        let data = [0xC0, 0x00, 0x00];
        assert!(parse_quic_initial(&data).is_none());
    }

    #[test]
    fn test_parse_quic_initial_not_initial() {
        // Handshake packet (0xD0)
        let data = [0xD0, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert!(parse_quic_initial(&data).is_none());
    }

    #[test]
    fn test_version_to_string() {
        assert_eq!(
            version_to_string(QUIC_VERSION_1),
            Some("QUIC v1".to_string())
        );
        assert_eq!(
            version_to_string(QUIC_VERSION_2),
            Some("QUIC v2".to_string())
        );
        assert_eq!(
            version_to_string(QUIC_VERSION_DRAFT29),
            Some("QUIC Draft-29".to_string())
        );
        assert_eq!(version_to_string(0), None); // Version negotiation
        assert_eq!(
            version_to_string(0x12345678),
            Some("QUIC 0x12345678".to_string())
        );
    }

    #[test]
    fn test_varint_integration_in_packet() {
        // Test with 2-byte token length varint
        let mut data = vec![
            0xC0, // Long Header + Initial
            0x00, 0x00, 0x00, 0x01, // Version: QUIC v1
            0x00, // DCID Length: 0
            0x00, // SCID Length: 0
            0x40, 0x64, // Token Length: 100 (2-byte varint: 0x4064)
        ];
        data.extend_from_slice(&[0u8; 100]); // Token: 100 zero bytes
        data.extend_from_slice(&[0x00, 0x01]); // Minimal payload

        let result = parse_quic_initial(&data);
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.token_len, 100);
    }
}
