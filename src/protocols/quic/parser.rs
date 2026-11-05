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

/// QUIC Retry 包解析结果（RFC 9000 §17.2.5）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicRetryInfo {
    /// QUIC 版本号
    pub version: u32,
    /// 包头 DCID 字段（= 触发 Retry 的客户端 Initial 包的 SCID）
    pub dcid: Vec<u8>,
    /// 包头 SCID 字段（客户端后续 Initial 必须改用该值作为 DCID）
    pub scid: Vec<u8>,
    /// Retry Token（头部之后、完整性标签之前的全部字节）
    pub token: Vec<u8>,
    /// 包尾 16 字节完整性标签（RFC 9001 §5.8）
    pub integrity_tag: [u8; 16],
}

/// Retry 包尾完整性标签长度（RFC 9001 §5.8）
const RETRY_INTEGRITY_TAG_SIZE: usize = 16;

/// 解析 QUIC Retry 包（仅结构自洽校验，不做完整性验证）
///
/// Retry 长包头无 Length 字段：DCID/SCID 之后到包尾 16 字节标签之前的
/// 全部字节均为 Retry Token。
///
/// 类型位按版本区分（RFC 9000 §17.2.5 / RFC 9369 §3.2）：
/// - QUIC v1：`(first_byte & 0x30) >> 4 == 0b11`（首字节 0xF0）
/// - QUIC v2：`(first_byte & 0x30) >> 4 == 0b00`（首字节 0xC0，类型映射重排）
///
/// draft 版本与 v2 类型位语义不匹配（避免与 v1 Initial 冲突），返回 None。
pub fn parse_retry_packet(data: &[u8]) -> Option<QuicRetryInfo> {
    let version = parse_quic_version(data)?;
    let is_retry_type = match version {
        QUIC_VERSION_1 => (data[0] & 0x30) == 0x30,
        QUIC_VERSION_2 => (data[0] & 0x30) == 0x00,
        _ => return None, // draft 版本类型位语义随草稿演进，不解析
    };
    if !is_quic_long_header(data) || (data[0] & 0x40) == 0 || !is_retry_type {
        return None;
    }

    // DCID / SCID（各 1 字节长度前缀 + 0-20 字节）
    let dcid = parse_long_header_dcid(data)?;
    let dcid_len = dcid.len();
    let scid_len_off = 6 + dcid_len;
    if data.len() < scid_len_off + 1 {
        return None;
    }
    let scid_len = data[scid_len_off] as usize;
    if scid_len > 20 || data.len() < scid_len_off + 1 + scid_len + RETRY_INTEGRITY_TAG_SIZE {
        return None;
    }
    let scid = data[scid_len_off + 1..scid_len_off + 1 + scid_len].to_vec();
    let token_end = data.len() - RETRY_INTEGRITY_TAG_SIZE;
    let token = data[scid_len_off + 1 + scid_len..token_end].to_vec();
    let mut integrity_tag = [0u8; 16];
    integrity_tag.copy_from_slice(&data[token_end..]);

    Some(QuicRetryInfo {
        version,
        dcid,
        scid,
        token,
        integrity_tag,
    })
}

/// 校验 QUIC Retry 包完整性（RFC 9001 §5.8）
///
/// AES-128-GCM：空明文、固定版本常数 key/nonce、AAD = Retry 伪包
/// （`odcid_len || odcid || retry_packet_without_tag`）。ODCID 为触发 Retry 的
/// 客户端 Initial 包的 DCID（DPI 场景下取自同一流的 Initial 元数据）。
///
/// 返回值：
/// - `Some(true)`：完整性标签匹配
/// - `Some(false)`：标签不匹配（伪造/注入或非标准实现）
/// - `None`：无法判定（格式非法、版本不支持、ODCID 缺失），调用方不得据此报警
pub fn verify_retry_integrity(retry_packet: &[u8], odcid: &[u8]) -> Option<bool> {
    if odcid.is_empty() {
        return None;
    }
    let info = parse_retry_packet(retry_packet)?;
    let without_tag = &retry_packet[..retry_packet.len() - RETRY_INTEGRITY_TAG_SIZE];
    let expected = crypto::retry_integrity_tag(without_tag, odcid, info.version)?;
    Some(expected == info.integrity_tag)
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

/// 解密客户端方向 Initial 包（带每 Detector 密钥缓存）——性能优化路径（F28）
///
/// 与 [`decrypt_initial`] 语义一致；缓存命中时免去 HKDF 派生 + AES 轮密钥扩展。
pub(crate) fn decrypt_initial_with_cache(
    data: &[u8],
    cache: &crypto::InitialKeyCache,
) -> Option<Vec<u8>> {
    let (info, pn_offset, packet_len) = parse_initial_header(data)?;
    let packet_len = usize::try_from(packet_len).ok()?;
    let end = (pn_offset + packet_len).min(data.len());
    let pre = cache.get_or_derive(info.version, &info.dcid, crypto::Side::Client)?;
    crypto::decrypt_initial_payload_with(&pre, &data[..end], pn_offset)
}

/// 解密服务端方向 Initial 包（带每 Detector 密钥缓存）——性能优化路径（F28）
pub(crate) fn decrypt_initial_server_with_cache(
    data: &[u8],
    cache: &crypto::InitialKeyCache,
) -> Option<Vec<u8>> {
    let (info, pn_offset, packet_len) = parse_initial_header(data)?;
    let packet_len = usize::try_from(packet_len).ok()?;
    let end = (pn_offset + packet_len).min(data.len());
    let pre = cache.get_or_derive(info.version, &info.dcid, crypto::Side::Server)?;
    crypto::decrypt_initial_payload_with(&pre, &data[..end], pn_offset)
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

/// 解析 QUIC Transport Parameters（RFC 9000 §18.2，ClientHello 0x0039 扩展值）
///
/// 序列为 `varint 参数 ID + varint 长度 + 值字节`；仅收录数值型参数（值本身为
/// varint）到 [`crate::core::types::QuicTransportParams`]，未知参数跳过。
/// 结构性损坏（截断/越界）返回 None；已知参数的值无法按 varint 解析时该字段留 None。
pub fn parse_transport_parameters(data: &[u8]) -> Option<crate::core::types::QuicTransportParams> {
    use crate::core::types::QuicTransportParams;

    let mut md = QuicTransportParams::default();
    let mut pos = 0usize;
    while pos < data.len() {
        // 参数 ID（varint）
        let (id, used) = parse_varint(&data[pos..])?;
        pos += used;
        // 值长度（varint）
        let (len, used) = parse_varint(&data[pos..])?;
        pos += used;
        let len = len as usize;
        if pos + len > data.len() {
            return None;
        }
        let value = &data[pos..pos + len];
        pos += len;
        match id {
            0x01 => md.max_idle_timeout = parse_varint(value).map(|(v, _)| v),
            0x03 => md.max_udp_payload_size = parse_varint(value).map(|(v, _)| v),
            0x04 => md.initial_max_data = parse_varint(value).map(|(v, _)| v),
            0x08 => md.initial_max_streams_bidi = parse_varint(value).map(|(v, _)| v),
            0x09 => md.initial_max_streams_uni = parse_varint(value).map(|(v, _)| v),
            _ => {}
        }
    }
    Some(md)
}

/// 解密 QUIC v1 Initial 包并提取其中的 TLS ClientHello（需要 tls feature）
///
/// CRYPTO 帧载荷是裸握手消息；套上一个合成的 TLS record 头后复用现有
/// `tls::parse_client_hello`（SNI/ALPN/版本全套提取），ClientHello 跨包截断时
/// 返回 None（尽力而为，不做跨包重组）。
#[cfg(feature = "tls")]
pub fn decrypt_client_hello(data: &[u8]) -> Option<crate::protocols::tls::ClientHelloInfo> {
    decrypt_client_meta(data).map(|(ch, _)| ch)
}

/// 解密客户端 Initial 包并提取 ClientHello + QUIC Transport Parameters（需要 tls feature）
///
/// 与 [`decrypt_client_hello`] 同一解密链路（单次解密，二者共用），额外从
/// ClientHello 的 0x0039 扩展解析 Transport Parameters；无该扩展或解析失败时
/// tp 为 None（不影响 ClientHello 字段）。
#[cfg(feature = "tls")]
pub fn decrypt_client_meta(
    data: &[u8],
) -> Option<(
    crate::protocols::tls::ClientHelloInfo,
    Option<crate::core::types::QuicTransportParams>,
)> {
    let plaintext = decrypt_initial(data)?;
    client_meta_from_plaintext(plaintext)
}

/// 带每 Detector 密钥缓存的 [`decrypt_client_meta`]（性能优化路径 F28）
#[cfg(feature = "tls")]
pub(crate) fn decrypt_client_meta_with_cache(
    data: &[u8],
    cache: &crypto::InitialKeyCache,
) -> Option<(
    crate::protocols::tls::ClientHelloInfo,
    Option<crate::core::types::QuicTransportParams>,
)> {
    let plaintext = decrypt_initial_with_cache(data, cache)?;
    client_meta_from_plaintext(plaintext)
}

/// 从解密后的 Initial 明文提取 ClientHello + Transport Parameters（共享后段）
#[cfg(feature = "tls")]
fn client_meta_from_plaintext(
    plaintext: Vec<u8>,
) -> Option<(
    crate::protocols::tls::ClientHelloInfo,
    Option<crate::core::types::QuicTransportParams>,
)> {
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

    let ch = crate::protocols::tls::parse_client_hello(&record)?;
    let tp = crate::protocols::tls::extract_quic_transport_parameters(&record)
        .and_then(|raw| parse_transport_parameters(&raw));
    Some((ch, tp))
}

/// 解密服务端 Initial 包并从 CRYPTO 帧的 ServerHello 提取 ALPN（需要 tls feature）
///
/// 服务端 Initial 的 CRYPTO 帧载荷为 ServerHello（RFC 9000 §7.2：QUIC 握手强制
/// 携带 ALPN）；ServerHello 无 SNI，故本函数仅返回 ALPN。
#[cfg(feature = "tls")]
pub fn decrypt_server_alpn(data: &[u8]) -> Option<String> {
    let plaintext = decrypt_initial_server(data)?;
    server_hello_from_plaintext(plaintext).and_then(|sh| sh.alpn)
}

/// 解密服务端 Initial 包并提取完整 ServerHello 字段（需要 tls feature）
///
/// 供 JA4S 服务端指纹计算使用：协商版本/选定密码套件/扩展列表/ALPN。
#[cfg(feature = "tls")]
pub fn decrypt_server_hello_meta(data: &[u8]) -> Option<crate::protocols::tls::ServerHelloInfo> {
    let plaintext = decrypt_initial_server(data)?;
    server_hello_from_plaintext(plaintext)
}

/// 带每 Detector 密钥缓存的 [`decrypt_server_hello_meta`]
#[cfg(feature = "tls")]
pub(crate) fn decrypt_server_hello_meta_with_cache(
    data: &[u8],
    cache: &crypto::InitialKeyCache,
) -> Option<crate::protocols::tls::ServerHelloInfo> {
    let plaintext = decrypt_initial_server_with_cache(data, cache)?;
    server_hello_from_plaintext(plaintext)
}

/// 从解密后的服务端 Initial 明文提取 ServerHello（共享后段）
#[cfg(feature = "tls")]
fn server_hello_from_plaintext(
    plaintext: Vec<u8>,
) -> Option<crate::protocols::tls::ServerHelloInfo> {
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

    crate::protocols::tls::parse_server_hello(&record)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==== Retry 包 golden 向量（独立实现交叉验证生成）====
    // 生成方式：Node.js OpenSSL（crypto.createCipheriv aes-128-gcm）按 RFC 9001 §5.8
    // 计算；key/nonce 常数与伪包构造经 quic-go retry.go 与 aioquic packet.py 双源核对。
    // ODCID = 0102030405060708；DCID = 11223344；SCID = aabbccddeeff0102；
    // Token = 0x20..0x43（36 字节）。
    const RETRY_V1: &str = "f000000001041122334408aabbccddeeff0102202122232425262728292a2b2c2d2e2f\
303132333435363738393a3b3c3d3e3f4041424355a0da97d3ec181617daab18fc9a0334";
    const RETRY_V2: &str = "c06b3343cf041122334408aabbccddeeff0102202122232425262728292a2b2c2d2e2f\
303132333435363738393a3b3c3d3e3f40414243c1c2be270155ab0b9726e21aca703b27";
    const ODCID: &str = "0102030405060708";

    #[test]
    fn test_parse_retry_packet_v1() {
        let data = hex(RETRY_V1);
        let info = parse_retry_packet(&data).expect("v1 Retry 应可解析");
        assert_eq!(info.version, QUIC_VERSION_1);
        assert_eq!(info.dcid, vec![0x11, 0x22, 0x33, 0x44]);
        assert_eq!(
            info.scid,
            vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02]
        );
        assert_eq!(info.token.len(), 36);
        assert_eq!(info.token[0], 0x20);
        assert_eq!(info.token[35], 0x43);
        assert_eq!(
            info.integrity_tag,
            [
                0x55, 0xa0, 0xda, 0x97, 0xd3, 0xec, 0x18, 0x16, 0x17, 0xda, 0xab, 0x18, 0xfc, 0x9a,
                0x03, 0x34
            ]
        );
    }

    #[test]
    fn test_verify_retry_integrity_v1_golden() {
        assert_eq!(
            verify_retry_integrity(&hex(RETRY_V1), &hex(ODCID)),
            Some(true)
        );
    }

    #[test]
    fn test_verify_retry_integrity_v2_golden() {
        // v2 Retry 首字节 0xC0（RFC 9369 类型位映射重排），不得与 v1 Initial 混淆
        assert_eq!(
            verify_retry_integrity(&hex(RETRY_V2), &hex(ODCID)),
            Some(true)
        );
    }

    #[test]
    fn test_verify_retry_integrity_tampered() {
        let mut data = hex(RETRY_V1);
        let last = data.len() - 1;
        data[last] ^= 0x01;
        assert_eq!(verify_retry_integrity(&data, &hex(ODCID)), Some(false));
    }

    #[test]
    fn test_verify_retry_integrity_wrong_odcid() {
        // ODCID 不匹配（伪包不同）→ 标签必然不匹配
        let wrong = hex("0102030405060709");
        assert_eq!(verify_retry_integrity(&hex(RETRY_V1), &wrong), Some(false));
    }

    #[test]
    fn test_verify_retry_integrity_unsupported_version() {
        // draft-29 Retry：常数未定义，返回 None（不报警）
        let mut data = vec![0xF0, 0xff, 0x00, 0x00, 0x1d, 0x04, 0x11, 0x22, 0x33, 0x44];
        data.extend_from_slice(&[0x8b; 20]);
        assert_eq!(verify_retry_integrity(&data, &hex(ODCID)), None);
    }

    #[test]
    fn test_verify_retry_integrity_truncated() {
        let data = hex(RETRY_V1);
        // 完整包 71 字节 = 头部(19) + token(36) + tag(16)；截断到头部后不足 16 字节
        assert_eq!(verify_retry_integrity(&data[..20], &hex(ODCID)), None);
    }

    #[test]
    fn test_verify_retry_integrity_empty_odcid() {
        assert_eq!(verify_retry_integrity(&hex(RETRY_V1), &[]), None);
    }

    #[test]
    fn test_parse_retry_v1_initial_is_not_retry() {
        // v1 首字节 0xC0（类型位 00）是 Initial 而非 Retry（v2 语义不得套用到 v1）
        let data = hex(RETRY_V2);
        let mut v1_initial = data.clone();
        v1_initial[1..5].copy_from_slice(&QUIC_VERSION_1.to_be_bytes());
        assert_eq!(parse_retry_packet(&v1_initial), None);
    }

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

    /// Transport Parameters 解析（合成 blob 覆盖 1/2/4 字节 varint + 未知参数跳过）
    #[test]
    fn test_parse_transport_parameters_full() {
        // 01 04 8001d4c0 → max_idle_timeout=120000（4 字节 varint，varint 无 3 字节形式）
        // 03 02 45ac → max_udp_payload_size=1452（2 字节）
        // 04 04 80100000 → initial_max_data=1048576（4 字节，首字节 0x80 前缀）
        // 08 02 4064 → initial_max_streams_bidi=100（2 字节）
        // 09 01 03 → initial_max_streams_uni=3（1 字节）
        // 00 04 deadbeef → original_destination_connection_id（字节值参数，跳过）
        let blob = hex(concat!(
            "01048001d4c0",
            "030245ac",
            "040480100000",
            "08024064",
            "090103",
            "0004deadbeef",
        ));
        let tp = parse_transport_parameters(&blob).expect("合法参数序列应解析成功");
        assert_eq!(tp.max_idle_timeout, Some(120000));
        assert_eq!(tp.max_udp_payload_size, Some(1452));
        assert_eq!(tp.initial_max_data, Some(1048576));
        assert_eq!(tp.initial_max_streams_bidi, Some(100));
        assert_eq!(tp.initial_max_streams_uni, Some(3));
    }

    #[test]
    fn test_parse_transport_parameters_empty() {
        let tp = parse_transport_parameters(&[]).expect("空序列应返回全 None");
        assert!(tp.max_idle_timeout.is_none());
        assert!(tp.max_udp_payload_size.is_none());
        assert!(tp.initial_max_data.is_none());
        assert!(tp.initial_max_streams_bidi.is_none());
        assert!(tp.initial_max_streams_uni.is_none());
    }

    #[test]
    fn test_parse_transport_parameters_truncated() {
        // 值截断：声明 3 字节只给 2
        assert!(parse_transport_parameters(&hex("010381d4")).is_none());
        // 长度越界：声明 5 字节只剩 2
        assert!(parse_transport_parameters(&hex("01050000")).is_none());
        // 长度字段本身截断
        assert!(parse_transport_parameters(&hex("0103")).is_none());
    }

    /// RFC 9001 A.2 官方样例：真解密全链路提取 Transport Parameters
    ///
    /// 样例 ClientHello 自带 0x0039 扩展（50 字节），逐字节核对官方值断言。
    #[test]
    #[cfg(feature = "tls")]
    fn test_decrypt_client_meta_transport_parameters_a2() {
        let packet = make_a2_sample_packet();
        let (_ch, tp) = decrypt_client_meta(&packet).expect("A.2 样例应解密成功");
        let tp = tp.expect("A.2 样例 ClientHello 应携带 0x0039 扩展");
        // 0408ffffffffffffffff → initial_max_data = 2^62-1（varint 首字节前缀占 2 位，最大 62 位）
        assert_eq!(tp.initial_max_data, Some((1u64 << 62) - 1));
        // 010480007530 → max_idle_timeout = 0x7530 = 30000 ms
        assert_eq!(tp.max_idle_timeout, Some(30000));
        // 080110 / 090110 → 双向/单向流数上限均为 16
        assert_eq!(tp.initial_max_streams_bidi, Some(16));
        assert_eq!(tp.initial_max_streams_uni, Some(16));
        // 样例未携带 0x03
        assert!(tp.max_udp_payload_size.is_none());
    }

    /// 打印 A.2 样例受保护包的 hex（用于生成 tests/test_quic.rs 集成测试夹具）
    #[test]
    fn test_print_a2_fixture() {
        let packet = make_a2_sample_packet();
        println!("A2_FIXTURE_LEN={}", packet.len());
        println!("A2_FIXTURE={}", to_hex(&packet));
    }

    /// 构造最小 ServerHello（RFC 8446 §4.1.3，QUIC 形态：32B session_id_echo，
    /// compression 0x00，扩展 = ALPN "h3" + supported_versions TLS 1.3）
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
        // 扩展区：ALPN（type 0x0010）+ supported_versions（type 0x002b）
        let alpn_data: [u8; 5] = [0x00, 0x03, 0x02, 0x68, 0x33]; // list_len=3, name_len=2, "h3"
        let sv_data: [u8; 2] = [0x03, 0x04]; // TLS 1.3
        let exts_len = (4 + alpn_data.len() + 4 + sv_data.len()) as u16;
        sh.extend_from_slice(&exts_len.to_be_bytes());
        sh.extend_from_slice(&[0x00, 0x10]);
        sh.extend_from_slice(&[0x00, 0x05]);
        sh.extend_from_slice(&alpn_data);
        sh.extend_from_slice(&[0x00, 0x2b]);
        sh.extend_from_slice(&[0x00, 0x02]);
        sh.extend_from_slice(&sv_data);

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
    fn test_decrypt_server_hello_meta_fields() {
        let packet = make_server_initial_packet();
        let sh = decrypt_server_hello_meta(&packet).expect("应解密出完整 ServerHello");
        assert_eq!(sh.legacy_version, 0x0303);
        assert_eq!(sh.supported_version, Some(0x0304));
        assert_eq!(sh.cipher_suite, 0x1301);
        assert_eq!(sh.alpn.as_deref(), Some("h3"));
        assert_eq!(sh.extensions, vec![0x0010, 0x002b]);
    }

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
                // JA4S：q 前缀 + TLS 1.3 + 2 扩展 + h3 | 1301 | sha256("0x0010,0x002b")[:12]
                assert_eq!(
                    meta.ja4s.as_deref(),
                    Some("q1302h3_1301_77012567d328"),
                    "服务端 Initial 应产出 JA4S 服务端指纹"
                );
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
