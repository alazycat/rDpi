//! DTLS 记录层解析（F38，RFC 6347/9147）
//!
//! DTLS 记录头 13 字节：content_type(1B) + legacy_record_version(2B) +
//! epoch(2B) + sequence_number(6B) + length(2B)；其后 DTLS 握手头 12 字节：
//! msg_type(1B) + length(3B) + message_seq(2B) + fragment_offset(3B) +
//! fragment_length(3B)，消息体从 offset 25 起。
//!
//! 本模块不依赖 tls feature——识别与版本提取自足；SNI/ALPN/JA4 的完整
//! 提取由 dtls/mod.rs 在 `feature = "tls"` 下经合成记录复用 tls 解析器完成。

/// DTLS handshake content_type（与 TLS 记录层同值 0x16）
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// legacy_record_version 允许值：DTLS 1.0 / 1.2 / 1.3
pub(crate) const DTLS_VERSION_10: u16 = 0xfeff;
pub(crate) const DTLS_VERSION_12: u16 = 0xfefd;
pub(crate) const DTLS_VERSION_13: u16 = 0xfefc;

/// supported_versions 扩展类型
const EXTENSION_TYPE_SUPPORTED_VERSIONS: u16 = 0x002b;

/// DTLS 握手消息（已通过记录头与握手头校验）
pub(crate) struct DtlsHandshake {
    /// legacy_record_version（0xfeff/0xfefd/0xfefc）
    pub version: u16,
    /// 握手消息类型（1=ClientHello, 2=ServerHello, 3=HelloVerifyRequest, ...）
    pub msg_type: u8,
    /// 握手消息体长度（length == fragment_length，单片段）
    pub msg_len: usize,
}

/// 校验并解析 DTLS 初始握手记录
///
/// 要求：content_type=0x16、legacy_record_version ∈ {0xfeff, 0xfefd, 0xfefc}、
/// epoch=0（初始握手明文，HVR/CH/SH 均在此阶段）、单片段
/// （fragment_offset=0 且 fragment_length=length）、记录层长度自洽。
/// 分片握手消息不解析（边界登记 risks.md F38）。
pub(crate) fn parse_handshake(payload: &[u8]) -> Option<DtlsHandshake> {
    // 13B 记录头 + 12B DTLS 握手头
    if payload.len() < 25 || payload[0] != CONTENT_TYPE_HANDSHAKE {
        return None;
    }
    let version = u16::from_be_bytes([payload[1], payload[2]]);
    if !matches!(version, DTLS_VERSION_10 | DTLS_VERSION_12 | DTLS_VERSION_13) {
        return None;
    }
    // epoch（payload[3..5]）必须为 0：加密记录（epoch>0）不可解析也不参与识别
    if payload[3] != 0 || payload[4] != 0 {
        return None;
    }
    let record_len = u16::from_be_bytes([payload[11], payload[12]]) as usize;
    if 13 + record_len > payload.len() {
        return None;
    }
    let msg_type = payload[13];
    let msg_len = u24(&payload[14..17]);
    // message_seq: payload[17..19]（识别不需要）
    let frag_offset = u24(&payload[19..22]);
    let frag_len = u24(&payload[22..25]);
    // 分片消息（fragment_offset≠0 或 fragment_length≠length）不解析
    if frag_offset != 0 || frag_len != msg_len {
        return None;
    }
    // 记录层长度须覆盖 12 字节 DTLS 握手头 + 消息体
    if record_len < 12 + msg_len {
        return None;
    }
    Some(DtlsHandshake {
        version,
        msg_type,
        msg_len,
    })
}

/// 合成 TLS 记录：`[0x16, 0x03, 0x03, len(2B)] ++ [msg_type, length(3B)] ++ 消息体`
///
/// 剥离 DTLS 握手头的 message_seq/fragment_offset/fragment_length 三段
/// （共 8 字节），使消息体落在合成记录 offset 9——与 `crate::protocols::tls`
/// 解析器期望的布局逐字节一致。识别包上一次小 Vec 分配（QUIC 每 Initial
/// 同样分配，先例一致）。
pub(crate) fn synthesize_server_hello(payload: &[u8], hs: &DtlsHandshake) -> Vec<u8> {
    build_synthetic(payload, hs, None)
}

/// 合成 ClientHello 的 TLS 记录（含 DTLS 1.2 legacy cookie 处理）
///
/// ClientHello 消息体布局差异（均从 client_version(2B) + random(32B) 后起）：
/// - DTLS 1.3（RFC 9147）：无 cookie 字段（cookie 改为扩展）——session_id
///   后直接是 cipher_suites；
/// - DTLS 1.2（RFC 6347 §4.2.1）：session_id 后有 legacy cookie 向量
///   （1B 长度 + 数据，初始飞行中为空 0x00）——需剥离后再合成，否则
///   tls 解析器把 cookie 长度字节误读进 cipher_suites 长度。
///
/// 布局判定：两种解释各做一次「cipher_suites → compression → extensions
/// 恰好走到消息体末尾」的结构校验，先试无 cookie（1.3），失败再试剥
/// cookie（1.2）。两种解释均失败返回 None（畸形输入，调用方降级为仅版本）。
pub(crate) fn synthesize_client_hello(payload: &[u8], hs: &DtlsHandshake) -> Option<Vec<u8>> {
    let end = 25 + hs.msg_len;
    // session_id 向量起点：client_version(2) + random(32) 之后
    let sid_off = 25 + 2 + 32;
    if sid_off >= end {
        return None;
    }
    let sid_len = payload[sid_off] as usize;
    let after_sid = sid_off + 1 + sid_len;
    // DTLS 1.3 布局：session_id 后直接 cipher_suites
    if ch_layout_valid(payload, after_sid, end) {
        return Some(build_synthetic(payload, hs, None));
    }
    // DTLS 1.2 布局：剥离 legacy cookie 向量
    let cookie_len = payload[after_sid] as usize;
    let after_cookie = after_sid + 1 + cookie_len;
    if ch_layout_valid(payload, after_cookie, end) {
        return Some(build_synthetic(
            payload,
            hs,
            Some((after_sid, after_cookie)),
        ));
    }
    None
}

/// 从 `cs_off` 起按 TLS 布局校验 ClientHello 尾段能否精确对齐消息体末尾
///
/// 依次消耗 cipher_suites(2B 长度) → compression(1B 长度) →
/// extensions(2B 长度)，要求 extensions 区域**恰好**结束于消息体末尾
/// （CH 扩展是最后一个字段）——排除错位解释的巧合命中。
fn ch_layout_valid(payload: &[u8], cs_off: usize, end: usize) -> bool {
    let mut off = cs_off;
    if off + 2 > end {
        return false;
    }
    let cs_len = u16::from_be_bytes([payload[off], payload[off + 1]]) as usize;
    off += 2 + cs_len;
    if off >= end {
        return false;
    }
    let comp_len = payload[off] as usize;
    off += 1 + comp_len;
    if off + 2 > end {
        return false;
    }
    let exts_len = u16::from_be_bytes([payload[off], payload[off + 1]]) as usize;
    off + 2 + exts_len == end
}

/// 构造合成 TLS 记录；`skip = Some((s, e))` 时剥掉消息体内 `[s, e)` 区间
/// （DTLS 1.2 legacy cookie），TLS 头部长度字段按剥后长度填写
fn build_synthetic(payload: &[u8], hs: &DtlsHandshake, skip: Option<(usize, usize)>) -> Vec<u8> {
    let (cut_s, cut_e) = skip.unwrap_or((0, 0));
    let body_len = hs.msg_len - (cut_e - cut_s);
    let mut out = Vec::with_capacity(9 + body_len);
    out.extend_from_slice(&[0x16, 0x03, 0x03]);
    out.extend_from_slice(&((4 + body_len) as u16).to_be_bytes());
    out.push(hs.msg_type);
    out.extend_from_slice(&(body_len as u32).to_be_bytes()[1..4]);
    match skip {
        Some((s, e)) => {
            out.extend_from_slice(&payload[25..s]);
            out.extend_from_slice(&payload[e..25 + hs.msg_len]);
        }
        None => out.extend_from_slice(&payload[25..25 + hs.msg_len]),
    }
    out
}

/// 从合成 TLS 记录的 ClientHello 提取 supported_versions 原始值
/// （非 GREASE 最大者；DTLS 1.3 ClientHello 携带 0xfefc）
///
/// 自足实现（不依赖 tls 模块），无 tls feature 时也可提取版本。
pub(crate) fn client_hello_supported_version(synth: &[u8]) -> Option<u16> {
    // 握手头(4B) + client version(2B) + random(32B)，从合成记录 offset 9 起
    let mut offset = 9 + 2 + 32;
    if offset >= synth.len() {
        return None;
    }
    let sid_len = synth[offset] as usize;
    offset += 1 + sid_len;
    if offset + 2 > synth.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([synth[offset], synth[offset + 1]]) as usize;
    offset += 2 + cs_len;
    if offset >= synth.len() {
        return None;
    }
    let comp_len = synth[offset] as usize;
    offset += 1 + comp_len;
    if offset + 2 > synth.len() {
        return None;
    }
    let exts_len = u16::from_be_bytes([synth[offset], synth[offset + 1]]) as usize;
    offset += 2;
    let end = (offset + exts_len).min(synth.len());
    let mut best: Option<u16> = None;
    while offset + 4 <= end {
        let ext_type = u16::from_be_bytes([synth[offset], synth[offset + 1]]);
        let ext_len = u16::from_be_bytes([synth[offset + 2], synth[offset + 3]]) as usize;
        offset += 4;
        if offset + ext_len > end {
            return best;
        }
        if ext_type == EXTENSION_TYPE_SUPPORTED_VERSIONS && ext_len >= 3 {
            // ClientHello 中为 1B 列表长 + 2B×N 版本列表，取非 GREASE 最大者
            let list = &synth[offset + 1..offset + ext_len];
            let mut i = 0;
            while i + 2 <= list.len() {
                let v = u16::from_be_bytes([list[i], list[i + 1]]);
                let grease = (v >> 8) == (v & 0xff) && (v & 0x0f) == 0x0a;
                if !grease && best.is_none_or(|b| v > b) {
                    best = Some(v);
                }
                i += 2;
            }
        }
        offset += ext_len;
    }
    best
}

/// DTLS 版本 u16 → 展示串（zeek ssl-consts.h TLS_VERSION_MAPPER 同源映射）
pub(crate) fn version_string(version: u16) -> Option<&'static str> {
    match version {
        DTLS_VERSION_13 => Some("DTLS 1.3"),
        DTLS_VERSION_12 => Some("DTLS 1.2"),
        DTLS_VERSION_10 => Some("DTLS 1.0"),
        _ => None,
    }
}

/// 从大端 3 字节读取 u24
fn u24(bytes: &[u8]) -> usize {
    ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
}
