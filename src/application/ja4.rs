//! JA4 TLS 指纹计算
//!
//! JA4 = tls.version.ciphers.extensions.supported_groups
//!
//! Each field after `tls.version` is a truncated SHA-256 hex digest
//! of the serialized (big-endian u16) list of values.

use sha2::{Digest, Sha256};

use crate::core::types::Application;

/// JA4 指纹 → Application 映射表
/// 占位表：待真实流量采集后填充（结构见下）；填充前允许未使用。
#[allow(dead_code)]
pub(crate) const JA4_MAPPINGS: &[(&str, Application)] = &[
    // 将在真实流量采集后填充
    // 结构: ("tls13.{ciphers12}.{extensions12}.{groups6}", Application::Chrome),
];

/// 计算 JA4 TLS 指纹
///
/// # 参数
///
/// * `version` - TLS 版本字符串，如 "TLS 1.3", "1.3", "TLSv1.3"
/// * `ciphers` - 密码套件列表
/// * `extensions` - 扩展类型列表（按在 ClientHello 中出现的顺序）
/// * `groups` - 支持的椭圆曲线/有限域组列表
///
/// # 返回
///
/// 格式为 `tlsNN.{ciphers12}.{extensions12}.{groups6}` 的 JA4 指纹
pub fn compute_ja4(version: &str, ciphers: &[u16], extensions: &[u16], groups: &[u16]) -> String {
    let ver = match version {
        "TLS 1.3" | "1.3" | "TLSv1.3" => "tls13",
        "TLS 1.2" | "1.2" | "TLSv1.2" => "tls12",
        "TLS 1.1" | "1.1" | "TLSv1.1" => "tls11",
        _ => "tls10",
    };

    let ciph = trunc_hash_hex(&serialize_u16(ciphers), 12);
    let ext = trunc_hash_hex(&serialize_u16(extensions), 12);
    let grp = trunc_hash_hex(&serialize_u16(groups), 6);

    format!("{}.{}.{}.{}", ver, ciph, ext, grp)
}

/// 将 u16 切片序列化为大端字节序
fn serialize_u16(items: &[u16]) -> Vec<u8> {
    items.iter().flat_map(|v| v.to_be_bytes()).collect()
}

/// 计算 SHA-256 并截取指定数量的十六进制字符
fn trunc_hash_hex(data: &[u8], chars: usize) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)[..chars.min(64)].to_string()
}

// ==== JA4S：服务端指纹（FoxIO JA4+ 家族，对应官方 ja4.py 的 to_ja4s）====

/// TLS_MAPPER（官方 common.py）：TLS 版本 → 2 字符编码
///
/// 0x0002→"s2"（SSL 2）、0x0300→"s3"（SSL 3）、0x0301→"10"、0x0302→"11"、
/// 0x0303→"12"、0x0304→"13"；未映射版本记 "00"。
fn version_code(version: u16) -> &'static str {
    match version {
        0x0002 => "s2",
        0x0300 => "s3",
        0x0301 => "10",
        0x0302 => "11",
        0x0303 => "12",
        0x0304 => "13",
        _ => "00",
    }
}

/// 判断 16 位值是否为 GREASE（0x0a0a/0x1a1a/.../0xfafa：两字节相同且低半字节为 0xa）
fn is_grease(value: u16) -> bool {
    (value >> 8) == (value & 0xff) && (value & 0x0f) == 0x0a
}

/// ALPN → 2 字符编码（官方 ja4.py）：无 ALPN 记 "00"；长度 >2 取首尾字符
/// （"http/1.1"→"h1"）；首字符非 ASCII 记 "99"（无法编码的协议名）。
fn alpn_code(alpn: Option<&str>) -> String {
    match alpn {
        None | Some("") => "00".to_string(),
        Some(a) => {
            let mut code: String = a.to_string();
            if code.chars().count() > 2 {
                let first = code.chars().next().unwrap();
                let last = code.chars().last().unwrap();
                code = format!("{}{}", first, last);
            }
            if code.chars().next().is_some_and(|c| c as u32 > 127) {
                "99".to_string()
            } else {
                code
            }
        }
    }
}

/// 计算 JA4S 服务端 TLS 指纹
///
/// 格式：`{t|q}{版本2位}{扩展数2位}{alpn 2字符}_{cipher 4hex}_{扩展哈希12hex}`
///
/// 与客户端 JA4 的关键差异（FoxIO 官方语义）：
/// - 扩展列表按服务端发送顺序哈希，**不排序**（服务端不乱序，顺序本身是指纹）；
/// - 扩展数与哈希**不过滤 GREASE**（官方 to_ja4s 路径无 GREASE 过滤，区别于 to_ja4）；
/// - 密码套件为服务器**选定**的那一个（4 位小写 hex），非哈希；
/// - 哈希输入为 `0x%04x` 形式的逗号拼接串（与官方 ja4.py 一致）。
///
/// # 参数
///
/// * `quic` - true 时传输前缀为 "q"（QUIC），false 为 "t"（TCP）
/// * `legacy_version` - ServerHello 握手头 legacy_version 字段
/// * `supported_version` - supported_versions 扩展中的协商版本（TLS 1.3 携带）
/// * `cipher_suite` - 服务器选定的密码套件
/// * `extensions` - 扩展类型列表（按服务端发送顺序）
/// * `alpn` - 协商出的 ALPN
pub fn compute_ja4s(
    quic: bool,
    legacy_version: u16,
    supported_version: Option<u16>,
    cipher_suite: u16,
    extensions: &[u16],
    alpn: Option<&str>,
) -> String {
    let transport = if quic { 'q' } else { 't' };
    // 协商版本优先取 supported_versions 扩展（GREASE 值防御性忽略），回退 legacy_version
    let negotiated = match supported_version {
        Some(v) if !is_grease(v) => v,
        _ => legacy_version,
    };
    let version = version_code(negotiated);
    let ext_count = extensions.len().min(99);
    let alpn = alpn_code(alpn);

    // 扩展哈希：0x%04x 小写形式逗号拼接后取 SHA-256 前 12 位；空列表为固定 12 个 0
    let ext_hash = if extensions.is_empty() {
        "000000000000".to_string()
    } else {
        let joined = extensions
            .iter()
            .map(|e| format!("0x{:04x}", e))
            .collect::<Vec<_>>()
            .join(",");
        trunc_hash_hex(joined.as_bytes(), 12)
    };

    format!(
        "{}{}{:02}{}_{:04x}_{}",
        transport, version, ext_count, alpn, cipher_suite, ext_hash
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ja4_basic() {
        let ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030];
        let extensions = [0x0000, 0x001b, 0x0023, 0x002d, 0x0033, 0xff01];
        let groups = [0x001d, 0x0017, 0x0018];
        let ja4 = compute_ja4("TLS 1.3", &ciphers, &extensions, &groups);
        assert!(!ja4.is_empty());
        assert!(ja4.starts_with("tls13."));
        // 期望格式: tls13.{12hex}.{12hex}.{6hex}
        let parts: Vec<&str> = ja4.split('.').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "tls13");
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
        assert_eq!(parts[3].len(), 6);
    }

    #[test]
    fn test_ja4_empty() {
        let ja4 = compute_ja4("TLS 1.2", &[], &[], &[]);
        // 空列表的哈希应一致，格式为 tls12.{12}.{12}.{6} = 38 字符
        assert_eq!(ja4.len(), 38);
        // 空列表的指纹应确定
        let ja4_again = compute_ja4("TLS 1.2", &[], &[], &[]);
        assert_eq!(ja4, ja4_again);
    }

    #[test]
    fn test_ja4_version_variants() {
        let ciphers = [0x1301];
        let extensions = [0x0000];
        let groups = [0x001d];

        // "TLS 1.3" form (from decode_tls_version)
        let ja4 = compute_ja4("TLS 1.3", &ciphers, &extensions, &groups);
        assert!(ja4.starts_with("tls13."));

        // "1.3" form
        let ja4 = compute_ja4("1.3", &ciphers, &extensions, &groups);
        assert!(ja4.starts_with("tls13."));

        // "TLSv1.3" form
        let ja4 = compute_ja4("TLSv1.3", &ciphers, &extensions, &groups);
        assert!(ja4.starts_with("tls13."));

        // Unknown version should fall back to tls10
        let ja4 = compute_ja4("unknown", &ciphers, &extensions, &groups);
        assert!(ja4.starts_with("tls10."));
    }

    #[test]
    fn test_ja4_deterministic() {
        let ciphers = [0x1301, 0x1302, 0x1303];
        let extensions = [0x0000, 0x001b, 0x0023];
        let groups = [0x001d, 0x0017];
        let ja4_a = compute_ja4("TLS 1.3", &ciphers, &extensions, &groups);
        let ja4_b = compute_ja4("TLS 1.3", &ciphers, &extensions, &groups);
        assert_eq!(ja4_a, ja4_b);
    }

    // ==== JA4S（golden 向量：SHA-256 前缀经 PowerShell .NET SHA256 独立实现交叉验证）====

    /// TCP + TLS 1.3（supported_versions 0x0304）+ cipher 0x1302 + ALPN "h2"
    /// 扩展 [0x002b, 0x0010] → sha256("0x002b,0x0010") 前 12 位
    #[test]
    fn test_ja4s_tcp_tls13() {
        let ja4s = compute_ja4s(
            false,
            0x0303,
            Some(0x0304),
            0x1302,
            &[0x002b, 0x0010],
            Some("h2"),
        );
        assert_eq!(ja4s, "t1302h2_1302_60694de2240d");
    }

    /// QUIC 前缀 q；TLS 1.2 风格（无 supported_versions，legacy 0x0303）→ 版本 "12"
    #[test]
    fn test_ja4s_quic_tls12_fallback() {
        let ja4s = compute_ja4s(true, 0x0303, None, 0x1301, &[0x0010, 0x002b], Some("h3"));
        assert_eq!(ja4s, "q1202h3_1301_77012567d328");
    }

    /// 服务端扩展顺序敏感：同集合不同顺序产生不同哈希（JA4S 不排序）
    #[test]
    fn test_ja4s_extension_order_is_significant() {
        let a = compute_ja4s(false, 0x0303, Some(0x0304), 0x1302, &[0x002b, 0x0010], None);
        let b = compute_ja4s(false, 0x0303, Some(0x0304), 0x1302, &[0x0010, 0x002b], None);
        assert_ne!(a, b);
        assert!(a.ends_with("60694de2240d"));
        assert!(b.ends_with("77012567d328"));
    }

    /// 版本编码全表 + 未知版本记 "00"
    #[test]
    fn test_ja4s_version_codes() {
        let cases = [
            (0x0002u16, "s2"),
            (0x0300, "s3"),
            (0x0301, "10"),
            (0x0302, "11"),
            (0x0303, "12"),
            (0x0304, "13"),
            (0x0999, "00"),
        ];
        for (version, code) in cases {
            let ja4s = compute_ja4s(false, version, None, 0x1301, &[0x0010], None);
            assert!(ja4s.starts_with(&format!("t{}", code)), "{}", ja4s);
        }
    }

    /// ALPN 编码：None/空 → "00"；>2 字符取首尾（"http/1.1"→"h1"）；2 字符原样
    #[test]
    fn test_ja4s_alpn_codes() {
        let base =
            |alpn: Option<&str>| compute_ja4s(false, 0x0303, Some(0x0304), 0x1302, &[0x002b], alpn);
        assert!(base(None).starts_with("t130100_1302_"));
        assert!(base(Some("")).starts_with("t130100_1302_"));
        assert!(base(Some("h2")).starts_with("t1301h2_1302_"));
        assert!(base(Some("http/1.1")).starts_with("t1301h1_1302_"));
    }

    /// GREASE supported_versions 防御性忽略，回退 legacy_version；
    /// 空扩展列表哈希为固定 12 个 0
    #[test]
    fn test_ja4s_grease_version_and_empty_extensions() {
        let ja4s = compute_ja4s(false, 0x0303, Some(0x0a0a), 0x1301, &[], None);
        assert_eq!(ja4s, "t120000_1301_000000000000");
    }
}
