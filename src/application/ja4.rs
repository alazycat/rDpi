//! JA4 TLS 指纹计算
//!
//! JA4 = tls.version.ciphers.extensions.supported_groups
//!
//! Each field after `tls.version` is a truncated SHA-256 hex digest
//! of the serialized (big-endian u16) list of values.

use sha2::{Digest, Sha256};

use crate::core::types::Application;

/// JA4 指纹 → Application 映射表
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
pub fn compute_ja4(
    version: &str,
    ciphers: &[u16],
    extensions: &[u16],
    groups: &[u16],
) -> String {
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
    hex::encode(&hash)[..chars.min(64)].to_string()
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
}
