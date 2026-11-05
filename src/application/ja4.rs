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

// ==== JA4H：HTTP 客户端指纹（FoxIO JA4+ 家族，对应官方 ja4h.py 的 to_ja4h）====

/// 计算 JA4H HTTP 客户端指纹（仅 HTTP/1.x 请求）
///
/// 格式：`{方法2位}{版本2位}{c|n}{r|n}{头部数2位}{语言4位}_{头部哈希12hex}_{cookie字段哈希}_{cookie值哈希}`
///
/// 与客户端 JA4 的关键差异（FoxIO 官方语义）：
/// - 头部名按**发送顺序**哈希，不排序（顺序本身是指纹信号）、保留原始大小写；
/// - Cookie 与 Referer 头不参与头部计数与哈希，仅作为 c/r 标志位；
/// - Cookie 字段/值按字段名**排序**后哈希（cookie 名序稳定）；无 Cookie 记 12 个 0；
/// - 语言取 Accept-Language 首项（去 `-`、截 `;q=` 权重、小写、4 位右补 0），缺省 `0000`；
/// - HTTP/2 请求走伪头部（`:method` 等），官方版本码为 "20"——本实现仅覆盖
///   HTTP/1.x（h2 头部需 HPACK 全量解码，超出本库 HTTP/1.x 解析器范围）。
///
/// # 参数
///
/// * `method` - 请求方法（如 "GET"，取小写前 2 位）
/// * `version` - 请求行版本字符串（如 "HTTP/1.1"，0→"10"、1→"11"、其余默认 "11"）
/// * `headers` - 请求头行列表（原始大小写与顺序，[`HeaderLine`](crate::protocols::http::HeaderLine) 可转换）
pub fn compute_ja4h(method: &str, version: &str, headers: &[(String, String)]) -> String {
    let has_cookie = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("cookie"));
    let has_referer = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("referer"));
    let cookie_flag = if has_cookie { 'c' } else { 'n' };
    let referer_flag = if has_referer { 'r' } else { 'n' };

    // 方法：小写前 2 位（"get"/"po"/"de"/"pu"/"he"/"op"/"co"/"tr"/"pa"）
    let method = method.to_lowercase();
    let method = &method[..method.len().min(2)];

    // 版本："HTTP/1.0"→"10"、HTTP/2→"20"、其余（含 HTTP/1.1）默认 "11"
    let version_code = if version.contains("HTTP/2") {
        "20"
    } else if version.contains("HTTP/1.0") {
        "10"
    } else {
        "11"
    };

    // 参与头部哈希的名字：排除伪头部（':' 开头）、cookie、referer、空名
    let header_names: Vec<&str> = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| {
            !name.starts_with(':')
                && !name.is_empty()
                && !name.eq_ignore_ascii_case("cookie")
                && !name.eq_ignore_ascii_case("referer")
        })
        .collect();
    let header_len = header_names.len().min(99);
    let headers_hash = if header_names.is_empty() {
        // 官方对空头部也做 sha256("")，非固定 0
        trunc_hash_hex(b"", 12)
    } else {
        trunc_hash_hex(header_names.join(",").as_bytes(), 12)
    };

    // Cookie 字段/值：按字段名排序（稳定排序，同名保持原始顺序）
    let (fields_hash, values_hash) = if has_cookie {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for (_, value) in headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("cookie"))
        {
            for part in value.split(';') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let field = part.split('=').next().unwrap_or("").trim().to_string();
                pairs.push((field, part.to_string()));
            }
        }
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let fields: Vec<&str> = pairs.iter().map(|(f, _)| f.as_str()).collect();
        let values: Vec<&str> = pairs.iter().map(|(_, v)| v.as_str()).collect();
        (
            trunc_hash_hex(fields.join(",").as_bytes(), 12),
            trunc_hash_hex(values.join(",").as_bytes(), 12),
        )
    } else {
        ("000000000000".to_string(), "000000000000".to_string())
    };

    // 语言：Accept-Language 首项，去 '-'、截 ';q=' 权重、小写、4 位右补 0
    let accept_language = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("accept-language"))
        .map(|(_, value)| value.as_str());
    let lang = match accept_language {
        Some(l) => {
            let l = l.replace('-', "").replace(';', ",").to_lowercase();
            let l = l.split(',').next().unwrap_or("");
            let l = &l[..l.chars().count().min(4)];
            format!("{:0<4}", l)
        }
        None => "0000".to_string(),
    };

    format!(
        "{}{}{}{}{:02}{}_{}_{}_{}",
        method,
        version_code,
        cookie_flag,
        referer_flag,
        header_len,
        lang,
        headers_hash,
        fields_hash,
        values_hash
    )
}

// ==== JA4X：X.509 证书指纹（FoxIO JA4+ 家族，对应官方 ja4x.py / rust/ja4x）====

/// 计算 JA4X X.509 证书指纹
///
/// 格式：`{issuer哈希12hex}_{subject哈希12hex}_{扩展哈希12hex}`
///
/// 官方语义（FoxIO rust/ja4x 权威实现）：
/// - 每段为 SHA-256 前 12 位 hex，输入为 OID **DER 内容字节**的小写 hex 串
///   逗号拼接（如 commonName 2.5.4.3 → "550403"），按证书 DER 中出现顺序；
/// - issuer/subject 取 Name 中全部 AttributeTypeAndValue 的 OID（含国家/组织），
///   扩展取 TBSCertificate `[3]` 中各 Extension 的 OID，均不排序、不过滤；
/// - 空列表记 12 个 0（区别于 JA4/JA4S 的 sha256("") 语义——官方 hash12 明确空串返回零）；
/// - 不含签名算法、公钥、扩展值，仅 OID 结构本身是指纹信号。
///
/// # 参数
///
/// * `issuer_oids` - issuer Name 的 OID 内容字节列表（DER 顺序）
/// * `subject_oids` - subject Name 的 OID 内容字节列表（DER 顺序）
/// * `extension_oids` - 证书扩展 OID 内容字节列表（DER 顺序）
pub fn compute_ja4x(
    issuer_oids: &[Vec<u8>],
    subject_oids: &[Vec<u8>],
    extension_oids: &[Vec<u8>],
) -> String {
    format!(
        "{}_{}_{}",
        hash12_oids(issuer_oids),
        hash12_oids(subject_oids),
        hash12_oids(extension_oids)
    )
}

/// JA4T：TCP 客户端指纹（F33，2026-11-05）
///
/// 格式对齐 FoxIO 官方 rust/ja4 `tcp.rs` 的 `to_ja4t`：
/// `{window}_{options}_{mss}_{window_scale}`
///
/// - `window`：TCP 头原始窗口值（未按缩放因子换算）
/// - `options`：TCP 选项 kind 序列按序 dash 连接（含 NOP=1；EOL=0 终止），
///   空记 "00"
/// - `mss`：MSS 选项值，缺省 0，最少两位（9→"09"，1460→"1460"）
/// - `window_scale`：缩放因子，为 0（含缺省）记 "00"，非 0 记原值
///
/// 触发语义由调用方负责：仅初始 SYN（SYN 置位且 ACK 清零），每流取第一个
/// 满足的包。官方测试向量：`8192_00_00_00`、`5744_2-4-8-1-3_1436_00`、
/// `8192_2_09_00`。
///
/// # 参数
///
/// * `window` - TCP 头原始窗口值
/// * `option_kinds` - TCP 选项 kind 序列（按出现顺序，含 NOP）
/// * `mss` - MSS 选项值（缺省 0）
/// * `window_scale` - 窗口缩放因子 shift（缺省 0）
pub fn compute_ja4t(window: u16, option_kinds: &[u8], mss: u16, window_scale: u8) -> String {
    let options = if option_kinds.is_empty() {
        "00".to_string()
    } else {
        option_kinds
            .iter()
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    let scale = if window_scale == 0 {
        "00".to_string()
    } else {
        window_scale.to_string()
    };
    format!("{window}_{options}_{mss:02}_{scale}")
}

/// OID 列表 → 12 位哈希段：DER 内容字节 hex 逗号拼接后 SHA-256 截断；空列表为 12 个 0
fn hash12_oids(oids: &[Vec<u8>]) -> String {
    if oids.is_empty() {
        return "000000000000".to_string();
    }
    let joined = oids.iter().map(hex::encode).collect::<Vec<_>>().join(",");
    trunc_hash_hex(joined.as_bytes(), 12)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ja4t_official_vectors() {
        // 官方 rust/ja4 tcp.rs 测试向量
        assert_eq!(compute_ja4t(8192, &[], 0, 0), "8192_00_00_00");
        assert_eq!(
            compute_ja4t(5744, &[2, 4, 8, 1, 3], 1436, 0),
            "5744_2-4-8-1-3_1436_00"
        );
        assert_eq!(compute_ja4t(8192, &[2], 9, 0), "8192_2_09_00");
    }

    #[test]
    fn test_ja4t_windows11_shape() {
        // 官方文档示例（Windows 11 Chrome）：MSS=1460、wscale=8（非 0 记原值）
        assert_eq!(
            compute_ja4t(64240, &[2, 1, 3, 1, 1, 4], 1460, 8),
            "64240_2-1-3-1-1-4_1460_8"
        );
    }

    #[test]
    fn test_ja4t_padding_semantics() {
        // mss/scale 补零语义：mss 9→"09"；scale 0→"00"
        assert_eq!(compute_ja4t(1024, &[2, 3], 9, 0), "1024_2-3_09_00");
        assert_eq!(compute_ja4t(1024, &[1, 1], 0, 2), "1024_1-1_00_2");
    }

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

    // ==== JA4H（golden 向量：SHA-256 前缀经 PowerShell .NET SHA256 独立实现交叉验证）====

    fn h(headers: &[(&str, &str)]) -> Vec<(String, String)> {
        headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    /// GET HTTP/1.1，3 个普通头部，无 cookie/referer/语言
    /// 头部哈希 = sha256("Host,User-Agent,Accept") 前 12 位
    #[test]
    fn test_ja4h_basic_get() {
        let ja4h = compute_ja4h(
            "GET",
            "HTTP/1.1",
            &h(&[
                ("Host", "example.com"),
                ("User-Agent", "test/1"),
                ("Accept", "*/*"),
            ]),
        );
        assert_eq!(ja4h, "ge11nn030000_fe444ad14866_000000000000_000000000000");
    }

    /// POST + cookie + referer + 语言：c/r 置位，cookie 名排序，
    /// 语言 "en-US,en;q=0.9" → 去 '-' 截 ';' → "enus"
    #[test]
    fn test_ja4h_post_cookie_referer_lang() {
        let ja4h = compute_ja4h(
            "POST",
            "HTTP/1.1",
            &h(&[
                ("Host", "example.com"),
                ("Cookie", "theme=dark; session_id=abc123"),
                ("Referer", "https://example.com/"),
                ("Accept-Language", "en-US,en;q=0.9"),
            ]),
        );
        // 头部计数排除 cookie/referer 后为 2（Host、Accept-Language）
        assert_eq!(ja4h, "po11cr02enus_09e340ee0db0_ae523545408f_12670912ce0c");
    }

    /// Cookie 顺序不敏感：同集合不同顺序哈希一致（按字段名排序）
    #[test]
    fn test_ja4h_cookie_order_insensitive() {
        let a = compute_ja4h(
            "GET",
            "HTTP/1.1",
            &h(&[("Cookie", "theme=dark; session_id=abc")]),
        );
        let b = compute_ja4h(
            "GET",
            "HTTP/1.1",
            &h(&[("Cookie", "session_id=abc; theme=dark")]),
        );
        assert_eq!(a, b);
    }

    /// 头部顺序敏感：同集合不同顺序产生不同哈希（JA4H 不排序）
    #[test]
    fn test_ja4h_header_order_is_significant() {
        let a = compute_ja4h(
            "GET",
            "HTTP/1.1",
            &h(&[("Host", "a"), ("User-Agent", "b"), ("Accept", "c")]),
        );
        let b = compute_ja4h(
            "GET",
            "HTTP/1.1",
            &h(&[("Accept", "c"), ("Host", "a"), ("User-Agent", "b")]),
        );
        assert_ne!(a, b);
        assert!(a.starts_with("ge11nn030000_"));
    }

    /// 版本编码：HTTP/1.0 → "10"；未知版本默认 "11"
    #[test]
    fn test_ja4h_version_codes() {
        let headers = h(&[("Host", "a")]);
        assert!(compute_ja4h("GET", "HTTP/1.0", &headers).starts_with("ge10nn010000_"));
        assert!(compute_ja4h("GET", "HTTP/1.1", &headers).starts_with("ge11nn010000_"));
        assert!(compute_ja4h("GET", "HTTP/9.9", &headers).starts_with("ge11nn010000_"));
    }

    /// 语言编码：去 '-'、截 ';q='、右补 0；缺省 "0000"；两字符补齐
    #[test]
    fn test_ja4h_language_padding() {
        let cases = [
            ("zh", "zh00"),
            ("en-US,en;q=0.9", "enus"),
            ("fr;q=0.5", "fr00"),
        ];
        for (lang, expected) in cases {
            let ja4h = compute_ja4h("GET", "HTTP/1.1", &h(&[("Accept-Language", lang)]));
            let mid = &ja4h[8..12];
            assert_eq!(mid, expected, "{}", ja4h);
        }
        let no_lang = compute_ja4h("GET", "HTTP/1.1", &h(&[("Host", "a")]));
        assert!(no_lang.starts_with("ge11nn010000_"));
    }

    /// 伪头部（':' 开头）与 cookie/referer 不参与头部计数；空头部哈希为 sha256("")
    #[test]
    fn test_ja4h_excluded_headers_and_empty_hash() {
        let ja4h = compute_ja4h(
            "GET",
            "HTTP/2",
            &h(&[(":method", "GET"), (":path", "/"), ("Cookie", "a=b")]),
        );
        // HTTP/2 版本码 20；参与哈希头部 0 个（sha256("")）；cookie 仍参与字段/值哈希
        assert_eq!(ja4h, "ge20cn000000_e3b0c44298fc_ca978112ca1b_42144f3939c3");
    }

    // ==== JA4X ====

    /// 官方向量（FoxIO rust/ja4x hash12 单测）：扩展 OID "551d0f,551d25,551d11"
    /// → aae71e8db6d7（本机 PowerShell .NET SHA256 独立交叉验证一致）
    #[test]
    fn test_ja4x_official_vector() {
        let oids: Vec<Vec<u8>> = ["551d0f", "551d25", "551d11"]
            .iter()
            .map(|s| hex::decode(s).unwrap())
            .collect();
        assert_eq!(
            compute_ja4x(&[], &[], &oids),
            "000000000000_000000000000_aae71e8db6d7"
        );
    }

    /// 空列表 → 12 个 0（官方 hash12 空串语义，区别于 JA4/JA4S 的 sha256("")）
    #[test]
    fn test_ja4x_empty_is_zeros() {
        assert_eq!(
            compute_ja4x(&[], &[], &[]),
            "000000000000_000000000000_000000000000"
        );
    }

    /// DN OID 输入编码：DER 内容字节 hex 逗号拼接
    /// （sha256("550403")[:12]="7022c563de38"、"550406,55040a,550403"→"a373a9f83c6b"，
    /// PowerShell .NET SHA256 独立交叉验证）
    #[test]
    fn test_ja4x_dn_oid_encoding() {
        let cn = vec![0x55, 0x04, 0x03]; // 2.5.4.3 commonName
        let s = std::slice::from_ref(&cn);
        let ja4x = compute_ja4x(s, s, &[]);
        assert_eq!(ja4x, "7022c563de38_7022c563de38_000000000000");

        let c = vec![0x55, 0x04, 0x06]; // 2.5.4.6 countryName
        let o = vec![0x55, 0x04, 0x0a]; // 2.5.4.10 organizationName
        let cn2 = vec![0x55, 0x04, 0x03];
        let ja4x = compute_ja4x(&[c, o.clone(), cn2], &[o], &[]);
        assert!(ja4x.starts_with("a373a9f83c6b_"), "{}", ja4x);
        assert!(ja4x.ends_with("_000000000000"));
    }

    /// 顺序敏感：OID 集合相同但顺序不同 → 哈希不同（JA4X 不排序）
    #[test]
    fn test_ja4x_order_sensitive() {
        let a = vec![vec![0x55, 0x04, 0x06], vec![0x55, 0x04, 0x0a]];
        let b = vec![vec![0x55, 0x04, 0x0a], vec![0x55, 0x04, 0x06]];
        assert_ne!(compute_ja4x(&a, &[], &[]), compute_ja4x(&b, &[], &[]));
    }
}
