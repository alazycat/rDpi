//! TLS protocol parser for rDpi
//!
//! Parses TLS record layer and ClientHello to extract SNI and version.

/// TLS ContentType values
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// TLS Handshake Type values
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// TLS Extension Type values
const EXTENSION_TYPE_SNI: u16 = 0x0000;

/// TLS SNI Name Type
const SNI_NAME_TYPE_HOSTNAME: u8 = 0x00;

/// TLS ClientHello 解析结果
#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    /// Server Name Indication (SNI)
    pub sni: Option<String>,
    /// TLS version string (e.g., "TLS 1.2", "TLS 1.3")
    pub version: Option<String>,
}

/// 检查是否为 TLS 记录
///
/// TLS 记录层格式:
/// - ContentType (1B): 0x16 for Handshake
/// - Version (2B): 0x03 xx (TLS 1.0-1.3)
/// - Length (2B): payload length
pub fn is_tls_record(data: &[u8]) -> bool {
    data.len() >= 5 && data[0] == CONTENT_TYPE_HANDSHAKE && data[1] == 0x03
}

/// 检查是否为 ClientHello
///
/// 返回 true 如果:
/// - 是 TLS 记录
/// - Handshake Type 为 ClientHello (0x01)
pub fn is_client_hello(data: &[u8]) -> bool {
    if !is_tls_record(data) {
        return false;
    }

    // TLS record header: 5 bytes
    // Handshake header: 4 bytes (type 1B + length 3B)
    if data.len() < 9 {
        return false;
    }

    // Offset 5 is the Handshake Type
    data[5] == HANDSHAKE_TYPE_CLIENT_HELLO
}

/// 解析 ClientHello，提取 SNI 和版本
///
/// 返回 (SNI, Version) 元组
///
/// ClientHello 结构:
/// - Handshake Type (1B): 0x01
/// - Length (3B): ClientHello 长度
/// - Client Version (2B): TLS 版本
/// - Random (32B): 随机数
/// - Session ID Length (1B) + Session ID
/// - Cipher Suites Length (2B) + Cipher Suites
/// - Compression Methods Length (1B) + Compression Methods
/// - Extensions Length (2B) + Extensions
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHelloInfo> {
    if !is_client_hello(data) {
        return None;
    }

    // Extract version from TLS record header (bytes 1-2)
    // This is the record layer version (usually TLS 1.0 for legacy compatibility)
    let record_version = decode_tls_version(data[1], data[2]);

    // Parse extensions to find SNI and actual supported version
    let (sni, supported_version) = parse_client_hello_extensions(data)?;

    // Prefer supported_version extension over record layer version
    let version = supported_version.or(record_version);

    Some(ClientHelloInfo { sni, version })
}

/// 解析 ClientHello 扩展，提取 SNI 和 supported_version
fn parse_client_hello_extensions(data: &[u8]) -> Option<(Option<String>, Option<String>)> {
    // TLS record header: 5 bytes
    // Handshake header: 4 bytes
    // Client Version: 2 bytes
    // Random: 32 bytes
    // Session ID: 1 byte length + data
    // Cipher Suites: 2 bytes length + data
    // Compression Methods: 1 byte length + data
    // Extensions: 2 bytes length + data

    let mut offset = 5; // Skip TLS record header

    // Skip handshake header (4 bytes)
    offset += 4;

    // Skip client version (2 bytes)
    offset += 2;

    // Skip random (32 bytes)
    offset += 32;

    // Skip session ID (1 byte length + session ID)
    if offset >= data.len() {
        return None;
    }
    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;

    // Skip cipher suites (2 bytes length + cipher suites)
    if offset + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = u16_from_be(&data[offset..offset + 2]) as usize;
    offset += 2 + cipher_suites_len;

    // Skip compression methods (1 byte length + compression methods)
    if offset >= data.len() {
        return None;
    }
    let compression_len = data[offset] as usize;
    offset += 1 + compression_len;

    // Parse extensions
    if offset + 2 > data.len() {
        return None;
    }
    let extensions_len = u16_from_be(&data[offset..offset + 2]) as usize;
    offset += 2;

    let extensions_end = offset + extensions_len;
    if extensions_end > data.len() {
        return None;
    }

    let mut sni: Option<String> = None;
    let mut supported_version: Option<String> = None;

    // Parse each extension
    while offset + 4 <= extensions_end {
        let ext_type = u16_from_be(&data[offset..offset + 2]);
        offset += 2;
        let ext_len = u16_from_be(&data[offset..offset + 2]) as usize;
        offset += 2;

        if offset + ext_len > extensions_end {
            break;
        }

        match ext_type {
            EXTENSION_TYPE_SNI => {
                sni = parse_sni_extension(&data[offset..offset + ext_len]);
            }
            0x002b => {
                // supported_versions extension (0x002b)
                supported_version = parse_supported_versions_extension(&data[offset..offset + ext_len]);
            }
            _ => {}
        }

        offset += ext_len;
    }

    Some((sni, supported_version))
}

/// 解析 SNI 扩展
///
/// SNI 扩展格式:
/// - Server Name List Length (2B)
/// - Server Name Type (1B): 0x00 for hostname
/// - Server Name Length (2B)
/// - Server Name (variable)
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // Server Name List Length (2 bytes) - we can skip this
    let mut offset = 2;

    // Server Name Type (1 byte)
    if data[offset] != SNI_NAME_TYPE_HOSTNAME {
        return None;
    }
    offset += 1;

    // Server Name Length (2 bytes)
    let name_len = u16_from_be(&data[offset..offset + 2]) as usize;
    offset += 2;

    if offset + name_len > data.len() {
        return None;
    }

    // Server Name
    let name_bytes = &data[offset..offset + name_len];
    String::from_utf8(name_bytes.to_vec()).ok()
}

/// 解析 supported_versions 扩展
///
/// 格式:
/// - Supported Versions Length (1B)
/// - Supported Version (2B each)
fn parse_supported_versions_extension(data: &[u8]) -> Option<String> {
    if data.len() < 3 {
        return None;
    }

    // Supported Versions Length (1 byte)
    let versions_len = data[0] as usize;
    if versions_len < 2 || versions_len + 1 > data.len() {
        return None;
    }

    // Take the first (highest) version
    let version_bytes = &data[1..3];
    decode_tls_version(version_bytes[0], version_bytes[1])
}

/// 将 TLS 版本字节转换为字符串
fn decode_tls_version(major: u8, minor: u8) -> Option<String> {
    match (major, minor) {
        (0x03, 0x01) => Some("TLS 1.0".to_string()),
        (0x03, 0x02) => Some("TLS 1.1".to_string()),
        (0x03, 0x03) => Some("TLS 1.2".to_string()),
        (0x03, 0x04) => Some("TLS 1.3".to_string()),
        _ => None,
    }
}

/// 从大端字节序读取 u16
#[inline]
fn u16_from_be(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

/// 从 ClientHello 提取 TLS 版本（从 supported_versions 扩展或记录层）
pub fn extract_tls_version(data: &[u8]) -> Option<String> {
    parse_client_hello(data).and_then(|info| info.version)
}

/// 从 ClientHello 提取 SNI
pub fn extract_sni(data: &[u8]) -> Option<String> {
    parse_client_hello(data).and_then(|info| info.sni)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_tls_record_valid() {
        // Valid TLS record header (Handshake, TLS 1.2)
        let data = [0x16, 0x03, 0x03, 0x00, 0x50];
        assert!(is_tls_record(&data));
    }

    #[test]
    fn test_is_tls_record_invalid_content_type() {
        // Invalid content type
        let data = [0x15, 0x03, 0x03, 0x00, 0x50];
        assert!(!is_tls_record(&data));
    }

    #[test]
    fn test_is_tls_record_invalid_version() {
        // Invalid version (not 0x03 xx)
        let data = [0x16, 0x02, 0x03, 0x00, 0x50];
        assert!(!is_tls_record(&data));
    }

    #[test]
    fn test_is_tls_record_too_short() {
        let data = [0x16, 0x03];
        assert!(!is_tls_record(&data));
    }

    #[test]
    fn test_decode_tls_version() {
        assert_eq!(decode_tls_version(0x03, 0x01), Some("TLS 1.0".to_string()));
        assert_eq!(decode_tls_version(0x03, 0x02), Some("TLS 1.1".to_string()));
        assert_eq!(decode_tls_version(0x03, 0x03), Some("TLS 1.2".to_string()));
        assert_eq!(decode_tls_version(0x03, 0x04), Some("TLS 1.3".to_string()));
        assert_eq!(decode_tls_version(0x03, 0x00), None);
    }

    /// Construct a minimal ClientHello for testing
    fn make_minimal_client_hello() -> Vec<u8> {
        // TLS record header
        let mut data = vec![
            0x16,       // ContentType: Handshake
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x00, // Length: placeholder
        ];

        // Handshake header
        data.push(0x01); // Handshake Type: ClientHello
        data.extend_from_slice(&[0x00, 0x00, 0x00]); // Length: placeholder

        // Client Version
        data.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        // Random (32 bytes)
        data.extend_from_slice(&[0u8; 32]);

        // Session ID (empty)
        data.push(0x00);

        // Cipher Suites (2 bytes length + minimal)
        data.extend_from_slice(&[0x00, 0x02]); // Length: 2
        data.extend_from_slice(&[0x00, 0x00]); // Null cipher suite

        // Compression Methods (1 byte length + null)
        data.push(0x01); // Length: 1
        data.push(0x00); // Null compression

        // Extensions (empty)
        data.extend_from_slice(&[0x00, 0x00]);

        // Update lengths
        let handshake_len = data.len() - 9; // Total - (TLS header + handshake header)
        let record_len = data.len() - 5; // Total - TLS header

        // Handshake length (3 bytes, big-endian)
        data[6] = ((handshake_len >> 16) & 0xFF) as u8;
        data[7] = ((handshake_len >> 8) & 0xFF) as u8;
        data[8] = (handshake_len & 0xFF) as u8;

        // Record length (2 bytes, big-endian)
        data[3] = ((record_len >> 8) & 0xFF) as u8;
        data[4] = (record_len & 0xFF) as u8;

        data
    }

    /// Construct a ClientHello with SNI extension
    fn make_client_hello_with_sni(hostname: &str) -> Vec<u8> {
        let hostname_bytes = hostname.as_bytes();

        // Build SNI extension
        let mut sni_ext = vec![
            0x00, 0x00, // Extension Type: SNI (0x0000)
            0x00, 0x00, // Extension Length: placeholder
            0x00, 0x00, // Server Name List Length: placeholder
            0x00, // Server Name Type: hostname (0x00)
        ];

        // Server Name Length (2 bytes)
        let name_len = hostname_bytes.len() as u16;
        sni_ext.push(((name_len >> 8) & 0xFF) as u8);
        sni_ext.push((name_len & 0xFF) as u8);

        // Server Name
        sni_ext.extend_from_slice(hostname_bytes);

        // Update SNI extension lengths
        // Server Name List Length = hostname + type (1 byte) + length (2 bytes) = hostname + 3
        let list_len = (hostname_bytes.len() + 3) as u16;
        sni_ext[4] = ((list_len >> 8) & 0xFF) as u8;
        sni_ext[5] = (list_len & 0xFF) as u8;
        // Extension Length = list_len + 2 bytes for list length field
        let ext_len = (hostname_bytes.len() + 5) as u16;
        sni_ext[2] = ((ext_len >> 8) & 0xFF) as u8;
        sni_ext[3] = (ext_len & 0xFF) as u8;

        // Build supported_versions extension for TLS 1.3
        let versions_ext = vec![
            0x00, 0x2b, // Extension Type: supported_versions (0x002b)
            0x00, 0x03, // Extension Length: 3
            0x02, // Supported Versions Length: 2
            0x03, 0x04, // TLS 1.3
        ];

        // Build extensions block
        let extensions_len = (sni_ext.len() + versions_ext.len()) as u16;
        let mut extensions = vec![
            ((extensions_len >> 8) & 0xFF) as u8,
            (extensions_len & 0xFF) as u8,
        ];
        extensions.extend(sni_ext);
        extensions.extend(versions_ext);

        // TLS record header
        let mut data = vec![
            0x16,       // ContentType: Handshake
            0x03, 0x01, // Version: TLS 1.0 (record layer)
            0x00, 0x00, // Length: placeholder
        ];

        // Handshake header
        data.push(0x01); // Handshake Type: ClientHello
        data.extend_from_slice(&[0x00, 0x00, 0x00]); // Length: placeholder

        // Client Version
        data.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 (legacy)

        // Random (32 bytes)
        data.extend_from_slice(&[0u8; 32]);

        // Session ID (empty)
        data.push(0x00);

        // Cipher Suites (2 bytes length + minimal)
        data.extend_from_slice(&[0x00, 0x02]); // Length: 2
        data.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256

        // Compression Methods (1 byte length + null)
        data.push(0x01); // Length: 1
        data.push(0x00); // Null compression

        // Extensions
        data.extend(extensions);

        // Update lengths
        let handshake_len = data.len() - 9;
        let record_len = data.len() - 5;

        data[6] = ((handshake_len >> 16) & 0xFF) as u8;
        data[7] = ((handshake_len >> 8) & 0xFF) as u8;
        data[8] = (handshake_len & 0xFF) as u8;

        data[3] = ((record_len >> 8) & 0xFF) as u8;
        data[4] = (record_len & 0xFF) as u8;

        data
    }

    #[test]
    fn test_parse_client_hello_minimal() {
        let data = make_minimal_client_hello();
        assert!(is_client_hello(&data));

        let result = parse_client_hello(&data);
        assert!(result.is_some());

        let info = result.unwrap();
        assert!(info.sni.is_none());
        // Should get record layer version (TLS 1.2)
        assert_eq!(info.version, Some("TLS 1.2".to_string()));
    }

    #[test]
    fn test_parse_client_hello_with_sni() {
        let data = make_client_hello_with_sni("example.com");
        assert!(is_client_hello(&data));

        let result = parse_client_hello(&data);
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.sni, Some("example.com".to_string()));
        // Should get TLS 1.3 from supported_versions extension
        assert_eq!(info.version, Some("TLS 1.3".to_string()));
    }

    #[test]
    fn test_parse_client_hello_with_sni_and_port() {
        let data = make_client_hello_with_sni("api.example.com");

        let result = parse_client_hello(&data);
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.sni, Some("api.example.com".to_string()));
    }

    #[test]
    fn test_parse_non_tls() {
        // HTTP request
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!is_tls_record(data));
        assert!(parse_client_hello(data).is_none());

        // Random data
        let data = [0x00, 0x01, 0x02, 0x03, 0x04];
        assert!(!is_tls_record(&data));
    }

    #[test]
    fn test_extract_functions() {
        let data = make_client_hello_with_sni("test.com");

        let sni = extract_sni(&data);
        assert_eq!(sni, Some("test.com".to_string()));

        let version = extract_tls_version(&data);
        assert_eq!(version, Some("TLS 1.3".to_string()));
    }

    #[test]
    fn test_tls_1_2_version() {
        // TLS 1.2 without supported_versions extension
        let data = make_minimal_client_hello();
        let version = extract_tls_version(&data);
        assert_eq!(version, Some("TLS 1.2".to_string()));
    }

    #[test]
    fn test_is_client_hello() {
        let data = make_client_hello_with_sni("example.com");
        assert!(is_client_hello(&data));

        // Not a ClientHello
        let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
        assert!(!is_client_hello(&alert));
    }
}
