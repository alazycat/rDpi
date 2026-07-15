//! JA4 TLS 指纹测试

use rdpi::application::compute_ja4;

#[test]
fn test_ja4_format() {
    let ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030];
    let extensions = [0x0000, 0x001b, 0x0023, 0x002d, 0x0033, 0xff01];
    let groups = [0x001d, 0x0017, 0x0018];
    let ja4 = compute_ja4("1.3", &ciphers, &extensions, &groups);
    assert!(ja4.starts_with("tls13."));
    let parts: Vec<&str> = ja4.split('.').collect();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[1].len(), 12);
    assert_eq!(parts[2].len(), 12);
    assert_eq!(parts[3].len(), 6);
}

#[test]
fn test_ja4_empty_lists() {
    let ja4 = compute_ja4("1.2", &[], &[], &[]);
    // "tls12." + 12 + "." + 12 + "." + 6 = 38
    assert_eq!(ja4.len(), 38);
}

#[test]
fn test_ja4_tls13() {
    let ja4 = compute_ja4("TLSv1.3", &[0x1301], &[0x0000], &[0x001d]);
    assert!(ja4.starts_with("tls13."));
}

#[test]
fn test_ja4_tls12() {
    let ja4 = compute_ja4("TLSv1.2", &[0x1301], &[0x0000], &[0x001d]);
    assert!(ja4.starts_with("tls12."));
}
