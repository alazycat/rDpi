//! DoH 解析器域名表（RFC 8484）
//!
//! nDPI 5.0 通过 TLS SNI 命中已知 DoH 解析器域名来识别 DoH/DoT。
//! 本模块维护公开解析器域名表，匹配语义为"全等或子域后缀"。

/// 已知 DoH 解析器域名（公开解析器文档整理）
const DOH_RESOLVERS: &[&str] = &[
    "dns.google",
    "dns.google.com",
    "mozilla.cloudflare-dns.com",
    "cloudflare-dns.com",
    "dns.adguard.com",
    "dns.adguard-dns.com",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    "doh.opendns.com",
    "doh.powerdns.org",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
    "doh.libredns.gr",
    "dns.dns-over-https.com",
    "doh.dns.sb",
    "dns.mullvad.net",
    "doh.mullvad.net",
];

/// 判断 SNI/host 是否命中已知 DoH 解析器域名
pub(crate) fn is_doh_resolver(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return false;
    }
    let host_bytes = host.as_bytes();
    DOH_RESOLVERS.iter().any(|resolver| {
        let resolver_bytes = resolver.as_bytes();
        host_bytes.eq_ignore_ascii_case(resolver_bytes)
            || (host_bytes.len() > resolver_bytes.len()
                && host_bytes[host_bytes.len() - resolver_bytes.len() - 1] == b'.'
                && host_bytes[host_bytes.len() - resolver_bytes.len()..]
                    .eq_ignore_ascii_case(resolver_bytes))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exact_subdomain_and_case() {
        assert!(is_doh_resolver("dns.google"));
        assert!(is_doh_resolver("DNS.GOOGLE"));
        assert!(is_doh_resolver("resolver.dns.google"));
        assert!(is_doh_resolver("mozilla.cloudflare-dns.com"));
        assert!(is_doh_resolver("dns.google."));
    }

    #[test]
    fn rejects_lookalikes_and_empty() {
        assert!(!is_doh_resolver("notdns.google"));
        assert!(!is_doh_resolver("dns.google.example.com"));
        assert!(!is_doh_resolver("example.com"));
        assert!(!is_doh_resolver(""));
    }
}
