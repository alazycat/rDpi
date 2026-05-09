//! Application layer identification module for rDpi
//!
//! Identifies specific applications (YouTube, WeChat, etc.) based on SNI domain matching.

mod mappings;
mod trie;

pub use mappings::DOMAIN_MAPPINGS;
pub use trie::ReverseTrie;

use std::sync::OnceLock;

static TRIE: OnceLock<ReverseTrie> = OnceLock::new();

/// 根据 SNI 域名识别应用
pub fn identify(sni: &str) -> Option<crate::core::types::Application> {
    let trie = TRIE.get_or_init(|| ReverseTrie::from_mappings(DOMAIN_MAPPINGS));
    trie.lookup(sni)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::Application;

    #[test]
    fn test_exact_match() {
        assert_eq!(identify("youtube.com"), Some(Application::YouTube));
    }

    #[test]
    fn test_subdomain_match() {
        assert_eq!(identify("www.youtube.com"), Some(Application::YouTube));
    }

    #[test]
    fn test_no_match() {
        assert_eq!(identify("example.com"), None);
    }

    #[test]
    fn test_partial_no_match() {
        // Should NOT match youtube.com
        assert_eq!(identify("notyoutube.com"), None);
    }

    #[test]
    fn test_longest_match() {
        // Both v.qq.com and qq.com exist; v.qq.com should match TencentVideo
        assert_eq!(identify("v.qq.com"), Some(Application::TencentVideo));
    }
}
