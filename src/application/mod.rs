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
