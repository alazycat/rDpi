//! Reverse Trie for domain suffix matching

use std::collections::HashMap;

use crate::core::types::Application;

/// 反向 Trie 用于域名后缀匹配
pub struct ReverseTrie {
    root: TrieNode,
}

struct TrieNode {
    children: HashMap<char, TrieNode>,
    application: Option<Application>,
}

impl ReverseTrie {
    /// 从映射表构建 Trie
    pub fn from_mappings(mappings: &[(&str, Application)]) -> Self {
        let mut root = TrieNode::new();
        for (domain, app) in mappings {
            root.insert(domain, *app);
        }
        Self { root }
    }

    /// 查找域名匹配的应用
    pub fn lookup(&self, sni: &str) -> Option<Application> {
        let reversed: String = sni.chars().rev().collect();
        self.root.search(&reversed)
    }
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            application: None,
        }
    }

    fn insert(&mut self, domain: &str, app: Application) {
        let reversed: String = domain.chars().rev().collect();
        let mut node = self;
        for ch in reversed.chars() {
            node = node.children.entry(ch).or_insert_with(TrieNode::new);
        }
        node.application = Some(app);
    }

    fn search(&self, reversed: &str) -> Option<Application> {
        let mut node = self;
        for ch in reversed.chars() {
            if let Some(next) = node.children.get(&ch) {
                node = next;
                if node.application.is_some() {
                    return node.application;
                }
            } else {
                break;
            }
        }
        None
    }
}
