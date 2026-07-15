//! Aho-Corasick 域名匹配引擎
//!
//! 基于 aho-corasick crate 实现的高效多模式域名匹配，
//! 用于 DNS 域名 / TLS SNI / HTTP Host 到协议和应用的映射。

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use crate::core::types::{Application, Confidence, DetectionResult, Protocol};

/// 域名匹配结果
#[derive(Debug, Clone)]
pub struct DomainMatch {
    pub protocol: Protocol,
    pub application: Option<Application>,
}

/// Aho-Corasick 域名匹配器
pub struct DomainMatcher {
    automa: AhoCorasick,
    values: Vec<DomainMatch>,
}

impl DomainMatcher {
    /// 从域名映射表构建匹配器
    pub fn from_entries(entries: &[(&str, Protocol, Option<Application>)]) -> Self {
        let patterns: Vec<&str> = entries.iter().map(|(d, _, _)| *d).collect();
        let values: Vec<DomainMatch> = entries
            .iter()
            .map(|(_, p, a)| DomainMatch {
                protocol: *p,
                application: *a,
            })
            .collect();

        let automa = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("valid Aho-Corasick patterns");

        Self { automa, values }
    }

    /// 匹配域名，返回最长匹配结果
    pub fn match_domain(&self, domain: &str) -> Option<&DomainMatch> {
        let domain_lower = domain.to_ascii_lowercase();
        self.automa
            .find(&domain_lower)
            .map(|m| &self.values[m.pattern().as_usize()])
    }
}

/// 域名→(协议, 应用) 映射表
pub fn domain_protocol_entries() -> Vec<(&'static str, Protocol, Option<Application>)> {
    vec![
        // Google 服务
        ("google.com",          Protocol::Http, Some(Application::Google)),
        ("youtube.com",         Protocol::Http, Some(Application::YouTube)),
        ("youtu.be",            Protocol::Http, Some(Application::YouTube)),
        ("ytimg.com",           Protocol::Http, Some(Application::YouTube)),
        ("googleapis.com",      Protocol::Tls,  None),
        // Meta
        ("facebook.com",        Protocol::Tls,  None),
        ("fbcdn.net",           Protocol::Tls,  None),
        ("instagram.com",       Protocol::Tls,  None),
        ("whatsapp.net",        Protocol::Tls,  Some(Application::WhatsApp)),
        ("whatsapp.com",        Protocol::Tls,  Some(Application::WhatsApp)),
        // Microsoft
        ("microsoft.com",       Protocol::Tls,  None),
        ("live.com",            Protocol::Tls,  None),
        ("office.com",          Protocol::Tls,  None),
        ("office365.com",       Protocol::Tls,  None),
        // 国内平台
        ("qq.com",              Protocol::Tls,  Some(Application::QQ)),
        ("weixin.qq.com",       Protocol::Tls,  Some(Application::WeChat)),
        ("tencent.com",         Protocol::Tls,  None),
        ("bilibili.com",        Protocol::Tls,  Some(Application::Bilibili)),
        ("douyin.com",          Protocol::Tls,  Some(Application::Douyin)),
        // IM
        ("telegram.org",        Protocol::Tls,  Some(Application::Telegram)),
        ("discord.com",         Protocol::Tls,  Some(Application::Discord)),
        ("discordapp.com",      Protocol::Tls,  Some(Application::Discord)),
        ("slack.com",           Protocol::Tls,  Some(Application::Slack)),
        ("line.me",             Protocol::Tls,  Some(Application::Line)),
        // 流媒体
        ("netflix.com",         Protocol::Tls,  Some(Application::Netflix)),
        ("nflxvideo.net",       Protocol::Tls,  Some(Application::Netflix)),
        ("hulu.com",            Protocol::Tls,  Some(Application::Hulu)),
        ("disneyplus.com",      Protocol::Tls,  Some(Application::DisneyPlus)),
        ("primevideo.com",      Protocol::Tls,  Some(Application::AmazonPrime)),
        ("twitch.tv",           Protocol::Tls,  Some(Application::Twitch)),
        // 通讯
        ("zoom.us",             Protocol::Tls,  Some(Application::Zoom)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_matcher() -> DomainMatcher {
        DomainMatcher::from_entries(&domain_protocol_entries())
    }

    #[test]
    fn test_match_google() {
        let matcher = test_matcher();
        let result = matcher.match_domain("www.google.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, Protocol::Http);
    }

    #[test]
    fn test_match_youtube() {
        let matcher = test_matcher();
        let result = matcher.match_domain("www.youtube.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().application, Some(Application::YouTube));
    }

    #[test]
    fn test_case_insensitive() {
        let matcher = test_matcher();
        assert!(matcher.match_domain("WWW.GOOGLE.COM").is_some());
        assert!(matcher.match_domain("www.YOUTUBE.com").is_some());
    }

    #[test]
    fn test_no_match() {
        let matcher = test_matcher();
        assert!(matcher.match_domain("example.com").is_none());
    }

    #[test]
    fn test_leftmost_longest() {
        let matcher = test_matcher();
        // weixin.qq.com 应匹配 weixin.qq.com → WeChat
        let result = matcher.match_domain("weixin.qq.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().application, Some(Application::WeChat));
    }

    #[test]
    fn test_wildcard_subdomain() {
        let matcher = test_matcher();
        // 任意子域名应匹配
        assert!(matcher.match_domain("mail.google.com").is_some());
        assert!(matcher.match_domain("drive.google.com").is_some());
    }

    #[test]
    fn test_domain_confidence() {
        let matcher = test_matcher();
        let result = matcher.match_domain("zoom.us").unwrap();
        assert_eq!(result.application, Some(Application::Zoom));
    }
}
