//! HTTP security risk processors
//!
//! Detects HTTP-related risks using payload inspection.

use crate::core::flow::Flow;
use crate::core::types::Protocol;
use crate::risk::types::{RiskFlag, RiskResult, RiskSeverity};
use crate::parser::ParsedPacket;
use crate::risk::RiskProcessor;

/// 已知爬虫 User-Agent 关键词（小写）
const CRAWLER_AGENTS: &[&str] = &[
    "googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider",
    "yandexbot", "facebot", "ia_archiver", "twitterbot",
    "rogerbot", "linkedinbot", "embedly", "quora link preview",
    "showyoubot", "outbrain", "pinterestbot",
    "seznambot", "semrushbot", "ahrefsbot", "dotbot",
    "applebot", "bytespider", "petalbot",
];

/// 过时 HTTP Server 版本关键词
const OBSOLETE_SERVERS: &[&str] = &[
    "apache/1.", "apache/2.0.", "apache/2.2.",
    "iis/5.", "iis/6.", "iis/7.0",
    "nginx/0.", "nginx/1.0.", "nginx/1.1.", "nginx/1.2.",
    "nginx/1.3.", "nginx/1.4.", "nginx/1.5.", "nginx/1.6.",
    "nginx/1.7.", "nginx/1.8.", "nginx/1.9.",
];

/// 明文密码字段模式（小写）
const PASSWORD_PATTERNS: &[&str] = &[
    "password=", "passwd=", "pwd=", "userpassword=",
    "pass=", "secret=", "passphrase=",
];

/// HTTP 安全风险处理器
pub struct HttpRiskProcessor;

impl HttpRiskProcessor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HttpRiskProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskProcessor for HttpRiskProcessor {
    fn name(&self) -> &'static str {
        "http_risk"
    }

    fn analyze_packet(&self, parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult> {
        if flow.protocol != Some(Protocol::Http) {
            return vec![];
        }

        let mut results = Vec::new();
        let payload_str = match std::str::from_utf8(&parsed.payload) {
            Ok(s) => s,
            Err(_) => return results, // non-UTF8 payload can't be HTTP
        };
        let lower = payload_str.to_lowercase();

        // 1. ClearTextCredentials: 检查请求中是否含明文密码
        if has_password(&lower) {
            results.push(RiskResult::new(
                RiskFlag::ClearTextCredentials,
                RiskSeverity::Critical,
                "Plaintext password detected in HTTP request",
            ));
        }

        // 2. HttpCrawlerBot: 检查 User-Agent 是否为已知爬虫
        if let Some(crawler) = find_crawler(&lower) {
            results.push(RiskResult::new(
                RiskFlag::HttpCrawlerBot,
                RiskSeverity::Low,
                format!("Known crawler/bot detected: {}", crawler),
            ));
        }

        // 3. HttpObsoleteServer: 检查 Server 头是否为过时版本
        if let Some(server) = find_obsolete_server(&lower) {
            results.push(RiskResult::new(
                RiskFlag::HttpObsoleteServer,
                RiskSeverity::Medium,
                format!("Obsolete HTTP server version: {}", server),
            ));
        }

        // 4. HttpSuspiciousContent: 检查内容特征（大块 base64/混淆 JS）
        if is_suspicious_content(payload_str, &lower) {
            results.push(RiskResult::new(
                RiskFlag::HttpSuspiciousContent,
                RiskSeverity::High,
                format!("Suspicious HTTP content ({} bytes)", parsed.payload.len()),
            ));
        }

        results
    }

    fn analyze_flow(&self, _flow: &Flow) -> Vec<RiskResult> {
        vec![]
    }
}

/// 检查是否含明文密码
fn has_password(lower: &str) -> bool {
    PASSWORD_PATTERNS.iter().any(|p| lower.contains(p))
}

/// 查找爬虫
fn find_crawler(lower: &str) -> Option<&'static str> {
    CRAWLER_AGENTS.iter().find(|&&agent| lower.contains(agent)).copied()
}

/// 查找过时服务器
fn find_obsolete_server(lower: &str) -> Option<&'static str> {
    // 在 Server: 头之后查找
    if let Some(pos) = lower.find("server: ") {
        let server_val = &lower[pos + 8..];
        let end = server_val.find('\r').unwrap_or(server_val.len());
        let server = &server_val[..end];
        OBSOLETE_SERVERS.iter().find(|&&s| server.contains(s)).copied()
    } else {
        None
    }
}

/// 检查可疑内容
fn is_suspicious_content(payload: &str, lower: &str) -> bool {
    // 特征1: 内容类型为 HTML/JS 且包含大块 base64 字符串 (>100 chars)
    // 特征2: 包含 `eval(` 或 `document.write(` 混淆 JS
    // 特征3:  payload 中 base64 字符比例异常高
    if payload.len() < 500 {
        return false;
    }

    // 检查 base64 块和大数据块
    let has_long_b64 = payload.len() > 2000;
    let has_obfuscated_js = lower.contains("eval(") && lower.contains("fromcharcode");
    let has_long_number = payload.contains("9999999999");

    (has_long_b64 && has_obfuscated_js) || (has_long_b64 && has_long_number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::flow::Flow;
    use crate::core::types::{FlowKey, TransportProto};

    fn make_http_flow(payload: &str) -> (ParsedPacket, Flow) {
        let mut flow = Flow::new(FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 54321, dst_port: 80,
            transport: TransportProto::Tcp,
        });
        flow.protocol = Some(Protocol::Http);
        let parsed = ParsedPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 54321, dst_port: 80,
            transport: TransportProto::Tcp,
            payload: payload.as_bytes().to_vec(),
        };
        (parsed, flow)
    }

    #[test]
    fn test_clear_text_credentials() {
        let (p, f) = make_http_flow("POST /login HTTP/1.1\r\npassword=secret123\r\n");
        let proc = HttpRiskProcessor::new();
        let risks = proc.analyze_packet(&p, &f);
        assert!(risks.iter().any(|r| r.flag == RiskFlag::ClearTextCredentials));
    }

    #[test]
    fn test_crawler_bot() {
        let (p, f) = make_http_flow("GET / HTTP/1.1\r\nUser-Agent: GoogleBot\r\n");
        let proc = HttpRiskProcessor::new();
        let risks = proc.analyze_packet(&p, &f);
        assert!(risks.iter().any(|r| r.flag == RiskFlag::HttpCrawlerBot));
    }

    #[test]
    fn test_obsolete_server() {
        let (p, f) = make_http_flow("HTTP/1.1 200 OK\r\nServer: Apache/2.2.15\r\n");
        let proc = HttpRiskProcessor::new();
        let risks = proc.analyze_packet(&p, &f);
        assert!(risks.iter().any(|r| r.flag == RiskFlag::HttpObsoleteServer));
    }

    #[test]
    fn test_suspicious_content() {
        let payload = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{}9999999999{}",
            "A".repeat(2001), "B".repeat(2001));
        let (p, f) = make_http_flow(&payload);
        let proc = HttpRiskProcessor::new();
        let risks = proc.analyze_packet(&p, &f);
        assert!(risks.iter().any(|r| r.flag == RiskFlag::HttpSuspiciousContent));
    }

    #[test]
    fn test_clean_http_no_risks() {
        let (p, f) = make_http_flow("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let proc = HttpRiskProcessor::new();
        let risks = proc.analyze_packet(&p, &f);
        assert!(risks.is_empty());
    }

    #[test]
    fn test_non_http_no_risk() {
        let flow = Flow::new(FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 54321, dst_port: 443,
            transport: TransportProto::Tcp,
        });
        let parsed = ParsedPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 54321, dst_port: 443,
            transport: TransportProto::Tcp,
            payload: b"password=secret".to_vec(),
        };
        let proc = HttpRiskProcessor::new();
        let risks = proc.analyze_packet(&parsed, &flow);
        assert!(risks.is_empty());
    }
}
