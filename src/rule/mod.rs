//! 自定义规则引擎
//!
//! 支持 JSON 配置的规则匹配，运行在内置 DPI 检测器之前。
//! 触发条件：端口、SNI 子串、payload 子串。
//!
//! # Feature
//!
//! 需要在 `Cargo.toml` 中启用 `rule` 功能：
//!
//! ```toml
//! [dependencies]
//! rdpi = { features = ["rule"] }
//! ```

mod parser;

use crate::core::types::*;

/// 单条自定义规则
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub protocol: Protocol,
    pub condition: RuleCondition,
    pub metadata: Option<Metadata>,
}

/// 规则触发条件
#[derive(Debug, Clone, Default)]
pub struct RuleCondition {
    pub dst_port: Option<u16>,
    pub src_port: Option<u16>,
    pub sni_contains: Option<String>,
    pub payload_contains: Option<String>,
}

impl RuleCondition {
    /// 计算特异性分数
    ///
    /// 分数越高表示匹配条件越精确。
    /// - 端口匹配：1 分
    /// - SNI 子串匹配：2 分
    /// - Payload 子串匹配：2 分
    pub fn specificity(&self) -> u32 {
        let mut score = 0u32;
        if self.dst_port.is_some() {
            score += 1;
        }
        if self.src_port.is_some() {
            score += 1;
        }
        if self.sni_contains.is_some() {
            score += 2;
        }
        if self.payload_contains.is_some() {
            score += 2;
        }
        score
    }

    /// 检查条件是否匹配
    ///
    /// 所有配置的条件字段都必须满足才视为匹配（AND 语义）。
    pub fn matches(&self, ctx: &RuleContext) -> bool {
        if let Some(port) = self.dst_port {
            if ctx.dst_port != port {
                return false;
            }
        }
        if let Some(port) = self.src_port {
            if ctx.src_port != port {
                return false;
            }
        }
        if let Some(ref sni) = self.sni_contains {
            match ctx.sni {
                Some(ref s) => {
                    if !s.contains(sni.as_str()) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        if let Some(ref pat) = self.payload_contains {
            if !ctx.payload.windows(pat.len()).any(|w| w == pat.as_bytes()) {
                return false;
            }
        }
        true
    }
}

/// 规则匹配上下文
///
/// 由调用方（如 Detector）构建，传递给规则引擎进行匹配。
#[derive(Debug, Clone)]
pub struct RuleContext {
    pub src_port: u16,
    pub dst_port: u16,
    pub sni: Option<String>,
    pub payload: Vec<u8>,
}

/// 规则引擎
///
/// 维护一组自定义规则，支持按特异性优先级匹配。
///
/// # Examples
///
/// ```rust
/// use rdpi::rule::{RuleEngine, Rule, RuleCondition, RuleContext};
/// use rdpi::Protocol;
///
/// let mut engine = RuleEngine::new();
/// engine.add_rule(Rule {
///     id: "my-http".into(),
///     protocol: Protocol::Http,
///     condition: RuleCondition { dst_port: Some(8080), ..Default::default() },
///     metadata: None,
/// });
///
/// let ctx = RuleContext {
///     src_port: 54321, dst_port: 8080,
///     sni: None, payload: vec![],
/// };
///
/// if let Some(result) = engine.match_rule(&ctx) {
///     println!("Matched: {:?}", result.protocol);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RuleEngine {
    pub(crate) rules: Vec<Rule>,
}

impl RuleEngine {
    /// 创建空规则引擎
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
        }
    }

    /// 从 JSON 字符串加载规则
    ///
    /// # Errors
    ///
    /// 返回 `Err` 当 JSON 格式无法解析时。
    pub fn from_json(json: &str) -> Result<Self, String> {
        let parsed: parser::RuleFile = serde_json::from_str(json)
            .map_err(|e| format!("Invalid rule JSON: {}", e))?;
        let rules = parsed.into_rules();
        Ok(Self { rules })
    }

    /// 从文件加载规则
    ///
    /// # Errors
    ///
    /// 返回 `Err` 当文件无法读取或 JSON 格式错误时。
    pub fn from_file(path: &str) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Cannot read rule file: {}", e))?;
        Self::from_json(&content)
    }

    /// 添加一条规则
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// 获取规则总数
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 匹配规则
    ///
    /// 返回特异性分数最高的匹配规则对应的 `DetectionResult`。
    /// 未匹配时返回 `None`。
    pub fn match_rule(&self, ctx: &RuleContext) -> Option<DetectionResult> {
        let mut best: Option<(u32, &Rule)> = None;

        for rule in &self.rules {
            if rule.condition.matches(ctx) {
                let spec = rule.condition.specificity();
                match best {
                    Some((best_spec, _)) if spec <= best_spec => continue,
                    _ => best = Some((spec, rule)),
                }
            }
        }

        best.map(|(_, rule)| {
            let mut result = DetectionResult::new(rule.protocol)
                .with_confidence(Confidence::CustomRule);
            if let Some(ref meta) = rule.metadata {
                result = result.with_metadata(meta.clone());
            }
            result
        })
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_rule() {
        let mut engine = RuleEngine::new();
        engine.add_rule(Rule {
            id: "test-http".into(),
            protocol: Protocol::Http,
            condition: RuleCondition {
                dst_port: Some(8080),
                ..Default::default()
            },
            metadata: None,
        });
        let ctx = RuleContext {
            src_port: 12345,
            dst_port: 8080,
            sni: None,
            payload: vec![],
        };
        let result = engine.match_rule(&ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(result.confidence, Confidence::CustomRule);
    }

    #[test]
    fn test_sni_rule() {
        let mut engine = RuleEngine::new();
        engine.add_rule(Rule {
            id: "zoom".into(),
            protocol: Protocol::Tls,
            condition: RuleCondition {
                sni_contains: Some("zoom.us".into()),
                ..Default::default()
            },
            metadata: None,
        });
        let ctx = RuleContext {
            src_port: 12345,
            dst_port: 443,
            sni: Some("client.zoom.us".into()),
            payload: vec![],
        };
        assert!(engine.match_rule(&ctx).is_some());
    }

    #[test]
    fn test_payload_rule() {
        let mut engine = RuleEngine::new();
        engine.add_rule(Rule {
            id: "bittorrent".into(),
            protocol: Protocol::Tls,
            condition: RuleCondition {
                payload_contains: Some("BitTorrent".into()),
                ..Default::default()
            },
            metadata: None,
        });
        let ctx = RuleContext {
            src_port: 6881,
            dst_port: 6881,
            sni: None,
            payload: b"BitTorrent protocol".to_vec(),
        };
        assert!(engine.match_rule(&ctx).is_some());
    }

    #[test]
    fn test_specificity_wins() {
        let mut engine = RuleEngine::new();
        engine.add_rule(Rule {
            id: "port-only".into(),
            protocol: Protocol::Http,
            condition: RuleCondition {
                dst_port: Some(443),
                ..Default::default()
            },
            metadata: None,
        });
        engine.add_rule(Rule {
            id: "sni+port".into(),
            protocol: Protocol::Tls,
            condition: RuleCondition {
                dst_port: Some(443),
                sni_contains: Some("zoom".into()),
                ..Default::default()
            },
            metadata: None,
        });
        let ctx = RuleContext {
            src_port: 12345,
            dst_port: 443,
            sni: Some("zoom.us".into()),
            payload: vec![],
        };
        let result = engine.match_rule(&ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Tls);
    }

    #[test]
    fn test_no_match() {
        let mut engine = RuleEngine::new();
        engine.add_rule(Rule {
            id: "strict".into(),
            protocol: Protocol::Dns,
            condition: RuleCondition {
                dst_port: Some(5353),
                ..Default::default()
            },
            metadata: None,
        });
        let ctx = RuleContext {
            src_port: 12345,
            dst_port: 53,
            sni: None,
            payload: vec![],
        };
        assert!(engine.match_rule(&ctx).is_none());
    }

    #[test]
    fn test_json_parsing() {
        let json = r#"{
            "rules": [
                { "id": "test", "protocol": "Http", "condition": { "dst_port": 80 } }
            ]
        }"#;
        let engine = RuleEngine::from_json(json).unwrap();
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn test_json_invalid() {
        assert!(RuleEngine::from_json("not json").is_err());
    }
}
