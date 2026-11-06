//! Risk analysis engine for rDpi
//!
//! Provides risk detection infrastructure parallel to protocol detection.

pub mod processors;
pub mod types;

pub use types::*;

use crate::core::flow::Flow;
use crate::parser::ParsedPacket;

/// 风险检测器 Trait
///
/// 与 `ProtocolDetector` 平行设计，每个处理器专注于一种风险类别。
#[cfg(feature = "risk")]
pub trait RiskProcessor: Send + Sync {
    /// 处理器名称
    fn name(&self) -> &'static str;

    /// 逐包分析（packet 到达时调用）
    fn analyze_packet(&self, _parsed: &ParsedPacket, _flow: &Flow) -> Vec<RiskResult> {
        vec![]
    }

    /// 流结束时分析（流过期/关闭时调用）
    fn analyze_flow(&self, _flow: &Flow) -> Vec<RiskResult> {
        vec![]
    }
}

/// 风险注册表
///
/// 管理所有注册的风险检测器，提供统一的分析入口。
#[cfg(feature = "risk")]
pub struct RiskRegistry {
    /// 逐包分析的处理器
    packet_processors: Vec<std::sync::Arc<dyn RiskProcessor>>,
    /// 流结束时分析的处理器
    flow_processors: Vec<std::sync::Arc<dyn RiskProcessor>>,
}

#[cfg(feature = "risk")]
impl RiskRegistry {
    /// 创建空的注册表
    pub fn new() -> Self {
        Self {
            packet_processors: Vec::new(),
            flow_processors: Vec::new(),
        }
    }

    /// 注册处理器
    ///
    /// 同一处理器注册到 packet 与 flow 两个列表——处理器未实现的方法
    /// 走 trait 默认空实现，不会重复产出（此前只注册 packet 侧，
    /// flow_processors 恒空导致 analyze_flow 永不产出任何结果）。
    pub fn register(&mut self, processor: Box<dyn RiskProcessor>) {
        let p: std::sync::Arc<dyn RiskProcessor> = std::sync::Arc::from(processor);
        self.packet_processors.push(p.clone());
        self.flow_processors.push(p);
    }

    /// 逐包运行所有处理器
    pub fn analyze_packet(&self, parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult> {
        let mut results = Vec::new();
        for proc in &self.packet_processors {
            results.extend(proc.analyze_packet(parsed, flow));
        }
        results
    }

    /// 流结束时运行所有处理器
    pub fn analyze_flow(&self, flow: &Flow) -> Vec<RiskResult> {
        let mut results = Vec::new();
        for proc in &self.flow_processors {
            results.extend(proc.analyze_flow(flow));
        }
        results
    }

    /// 获取注册的处理器数量
    pub fn processor_count(&self) -> usize {
        self.packet_processors.len()
    }
}

#[cfg(feature = "risk")]
impl Default for RiskRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        processors::register_defaults(&mut registry);
        registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::TransportProto;
    use crate::core::flow::Flow;
    use crate::core::types::FlowKey;

    struct TestProcessor;

    #[cfg(feature = "risk")]
    impl RiskProcessor for TestProcessor {
        fn name(&self) -> &'static str {
            "test"
        }
        fn analyze_packet(&self, _parsed: &ParsedPacket, _flow: &Flow) -> Vec<RiskResult> {
            vec![RiskResult::new(
                RiskFlag::TlsMissingSni,
                RiskSeverity::Medium,
                "test risk",
            )]
        }
        fn analyze_flow(&self, _flow: &Flow) -> Vec<RiskResult> {
            vec![RiskResult::new(
                RiskFlag::ProbingAttempt,
                RiskSeverity::Low,
                "test flow risk",
            )]
        }
    }

    fn dummy_flow() -> Flow {
        Flow::new(FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            transport: TransportProto::Tcp,
        })
    }

    #[test]
    fn test_registry_register() {
        let mut registry = RiskRegistry::new();
        registry.register(Box::new(TestProcessor));
        assert_eq!(registry.processor_count(), 1);
    }

    /// 同一处理器须同时可跑 packet 与 flow 两个阶段（此前 flow_processors 恒空）
    #[test]
    fn test_registry_dual_phase_registration() {
        let mut registry = RiskRegistry::new();
        registry.register(Box::new(TestProcessor));
        let flow = dummy_flow();
        assert_eq!(registry.analyze_flow(&flow).len(), 1);
    }

    #[test]
    fn test_registry_analyze_packet() {
        let mut registry = RiskRegistry::new();
        registry.register(Box::new(TestProcessor));
        let parsed = crate::parser::ParsedPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            transport: TransportProto::Tcp,
            payload: vec![],
            tcp: None,
            ttl: 0,
        };
        let flow = dummy_flow();
        let results = registry.analyze_packet(&parsed, &flow);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].flag, RiskFlag::TlsMissingSni);
    }

    #[test]
    fn test_registry_empty() {
        let registry = RiskRegistry::new();
        let parsed = crate::parser::ParsedPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            transport: TransportProto::Tcp,
            payload: vec![],
            tcp: None,
            ttl: 0,
        };
        let flow = dummy_flow();
        assert!(registry.analyze_packet(&parsed, &flow).is_empty());
    }
}
