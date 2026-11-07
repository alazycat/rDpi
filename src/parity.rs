//! P0 差分链路：归一化流记录（`feature: json`）
//!
//! 把内部 [`Flow`] 映射为 nDPI/rDpi 对比用的 JSONL schema。
//! 比较器位于 `tests/parity/`，按双向规范五元组匹配这些记录。
//!
//! 示例（每行一条）：
//!
//! ```json
//! {"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":12345,"dst_port":53,
//!  "transport":"udp","master_protocol":"Dns","app_protocol":null,
//!  "category":"Dns","breed":"Safe","confidence":"Dpi",
//!  "protocol_stack":["Dns"],"risk_mask":[]}
//! ```

use crate::core::flow::Flow;
use crate::core::types::{Protocol, TransportProto};

/// 归一化后的单条流记录
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NormalizedFlow {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub transport: String,
    pub master_protocol: Option<String>,
    pub app_protocol: Option<String>,
    pub category: Option<String>,
    pub breed: Option<String>,
    pub confidence: Option<String>,
    #[serde(default)]
    pub protocol_stack: Vec<String>,
    #[serde(default)]
    pub risk_mask: Vec<String>,
}

impl NormalizedFlow {
    /// 从内部流记录导出归一化字段
    ///
    /// 协议/分类/评级沿用库内的 `Debug` 名称（`Tls`、`WebTunnel` 等），
    /// 与 nDPI 名称的对齐由 JSON 适配器负责；比较器按大小写不敏感处理。
    pub fn from_flow(flow: &Flow) -> Self {
        let key = &flow.key;
        let transport = match key.transport {
            TransportProto::Tcp => "tcp",
            TransportProto::Udp => "udp",
            TransportProto::Icmp => "icmp",
            TransportProto::Other(_) => "other",
        }
        .to_string();

        let master_protocol = flow.protocol.map(protocol_name);
        let app_protocol = flow
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.application())
            .map(|application| application.name().to_string());
        let category = flow
            .protocol
            .map(|protocol| format!("{:?}", protocol.category()));
        let breed = flow
            .protocol
            .map(|protocol| format!("{:?}", protocol.breed()));
        let confidence = flow.confidence.map(|confidence| format!("{confidence:?}"));
        let protocol_stack = flow.protocol_stack.iter().map(protocol_name).collect();

        #[cfg(feature = "risk")]
        let risk_mask = flow
            .risks
            .iter()
            .map(|risk| risk.flag.name().to_string())
            .collect();
        #[cfg(not(feature = "risk"))]
        let risk_mask = Vec::new();

        Self {
            src_ip: key.src_ip.to_string(),
            dst_ip: key.dst_ip.to_string(),
            src_port: key.src_port,
            dst_port: key.dst_port,
            transport,
            master_protocol,
            app_protocol,
            category,
            breed,
            confidence,
            protocol_stack,
            risk_mask,
        }
    }

    /// 导出排序键：信息量高的记录优先，其后按端点字典序稳定排序
    ///
    /// 单向流模型下同一连接会导出两条记录（两个方向）；下游按双向规范键
    /// 去重时保留信息更完整的一条。排序保证输出与 `HashMap` 迭代顺序无关。
    pub(crate) fn export_sort_key(&self) -> (std::cmp::Reverse<u8>, &str, u16, &str, u16, &str) {
        (
            std::cmp::Reverse(self.richness()),
            &self.src_ip,
            self.src_port,
            &self.dst_ip,
            self.dst_port,
            &self.transport,
        )
    }

    /// 信息量：已分类 / 已识别应用 / 非空协议栈 / 有风险
    fn richness(&self) -> u8 {
        u8::from(self.master_protocol.is_some())
            + u8::from(self.app_protocol.is_some())
            + u8::from(!self.protocol_stack.is_empty())
            + u8::from(!self.risk_mask.is_empty())
    }
}

fn protocol_name(protocol: Protocol) -> String {
    format!("{protocol:?}")
}
