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
use crate::core::types::{Application, Protocol, TransportProto};
use std::collections::BTreeMap;

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
        let application = flow
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.application());
        // F44：DoH/DoQ 子分类流的 app 层记 DoH_DoT（对齐 nDPI `TLS.DoH_DoT`）；
        // F45：SMBv1/SMB23 流的 app 层记 NetBIOS（对齐 nDPI `SMBv1.NetBIOS`）
        let app_protocol = application
            .map(ndpi_compat_app_name)
            .or_else(|| flow.protocol.and_then(doh_dot_app_name).map(str::to_string))
            .or_else(|| flow.protocol.and_then(smb_app_name).map(str::to_string));
        let (category, breed) = match flow.protocol {
            Some(protocol) => {
                let (category, breed) = ndpi_compat_classification(protocol, application);
                (Some(category), Some(breed))
            }
            None => (None, None),
        };
        let confidence = flow.confidence.map(|confidence| format!("{confidence:?}"));
        let mut protocol_stack: Vec<String> =
            flow.protocol_stack.iter().map(protocol_name).collect();
        // nDPI 协议栈含 app 层（`TLS.DoH_DoT` → [TLS, DoH_DoT]、
        // `SMBv1.NetBIOS` → [SMBv1, NetBIOS]）
        if let Some(app) = app_protocol.as_deref()
            && matches!(
                flow.protocol,
                Some(Protocol::Doh | Protocol::Doq | Protocol::Smb1 | Protocol::Smb23)
            )
        {
            protocol_stack.push(app.to_string());
        }

        // 风险名导出为 nDPI 5.0 兼容名（`tls_missing_sni` → `missing_sni_tls_extn`）；
        // 逐包分析可能重复累积同一风险，导出前排序去重
        #[cfg(feature = "risk")]
        let risk_mask = {
            let mut risks: Vec<String> = flow
                .risks
                .iter()
                .map(|risk| ndpi_compat_risk_name(risk.flag.name()))
                .collect();
            risks.sort();
            risks.dedup();
            risks
        };
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

    /// 解析 nDPI `ndpiReader -K json` 的单行流记录
    ///
    /// 字段映射（与 nDPI 5.0 `ndpi_flow2json`/`ndpi_protocol2name` 对齐）：
    /// - `src_ip` / `dest_ip` / `src_port` / `dst_port` / `proto`（L4 名称）；
    /// - `ndpi.proto`：`MASTER.APP` 或单协议名——拆分到 master/app 与协议栈；
    /// - `ndpi.confidence`：数字键 → 名称的对象，取首个值；
    /// - `ndpi.flow_risk`：数字键 → `{risk, severity, ...}`，取 `risk` 名称并
    ///   归一化为 snake_case（与 rDpi `RiskFlag::name()` 对齐）。
    pub fn from_ndpi_json(line: &str) -> Result<Self, serde_json::Error> {
        let record: NdpiFlowRecord = serde_json::from_str(line)?;
        let (master_protocol, app_protocol, protocol_stack) =
            split_ndpi_protocol(record.ndpi.proto.as_deref());
        let confidence = record
            .ndpi
            .confidence
            .and_then(|confidence| confidence.into_values().next());
        let mut risk_mask: Vec<String> = record
            .ndpi
            .flow_risk
            .into_iter()
            .flat_map(BTreeMap::into_values)
            .filter_map(|risk| risk.risk)
            .map(|name| normalize_ndpi_risk(&name))
            .collect();
        risk_mask.sort();
        risk_mask.dedup();

        Ok(Self {
            src_ip: record.src_ip,
            dst_ip: record.dest_ip,
            src_port: record.src_port,
            dst_port: record.dst_port,
            transport: normalize_ndpi_transport(record.proto.as_deref()),
            master_protocol,
            app_protocol,
            category: record.ndpi.category,
            breed: record.ndpi.breed,
            confidence,
            protocol_stack,
            risk_mask,
        })
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
    match protocol {
        // 仅列出与 nDPI 5.0 名称差异超出大小写的协议
        Protocol::Redis => "RESP".to_string(),
        #[cfg(feature = "proto3")]
        Protocol::Ftp => "FTP_CONTROL".to_string(),
        // F44 子分类（真实 ndpiReader 5.0 golden 验证）：
        // - HTTP CONNECT/Proxy 是独立协议 ID（130/131），名称 HTTP_Connect/HTTP_Proxy
        // - DoH/DoT/DoQ 共用 NDPI_PROTOCOL_DOH_DOT（196），JSON 输出为
        //   `TLS.DoH_DoT` 拆分到 master/app；rDpi 的 Dot 子分类在 nDPI 5.0
        //   中不单独识别（golden 中仍报 TLS），导出统一记 TLS
        Protocol::HttpConnect => "HTTP_Connect".to_string(),
        Protocol::HttpProxy => "HTTP_Proxy".to_string(),
        Protocol::Doh | Protocol::Dot | Protocol::Doq => "TLS".to_string(),
        // F45（真实 ndpiReader 5.0 golden 验证）：NetBIOS 为独立协议 ID（10）；
        // SMBv1/SMBv2/3 分别为 SMBv1(16)/SMBv23(41)，JSON 输出为
        // `SMBv1.NetBIOS` / `SMBv23.NetBIOS` 拆分到 master/app
        #[cfg(feature = "smb")]
        Protocol::NetBios => "NetBIOS".to_string(),
        #[cfg(feature = "smb")]
        Protocol::Smb1 => "SMBv1".to_string(),
        #[cfg(feature = "smb")]
        Protocol::Smb23 => "SMBv23".to_string(),
        _ => format!("{protocol:?}"),
    }
}

/// DNS-over-X 家族的 nDPI 5.0 应用层名称（NDPI_PROTOCOL_DOH_DOT = 196）
///
/// nDPI 对 DoH/DoQ 子分类流输出 `TLS.DoH_DoT`（master TLS + app DoH_DoT）；
/// DoT 在 nDPI 5.0 中不子分类（golden 中报纯 TLS），故仅 Doh/Doq 产出 app。
fn doh_dot_app_name(protocol: Protocol) -> Option<&'static str> {
    match protocol {
        Protocol::Doh | Protocol::Doq => Some("DoH_DoT"),
        _ => None,
    }
}

/// SMB 家族的 nDPI 5.0 应用层名称
///
/// nDPI 对 SMBv1/SMBv2/3 流输出 `SMBv1.NetBIOS` / `SMBv23.NetBIOS`
/// （master SMBv1/SMBv23 + app NetBIOS）；纯 NetBIOS 流不产出 app。
fn smb_app_name(protocol: Protocol) -> Option<&'static str> {
    match protocol {
        Protocol::Smb1 | Protocol::Smb23 => Some("NetBIOS"),
        _ => None,
    }
}

/// rDpi 风险名 → nDPI 5.0 风险名（归一化后的 snake_case）
///
/// nDPI 的风险名来自 `ndpi_risk2str()`，比较器会统一转小写并把空格/标点
/// 归一化为下划线。下表只列出与 rDpi `RiskFlag::name()` 存在命名差异且
/// 语义等价的组合；未列出的名称保持原样（如 `unidirectional_traffic`
/// 两侧已一致），差异会在差分报告中暴露。
fn ndpi_compat_risk_name(name: &str) -> String {
    match name {
        "tls_missing_sni" => "missing_sni_tls_extn",
        "tls_self_signed_cert" => "self_signed_certificate",
        "tls_weak_cipher" => "weak_tls_cipher",
        "tls_obsolete_version" => "obsolete_tls_version",
        "tls_alpn_sni_mismatch" => "alpn_sni_mismatch",
        "smb_insecure_version" => "smb_insecure_ver",
        _ => name,
    }
    .to_string()
}

/// rDpi 应用名 → nDPI 5.0 应用协议名（仅列出已验证的名称差异；
/// 其余保持原名，比较器按大小写不敏感处理）
fn ndpi_compat_app_name(application: Application) -> String {
    match application {
        Application::Google => "GoogleServices".to_string(),
        _ => application.name().to_string(),
    }
}

/// rDpi 协议/应用 → nDPI 5.0 兼容的 `(category, breed)`
///
/// nDPI 的分类/评级取自最终识别协议（app 优先），DNS 等协议则固定在
/// master 上。下表只覆盖已用真实 ndpiReader 5.0 输出验证过的组合；
/// 未覆盖时回退到 rDpi 原生名称，差异会在差分报告中暴露。
fn ndpi_compat_classification(
    protocol: Protocol,
    application: Option<Application>,
) -> (String, String) {
    let native = || {
        (
            format!("{:?}", protocol.category()),
            format!("{:?}", protocol.breed()),
        )
    };
    match protocol {
        Protocol::Dns => ("Network".to_string(), "Acceptable".to_string()),
        // F44 子分类（真实 ndpiReader 5.0 golden 验证）：DoH/DoQ 在 nDPI 中
        // 为 TLS.DoH_DoT → Network/Acceptable；DoT 不子分类，golden 报纯
        // TLS → Web/Safe（与 Tls 分支一致）
        Protocol::Doh | Protocol::Doq => ("Network".to_string(), "Acceptable".to_string()),
        Protocol::Dot => ("Web".to_string(), "Safe".to_string()),
        Protocol::Http => app_taxonomy(application)
            .unwrap_or_else(|| ("Web".to_string(), "Acceptable".to_string())),
        // F44 子分类：HTTP CONNECT/Proxy 在 nDPI 中归 Web/Acceptable
        Protocol::HttpConnect | Protocol::HttpProxy => {
            ("Web".to_string(), "Acceptable".to_string())
        }
        Protocol::Tls => {
            app_taxonomy(application).unwrap_or_else(|| ("Web".to_string(), "Safe".to_string()))
        }
        // 企业协议（真实 ndpiReader 5.0 输出验证）
        Protocol::Ssh => ("RemoteAccess".to_string(), "Acceptable".to_string()),
        Protocol::Smtp => ("Email".to_string(), "Acceptable".to_string()),
        Protocol::Ntp => ("System".to_string(), "Acceptable".to_string()),
        Protocol::Dhcp | Protocol::Snmp => ("Network".to_string(), "Acceptable".to_string()),
        Protocol::Modbus => ("IoT-Scada".to_string(), "Acceptable".to_string()),
        Protocol::Redis => ("Database".to_string(), "Acceptable".to_string()),
        Protocol::Mysql | Protocol::Postgresql => {
            ("Database".to_string(), "Acceptable".to_string())
        }
        #[cfg(feature = "proto3")]
        Protocol::Ftp => ("Download".to_string(), "Unsafe".to_string()),
        #[cfg(feature = "proto3")]
        Protocol::Sip => ("VoIP".to_string(), "Acceptable".to_string()),
        #[cfg(feature = "iot")]
        Protocol::Mqtt => ("RPC".to_string(), "Acceptable".to_string()),
        // F45（真实 ndpiReader 5.0 golden 验证）：NetBIOS/SMB 在 nDPI 中归 System
        #[cfg(feature = "smb")]
        Protocol::NetBios | Protocol::Smb23 => ("System".to_string(), "Acceptable".to_string()),
        #[cfg(feature = "smb")]
        Protocol::Smb1 => ("System".to_string(), "Dangerous".to_string()),
        _ => native(),
    }
}

/// 已验证的应用层分类/评级（HTTP/TLS 共用）
fn app_taxonomy(application: Option<Application>) -> Option<(String, String)> {
    let (category, breed) = match application? {
        Application::YouTube => ("Media", "Fun"),
        Application::Facebook => ("SocialNetwork", "Fun"),
        Application::GitHub => ("Collaborative", "Acceptable"),
        Application::Google => ("Web", "Acceptable"),
        _ => return None,
    };
    Some((category.to_string(), breed.to_string()))
}

/// 解析 nDPI JSONL 文本（每行一条流记录，空行跳过）
pub fn parse_ndpi_jsonl(text: &str) -> Result<Vec<NormalizedFlow>, serde_json::Error> {
    let mut flows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        flows.push(NormalizedFlow::from_ndpi_json(line)?);
    }
    Ok(flows)
}

/// nDPI `proto`（L4）名称 → 归一化 transport
fn normalize_ndpi_transport(proto: Option<&str>) -> String {
    match proto {
        Some(name) if !name.is_empty() => name.to_ascii_lowercase(),
        _ => "other".to_string(),
    }
}

/// nDPI L7 协议名拆分：`MASTER.APP` → (master, app, stack)
fn split_ndpi_protocol(proto: Option<&str>) -> (Option<String>, Option<String>, Vec<String>) {
    let Some(name) = proto.filter(|name| !name.is_empty()) else {
        return (None, None, Vec::new());
    };
    match name.split_once('.') {
        Some((master, app)) if !master.is_empty() && !app.is_empty() => (
            Some(master.to_string()),
            Some(app.to_string()),
            vec![master.to_string(), app.to_string()],
        ),
        _ => (Some(name.to_string()), None, vec![name.to_string()]),
    }
}

/// nDPI 风险名 → snake_case（如 `Unidirectional Traffic` →
/// `unidirectional_traffic`），与 rDpi `RiskFlag::name()` 命名对齐
fn normalize_ndpi_risk(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_separator = false;
    for ch in name.trim().to_ascii_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_separator = false;
        } else if !last_separator && !out.is_empty() {
            out.push('_');
            last_separator = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

/// ndpiReader 单条流 JSON（仅反序列化归一化所需字段）
#[derive(Debug, serde::Deserialize)]
struct NdpiFlowRecord {
    src_ip: String,
    dest_ip: String,
    #[serde(default)]
    src_port: u16,
    #[serde(default)]
    dst_port: u16,
    /// L4 协议名称（TCP / UDP / ICMP / ...）
    #[serde(default)]
    proto: Option<String>,
    ndpi: NdpiProtocolInfo,
}

#[derive(Debug, serde::Deserialize)]
struct NdpiProtocolInfo {
    /// L7 协议名：`MASTER.APP` 或单协议
    #[serde(default)]
    proto: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    breed: Option<String>,
    /// 数字置信度 ID → 名称
    #[serde(default)]
    confidence: Option<BTreeMap<String, String>>,
    /// 数字风险 ID → 风险详情
    #[serde(default)]
    flow_risk: Option<BTreeMap<String, NdpiRiskInfo>>,
}

#[derive(Debug, serde::Deserialize)]
struct NdpiRiskInfo {
    #[serde(default)]
    risk: Option<String>,
}
