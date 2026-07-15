//! 检测猜测引擎
//!
//! 当 DPI 无法识别协议时，依次尝试域名匹配 → IP 子网 → 端口回退。

pub(crate) mod info;
pub(crate) mod ip;
pub(crate) mod port;

pub(crate) use info::GuessContext;

use crate::core::types::DetectionResult;

/// 猜测引擎
pub(crate) struct GuessEngine {
    ip_matcher: Option<ip::IpMatcher>,
}

impl GuessEngine {
    /// 创建默认猜测引擎（含内置 IP 子网表）
    pub fn new() -> Self {
        Self {
            ip_matcher: Some(ip::IpMatcher::new(ip::builtin_subnets())),
        }
    }

    /// 执行猜测链路：域名 → IP → 端口
    pub fn guess(&self, ctx: &GuessContext) -> Option<DetectionResult> {
        self.match_ip(ctx)
            .or_else(|| port::match_port(ctx.dst_port))
    }

    fn match_ip(&self, ctx: &GuessContext) -> Option<DetectionResult> {
        self.ip_matcher
            .as_ref()
            .and_then(|m| ctx.dst_ip.and_then(|ip| m.match_ip(ip)))
    }
}

impl Default for GuessEngine {
    fn default() -> Self {
        Self::new()
    }
}
