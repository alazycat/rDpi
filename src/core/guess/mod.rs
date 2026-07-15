//! 检测猜测引擎
//!
//! 当 DPI 无法识别协议时，依次尝试域名匹配 → IP 子网 → 端口回退。

pub(crate) mod info;
pub(crate) mod port;

pub(crate) use info::GuessContext;

use crate::core::types::DetectionResult;

/// 猜测引擎
pub(crate) struct GuessEngine;

impl GuessEngine {
    /// 执行猜测链路
    pub fn guess(ctx: &GuessContext) -> Option<DetectionResult> {
        // 域名匹配 (Task 5)
        // IP 子网匹配 (Task 4)
        port::match_port(ctx.dst_port)
    }
}
