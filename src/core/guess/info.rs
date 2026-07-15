//! 猜测引擎上下文

/// 猜测引擎上下文
#[derive(Debug, Clone, Default)]
pub(crate) struct GuessContext {
    /// 目的端口
    pub dst_port: u16,
}

impl GuessContext {
    pub fn new(dst_port: u16) -> Self {
        Self { dst_port }
    }
}
