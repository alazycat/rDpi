//! 跨平台 Ctrl-C 中断标志（仅 live feature）。

use super::LiveError;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// 跨平台 Ctrl-C 中断标志。
///
/// 第一次信号置位 `requested`；第二次信号直接 `std::process::exit(130)`。
#[derive(Clone)]
pub struct InterruptFlag {
    requested: Arc<AtomicBool>,
    signals: Arc<AtomicU8>,
}

impl InterruptFlag {
    /// 安装进程级 Ctrl-C 处理器；重复安装返回错误。
    pub fn install() -> Result<Self, LiveError> {
        let flag = Self::default();
        let requested = Arc::clone(&flag.requested);
        let signals = Arc::clone(&flag.signals);
        ctrlc::set_handler(move || match signals.fetch_add(1, Ordering::SeqCst) {
            0 => requested.store(true, Ordering::SeqCst),
            _ => std::process::exit(130),
        })
        .map_err(|error| LiveError::Signal(error.to_string()))?;
        Ok(flag)
    }

    /// 是否已收到第一次 Ctrl-C。
    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }
}

impl Default for InterruptFlag {
    fn default() -> Self {
        Self {
            requested: Arc::new(AtomicBool::new(false)),
            signals: Arc::new(AtomicU8::new(0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_flag_is_not_requested() {
        assert!(!InterruptFlag::default().is_requested());
    }

    #[test]
    fn clones_share_the_requested_state() {
        let flag = InterruptFlag::default();
        let clone = flag.clone();
        flag.requested.store(true, Ordering::SeqCst);
        assert!(clone.is_requested());
    }
}
