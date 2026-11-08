//! 实时抓包适配层（feature: `live`）
//!
//! 通过运行时动态加载 Npcap（Windows）或 libpcap（Linux/macOS）读取网卡帧。
//! 默认构建不引入这些依赖；抓到的以太网帧可直接交给
//! [`Detector::process_packet`](crate::Detector::process_packet)。

mod ffi;

/// 列出所有可抓包设备。
///
/// 后端动态库缺失时返回 [`LiveError::BackendUnavailable`]。
pub fn devices() -> Result<Vec<Device>, LiveError> {
    ffi::list_devices()
}

/// 抓包配置。
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// pcap 设备名（`devices()` 返回的 `Device::name`）
    pub device: String,
    /// BPF 过滤表达式；`None` 表示不过滤
    pub filter: Option<String>,
    /// 快照长度，默认 65535
    pub snaplen: i32,
    /// 混杂模式，默认 true
    pub promisc: bool,
    /// 读超时（毫秒），默认 100
    pub timeout_ms: i32,
}

impl CaptureConfig {
    /// 以设备名创建默认配置。
    pub fn new(device: impl Into<String>) -> Self {
        Self {
            device: device.into(),
            filter: None,
            snaplen: 65535,
            promisc: true,
            timeout_ms: 100,
        }
    }

    /// 设置 BPF 过滤表达式。
    pub fn filter(mut self, expression: impl Into<String>) -> Self {
        self.filter = Some(expression.into());
        self
    }

    /// 设置快照长度。
    pub fn snaplen(mut self, snaplen: i32) -> Self {
        self.snaplen = snaplen;
        self
    }

    /// 设置混杂模式。
    pub fn promisc(mut self, promisc: bool) -> Self {
        self.promisc = promisc;
        self
    }

    /// 设置读超时（毫秒）。
    pub fn timeout_ms(mut self, timeout_ms: i32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
}

/// 可抓包设备。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// 传给 `CaptureConfig::new` 的设备名（Windows: `\Device\NPF_{GUID}`）
    pub name: String,
    /// 描述（Windows 为 "Ethernet" / "Wi-Fi" 等；可能为 `None`）
    pub description: Option<String>,
    /// 是否回环设备
    pub is_loopback: bool,
    /// 是否处于 up 状态
    pub is_up: bool,
}

/// 一帧以太网数据。
#[derive(Debug, Clone)]
pub struct CapturedFrame {
    /// 帧字节（长度 = caplen，不超过 snaplen）
    pub data: Vec<u8>,
    /// 抓包时间戳（微秒）
    pub timestamp_us: u64,
    /// 原始线上长度（可能大于 `data.len()`，表示被 snaplen 截断）
    pub original_len: u32,
}

/// 实时抓包错误。
#[derive(Debug, thiserror::Error)]
pub enum LiveError {
    /// 找不到可用的 pcap 动态库
    #[error("pcap backend not found (tried: {tried:?}); install Npcap or libpcap: {message}")]
    BackendUnavailable {
        /// 已尝试的库路径/名称
        tried: Vec<String>,
        /// 最后一次加载错误
        message: String,
    },

    /// 设备名为空或包含 NUL
    #[error("capture device not found: {0}")]
    DeviceNotFound(String),

    /// 打开设备失败
    #[error("failed to open device '{device}': {message}")]
    OpenFailed {
        /// 设备名
        device: String,
        /// pcap 错误文本
        message: String,
    },

    /// BPF 编译或应用失败
    #[error("invalid BPF filter '{expression}': {message}")]
    Filter {
        /// 用户提供的表达式
        expression: String,
        /// pcap 错误文本
        message: String,
    },

    /// 非以太网链路层
    #[error("unsupported data link type {0}; only Ethernet (DLT_EN10MB=1) is supported")]
    UnsupportedDatalink(i32),

    /// 读取过程中的其他 pcap 错误
    #[error("capture error: {0}")]
    Capture(String),
}
