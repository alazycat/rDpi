# Live Capture 垂直切片实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 rDpi 增加单线程实时抓包能力：动态加载 Npcap/libpcap，提供 `rdpi::live` 库 API，并让 CLI 支持 `-i <网卡>`、`--list-ifaces`、BPF 过滤与计数/时长停止。

**Architecture:** 新增可选 feature `live`，`src/live/mod.rs` 提供安全公共 API，`src/live/ffi.rs` 集中所有 `unsafe` 与 pcap 动态符号。抓到的以太网帧直接交给现有 `Detector::process_packet`，CLI 文件路径与实时路径共用抽取后的 `OutputSink`。

**Tech Stack:** Rust 2024、`libloading 0.8`（可选依赖）、现有 `Detector`/`PcapProcessor`/clap/serde。

## Global Constraints

- 不新增除 `libloading` 之外的依赖；`libloading` 必须为 optional，默认构建不受影响。
- 核心 crate 保持零 C/C++ 编译期依赖；不得引入 Npcap SDK / libpcap 开发包。
- `unsafe` 只允许出现在 `src/live/ffi.rs`；`src/live/mod.rs`、`src/bin/rdpi.rs` 不写 `unsafe`。
- 仅接受 `DLT_EN10MB`（值 1）；其他链路层返回 `LiveError::UnsupportedDatalink`。
- 不实现 Ctrl-C 优雅停机；停止条件仅 `--count` / `--duration`。
- 项目文档使用中文；提交信息不得包含任何 AI 署名或 `Co-Authored-By`。
- 每次提交只包含本任务相关文件；不得修改既有 detector 注册顺序。
- 默认 features 与 `--all-features` 测试必须全绿；测试不得依赖本机安装 libpcap/Npcap。
- 既有 pcap 回放输出（text/json/jsonl/csv/flows-jsonl）语义保持不变。

---

## 文件结构

| 文件 | 职责 | 创建/修改 |
|---|---|---|
| `Cargo.toml` | `libloading` 可选依赖、`live` feature、示例 required-features | 修改 |
| `src/lib.rs` | 声明 `pub mod live`、feature 文档 | 修改 |
| `src/live/mod.rs` | 公共 API 与安全包装 | 创建 |
| `src/live/ffi.rs` | 动态加载、FFI 声明、pcap 句柄/设备链表 RAII | 创建 |
| `src/bin/rdpi.rs` | CLI 参数、来源解析、输出复用、实时循环 | 修改 |
| `examples/live_capture.rs` | 手工验证示例 | 创建 |
| `tests/test_live.rs` | feature-gated 公共 API 测试 | 创建 |
| `README.md` | feature 表与实时抓包说明 | 修改 |
| `AGENTS.md` | F47 认知条目与命令 | 修改 |
| `docs/architecture/ndpi-pure-rust-plan.md` | §9 实施进展回写 | 修改 |

---

### Task 1: Feature 与公共类型

**Files:**
- Modify: `Cargo.toml:11-48`
- Modify: `src/lib.rs:6-17`、`src/lib.rs:50-64`
- Create: `src/live/mod.rs`
- Create: `tests/test_live.rs`

**Interfaces:**
- Produces: `CaptureConfig`（字段 `device: String`、`filter: Option<String>`、`snaplen: i32`、`promisc: bool`、`timeout_ms: i32`，builder 方法同名）、`Device`、`CapturedFrame`、`LiveError`；feature `live`。

- [ ] **Step 1: 写失败测试**

创建 `tests/test_live.rs`：

```rust
#![cfg(feature = "live")]

use rdpi::live::{CaptureConfig, LiveError};

#[test]
fn capture_config_defaults() {
    let config = CaptureConfig::new("eth0");
    assert_eq!(config.device, "eth0");
    assert_eq!(config.filter, None);
    assert_eq!(config.snaplen, 65535);
    assert!(config.promisc);
    assert_eq!(config.timeout_ms, 100);
}

#[test]
fn capture_config_builder_overrides() {
    let config = CaptureConfig::new("wlan0")
        .filter("tcp port 443")
        .snaplen(9000)
        .promisc(false)
        .timeout_ms(250);
    assert_eq!(config.filter.as_deref(), Some("tcp port 443"));
    assert_eq!(config.snaplen, 9000);
    assert!(!config.promisc);
    assert_eq!(config.timeout_ms, 250);
}

#[test]
fn backend_unavailable_error_mentions_candidates() {
    let error = LiveError::BackendUnavailable {
        tried: vec!["wpcap.dll: not found".to_string()],
        message: "not found".to_string(),
    };
    let text = error.to_string();
    assert!(text.contains("wpcap.dll"));
    assert!(text.contains("Npcap"));
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features live --test test_live`

Expected: 编译失败，报 `unresolved import rdpi::live` / `no feature named live`。

- [ ] **Step 3: 添加 Cargo feature 与依赖**

在 `Cargo.toml` 的 `[dependencies]` 中 `hex = "0.4"` 之后加入：

```toml
libloading = { version = "0.8", optional = true }
```

在 `[features]` 中 `misc = [...]` 行之后加入：

```toml
live = ["dep:libloading"]  # 实时抓包适配层（动态加载 Npcap/libpcap）
```

- [ ] **Step 4: 声明模块并补文档**

在 `src/lib.rs` 的 `pub mod core;` 之后加入：

```rust
#[cfg(feature = "live")]
pub mod live;
```

在模块文档的 feature 列表（`//! - database ...` 之后）加入：

```rust
//! - `live` - live packet capture via dynamically loaded Npcap/libpcap
```

- [ ] **Step 5: 实现公共类型**

创建 `src/live/mod.rs`：

```rust
//! 实时抓包适配层（feature: `live`）
//!
//! 通过运行时动态加载 Npcap（Windows）或 libpcap（Linux/macOS）读取网卡帧。
//! 默认构建不引入这些依赖；抓到的以太网帧可直接交给
//! [`Detector::process_packet`](crate::Detector::process_packet)。

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
```

- [ ] **Step 6: 运行测试确认通过**

Run: `cargo test --features live --test test_live`

Expected: 3 passed。

- [ ] **Step 7: 提交**

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/live/mod.rs tests/test_live.rs
git commit -m "Add live capture types and feature"
```

---

### Task 2: pcap 动态加载器

**Files:**
- Create: `src/live/ffi.rs`
- Modify: `src/live/mod.rs:1`（加入 `mod ffi;`）

**Interfaces:**
- Consumes: `LiveError`（Task 1）。
- Produces: `pub(crate) fn api() -> Result<&'static PcapApi, LiveError>`、`pub(crate) fn library_candidates() -> &'static [&'static str]`、`PcapApi` 函数指针字段、`Timeval`/`PcapPkthdr`/`PcapIf`/`BpfProgram` 布局类型。

- [ ] **Step 1: 写失败测试**

创建 `src/live/ffi.rs`，只写模块头与测试：

```rust
//! pcap 动态加载与 FFI 声明。
//!
//! 所有 `unsafe` 集中在本文件。

use std::ffi::{CString, c_char, c_int, c_uchar, c_void};
use std::sync::OnceLock;

use super::LiveError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeval_layout_matches_platform() {
        #[cfg(windows)]
        assert_eq!(std::mem::size_of::<Timeval>(), 8);
        #[cfg(target_os = "macos")]
        assert_eq!(std::mem::size_of::<Timeval>(), 16);
        #[cfg(all(unix, not(target_os = "macos"), target_pointer_width = "64"))]
        assert_eq!(std::mem::size_of::<Timeval>(), 16);
        #[cfg(all(unix, not(target_os = "macos"), target_pointer_width = "32"))]
        assert_eq!(std::mem::size_of::<Timeval>(), 8);
    }

    #[test]
    fn candidates_are_platform_specific() {
        let candidates = library_candidates();
        assert!(!candidates.is_empty());
        #[cfg(windows)]
        assert!(candidates.contains(&"wpcap.dll"));
        #[cfg(all(unix, not(target_os = "macos")))]
        assert!(candidates.iter().any(|name| name.starts_with("libpcap.so")));
        #[cfg(target_os = "macos")]
        assert!(candidates.contains(&"libpcap.dylib"));
    }

    #[test]
    fn api_load_never_panics() {
        match api() {
            Ok(_) | Err(LiveError::BackendUnavailable { .. }) => {}
            Err(error) => panic!("unexpected backend error: {error}"),
        }
    }
}
```

在 `src/live/mod.rs` 第一行加入：

```rust
mod ffi;
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features live --lib live::ffi`

Expected: 编译失败，报 `cannot find type Timeval`、`cannot find function library_candidates`。

- [ ] **Step 3: 实现 FFI 类型与加载器**

在 `src/live/ffi.rs` 的 `use super::LiveError;` 之后、测试模块之前加入：

```rust
/// pcap 错误缓冲区大小（pcap.h: PCAP_ERRBUF_SIZE）
pub(crate) const PCAP_ERRBUF_SIZE: usize = 256;
/// `pcap_compile` 的未知 netmask
pub(crate) const PCAP_NETMASK_UNKNOWN: u32 = 0xffff_ffff;
/// Ethernet 链路层类型
pub(crate) const DLT_EN10MB: c_int = 1;
/// `pcap_if_t.flags`：回环
pub(crate) const PCAP_IF_LOOPBACK: u32 = 0x1;
/// `pcap_if_t.flags`：up
pub(crate) const PCAP_IF_UP: u32 = 0x2;

/// 不透明 pcap_t
#[repr(C)]
pub(crate) struct PcapT {
    _private: [u8; 0],
}

/// Windows 的 long 为 32 位；32 位 Unix 的 time_t/suseconds_t 为 32 位
#[cfg(any(windows, all(unix, not(target_os = "macos"), target_pointer_width = "32")))]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Timeval {
    pub(crate) tv_sec: i32,
    pub(crate) tv_usec: i32,
}

/// macOS 的 time_t 为 64 位、suseconds_t 为 32 位（结构体因对齐为 16 字节）
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Timeval {
    pub(crate) tv_sec: i64,
    pub(crate) tv_usec: i32,
}

/// 其余 64 位 Unix：time_t/suseconds_t 均为 64 位
#[cfg(all(unix, not(target_os = "macos"), target_pointer_width = "64"))]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Timeval {
    pub(crate) tv_sec: i64,
    pub(crate) tv_usec: i64,
}

/// 非 Windows/Unix 平台占位：候选库为空，实际运行会返回 `BackendUnavailable`。
#[cfg(not(any(windows, unix)))]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Timeval {
    pub(crate) tv_sec: i64,
    pub(crate) tv_usec: i64,
}

/// pcap 抓包头
#[repr(C)]
pub(crate) struct PcapPkthdr {
    pub(crate) ts: Timeval,
    pub(crate) caplen: u32,
    pub(crate) len: u32,
}

/// pcap 设备链表节点
#[allow(dead_code)] // addresses 仅用于保持 C 布局，本切片不读取
#[repr(C)]
pub(crate) struct PcapIf {
    pub(crate) next: *mut PcapIf,
    pub(crate) name: *mut c_char,
    pub(crate) description: *mut c_char,
    pub(crate) addresses: *mut c_void,
    pub(crate) flags: u32,
}

/// BPF 程序（pcap 分配，pcap_freecode 释放）
#[allow(dead_code)] // bf_len 由 pcap 填写，本切片不读取
#[repr(C)]
pub(crate) struct BpfProgram {
    pub(crate) bf_len: u32,
    pub(crate) bf_insns: *mut c_void,
}

type PcapFindAllDevsFn = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
type PcapFreeAllDevsFn = unsafe extern "C" fn(*mut PcapIf);
type PcapOpenLiveFn =
    unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut PcapT;
type PcapCompileFn =
    unsafe extern "C" fn(*mut PcapT, *mut BpfProgram, *const c_char, c_int, u32) -> c_int;
type PcapFreeCodeFn = unsafe extern "C" fn(*mut BpfProgram);
type PcapSetFilterFn = unsafe extern "C" fn(*mut PcapT, *mut BpfProgram) -> c_int;
type PcapNextExFn =
    unsafe extern "C" fn(*mut PcapT, *mut *mut PcapPkthdr, *mut *const c_uchar) -> c_int;
type PcapDatalinkFn = unsafe extern "C" fn(*mut PcapT) -> c_int;
type PcapGetErrFn = unsafe extern "C" fn(*mut PcapT) -> *mut c_char;
type PcapCloseFn = unsafe extern "C" fn(*mut PcapT);
type PcapLibVersionFn = unsafe extern "C" fn() -> *const c_char;

/// 已加载的 pcap 函数表。
pub(crate) struct PcapApi {
    pub(crate) findalldevs: PcapFindAllDevsFn,
    pub(crate) freealldevs: PcapFreeAllDevsFn,
    pub(crate) open_live: PcapOpenLiveFn,
    pub(crate) compile: PcapCompileFn,
    pub(crate) freecode: PcapFreeCodeFn,
    pub(crate) setfilter: PcapSetFilterFn,
    pub(crate) next_ex: PcapNextExFn,
    pub(crate) datalink: PcapDatalinkFn,
    pub(crate) geterr: PcapGetErrFn,
    pub(crate) close: PcapCloseFn,
    pub(crate) lib_version: Option<PcapLibVersionFn>,
}

static API: OnceLock<PcapApi> = OnceLock::new();

/// 获取加载后的函数表；加载失败不缓存，后续调用可重试。
pub(crate) fn api() -> Result<&'static PcapApi, LiveError> {
    if let Some(api) = API.get() {
        return Ok(api);
    }
    let loaded = PcapApi::load()?;
    Ok(API.get_or_init(|| loaded))
}

/// 当前平台的动态库候选列表。
pub(crate) fn library_candidates() -> &'static [&'static str] {
    LIBRARY_CANDIDATES
}

#[cfg(windows)]
const LIBRARY_CANDIDATES: &[&str] = &[
    "wpcap.dll",
    r"C:\Windows\System32\Npcap\wpcap.dll",
    r"C:\Program Files\Npcap\wpcap.dll",
];

#[cfg(all(unix, not(target_os = "macos")))]
const LIBRARY_CANDIDATES: &[&str] = &["libpcap.so.1", "libpcap.so.0.8", "libpcap.so"];

#[cfg(target_os = "macos")]
const LIBRARY_CANDIDATES: &[&str] = &["libpcap.dylib", "/usr/lib/libpcap.A.dylib"];

#[cfg(not(any(windows, unix)))]
const LIBRARY_CANDIDATES: &[&str] = &[];

impl PcapApi {
    fn load() -> Result<Self, LiveError> {
        let mut tried = Vec::new();
        let mut last_message = String::new();

        for &path in library_candidates() {
            // SAFETY: 候选名固定，不接受用户输入。
            match unsafe { libloading::Library::new(path) } {
                Ok(library) => {
                    // SAFETY: 符号名与签名与 pcap.h 一致。
                    match unsafe { Self::from_library(&library) } {
                        Ok(api) => {
                            // 函数指针已复制；库需在进程生命周期内保持加载。
                            std::mem::forget(library);
                            return Ok(api);
                        }
                        Err(message) => last_message = format!("{path}: {message}"),
                    }
                }
                Err(error) => {
                    tried.push(format!("{path}: {error}"));
                    last_message = error.to_string();
                }
            }
        }

        Err(LiveError::BackendUnavailable {
            tried,
            message: last_message,
        })
    }

    unsafe fn from_library(library: &libloading::Library) -> Result<Self, String> {
        Ok(Self {
            findalldevs: unsafe { require(library, "pcap_findalldevs")? },
            freealldevs: unsafe { require(library, "pcap_freealldevs")? },
            open_live: unsafe { require(library, "pcap_open_live")? },
            compile: unsafe { require(library, "pcap_compile")? },
            freecode: unsafe { require(library, "pcap_freecode")? },
            setfilter: unsafe { require(library, "pcap_setfilter")? },
            next_ex: unsafe { require(library, "pcap_next_ex")? },
            datalink: unsafe { require(library, "pcap_datalink")? },
            geterr: unsafe { require(library, "pcap_geterr")? },
            close: unsafe { require(library, "pcap_close")? },
            lib_version: unsafe { optional(library, "pcap_lib_version") },
        })
    }
}

unsafe fn require<T: Copy + 'static>(
    library: &libloading::Library,
    name: &str,
) -> Result<T, String> {
    let name = CString::new(name).map_err(|error| error.to_string())?;
    // SAFETY: 调用方保证 T 与 C 声明一致。
    unsafe { library.get::<T>(name.as_bytes_with_nul()) }
        .map(|symbol| *symbol)
        .map_err(|error| error.to_string())
}

unsafe fn optional<T: Copy + 'static>(
    library: &libloading::Library,
    name: &str,
) -> Option<T> {
    let name = CString::new(name).ok()?;
    // SAFETY: 调用方保证 T 与 C 声明一致。
    unsafe { library.get::<T>(name.as_bytes_with_nul()) }
        .ok()
        .map(|symbol| *symbol)
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --features live --lib live::ffi`

Expected: 3 passed（本机有 Npcap 时 `api_load_never_panics` 走 `Ok`；CI 无后端时走 `BackendUnavailable`）。

- [ ] **Step 5: 提交**

```bash
git add src/live/ffi.rs src/live/mod.rs Cargo.lock
git commit -m "Add dynamic pcap loader"
```

---

### Task 3: 设备枚举

**Files:**
- Modify: `src/live/ffi.rs`（文件末尾、测试模块之前）
- Modify: `src/live/mod.rs`
- Modify: `tests/test_live.rs`

**Interfaces:**
- Consumes: `api()`、`PcapIf`、`PCAP_IF_LOOPBACK`、`PCAP_IF_UP`（Task 2）、`Device`/`LiveError`（Task 1）。
- Produces: `pub fn devices() -> Result<Vec<Device>, LiveError>`；`pub(crate) fn list_devices()`；`pub(crate) unsafe fn c_ptr_to_string(ptr: *const c_char) -> Option<String>`；`pub(crate) fn errbuf_to_string(buf: &[c_char]) -> String`。

- [ ] **Step 1: 写失败测试**

在 `tests/test_live.rs` 末尾追加：

```rust
#[test]
fn devices_return_list_or_backend_error() {
    match rdpi::live::devices() {
        Ok(devices) => {
            for device in devices {
                assert!(!device.name.is_empty());
            }
        }
        Err(LiveError::BackendUnavailable { .. }) => {}
        Err(error) => panic!("unexpected device enumeration error: {error}"),
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features live --test test_live devices_return_list_or_backend_error`

Expected: 编译失败，报 `no function or associated item named 'devices'`。

- [ ] **Step 3: 实现设备枚举**

在 `src/live/ffi.rs` 的 `use super::LiveError;` 改为：

```rust
use super::{Device, LiveError};
```

并在 `optional` 函数之后、`#[cfg(test)] mod tests` 之前加入：

```rust
/// 列出所有可抓包设备。
pub(crate) fn list_devices() -> Result<Vec<Device>, LiveError> {
    let api = api()?;
    let mut head: *mut PcapIf = std::ptr::null_mut();
    let mut errbuf = [0 as c_char; PCAP_ERRBUF_SIZE];

    // SAFETY: head 由 pcap 分配，errbuf 大小符合 pcap.h 要求。
    let rc = unsafe { (api.findalldevs)(&mut head, errbuf.as_mut_ptr()) };
    if rc != 0 {
        return Err(LiveError::Capture(errbuf_to_string(&errbuf)));
    }

    let guard = DeviceList { api, head };
    let mut devices = Vec::new();
    let mut current = head;

    while !current.is_null() {
        // SAFETY: current 来自 pcap 设备链表，链接在 guard 释放前有效。
        let node = unsafe { &*current };
        let name = unsafe { c_ptr_to_string(node.name) }.unwrap_or_default();
        let description = unsafe { c_ptr_to_string(node.description) };
        devices.push(Device {
            name,
            description,
            is_loopback: node.flags & PCAP_IF_LOOPBACK != 0,
            is_up: node.flags & PCAP_IF_UP != 0,
        });
        current = node.next;
    }

    drop(guard);
    Ok(devices)
}

/// pcap 设备链表 RAII 包装。
struct DeviceList {
    api: &'static PcapApi,
    head: *mut PcapIf,
}

impl Drop for DeviceList {
    fn drop(&mut self) {
        if !self.head.is_null() {
            // SAFETY: head 来自 pcap_findalldevs，且只释放一次。
            unsafe { (self.api.freealldevs)(self.head) };
        }
    }
}

/// 把 C 字符串复制为 Rust `String`；空指针返回 `None`。
///
/// # Safety
///
/// `ptr` 必须为空指针，或指向以 NUL 结尾的有效 C 字符串。
pub(crate) unsafe fn c_ptr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: 调用方保证 ptr 指向以 NUL 结尾的有效字符串。
    Some(unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned())
}

/// 把 pcap 错误缓冲区复制为 `String`。
pub(crate) fn errbuf_to_string(buf: &[c_char]) -> String {
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&byte| byte != 0)
        .map(|&byte| byte as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
```

在 `src/live/mod.rs` 的 `mod ffi;` 之后加入：

```rust
/// 列出所有可抓包设备。
///
/// 后端动态库缺失时返回 [`LiveError::BackendUnavailable`]。
pub fn devices() -> Result<Vec<Device>, LiveError> {
    ffi::list_devices()
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --features live --test test_live devices_return_list_or_backend_error`

Expected: 1 passed。

- [ ] **Step 5: 提交**

```bash
git add src/live/ffi.rs src/live/mod.rs tests/test_live.rs
git commit -m "Add capture device enumeration"
```

---

### Task 4: LiveCapture 打开、过滤与读取

**Files:**
- Modify: `src/live/ffi.rs`
- Modify: `src/live/mod.rs`
- Modify: `tests/test_live.rs`

**Interfaces:**
- Consumes: Task 2/3 的 `api()`、`PcapT`、`PcapPkthdr`、`BpfProgram`、`c_ptr_to_string`、`errbuf_to_string`。
- Produces: `LiveCapture`（`open`、`next_frame`、`datalink`、`backend_version`、`Iterator`）；`ffi::CaptureHandle`、`ffi::PollResult`。

- [ ] **Step 1: 写失败测试**

在 `tests/test_live.rs` 末尾追加：

```rust
use rdpi::live::LiveCapture;

#[test]
fn open_empty_device_is_device_not_found() {
    match LiveCapture::open(CaptureConfig::new("")) {
        Err(LiveError::DeviceNotFound(name)) => assert!(name.is_empty()),
        Err(error) => panic!("unexpected error: {error:?}"),
        Ok(_) => panic!("unexpected success"),
    }
}

#[test]
fn open_unknown_device_reports_failure() {
    match LiveCapture::open(CaptureConfig::new("rdpi-definitely-not-a-device")) {
        Err(LiveError::OpenFailed { .. }) | Err(LiveError::BackendUnavailable { .. }) => {}
        Err(error) => panic!("unexpected error: {error:?}"),
        Ok(_) => panic!("unexpected success"),
    }
}

#[test]
fn invalid_bpf_is_reported_when_backend_available() {
    let Ok(devices) = rdpi::live::devices() else {
        return;
    };
    let Some(device) = devices.into_iter().next() else {
        return;
    };

    let config = CaptureConfig::new(device.name).filter("this is not a bpf");
    match LiveCapture::open(config) {
        Err(LiveError::Filter { expression, .. }) => {
            assert_eq!(expression, "this is not a bpf");
        }
        // 权限不足等环境问题下无法走到过滤器编译，跳过。
        Err(LiveError::OpenFailed { .. }) | Err(LiveError::BackendUnavailable { .. }) => {}
        Err(error) => panic!("unexpected error: {error:?}"),
        Ok(_) => panic!("unexpected success"),
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features live --test test_live open_empty_device_is_device_not_found`

Expected: 编译失败，报 `cannot find type LiveCapture`。

- [ ] **Step 3: 在 ffi.rs 实现句柄与读取**

在 `src/live/ffi.rs` 的 `errbuf_to_string` 之后、`#[cfg(test)] mod tests` 之前加入：

```rust
/// 一次读取的结果。
pub(crate) enum PollResult {
    /// 读到一帧
    Packet {
        data: Vec<u8>,
        timestamp_us: u64,
        original_len: u32,
    },
    /// 读超时
    Timeout,
    /// savefile 读取结束（live capture 通常不会出现）
    End,
}

/// pcap 抓包句柄 RAII 包装。
pub(crate) struct CaptureHandle {
    api: &'static PcapApi,
    handle: *mut PcapT,
    datalink: i32,
    snaplen: i32,
    backend_version: Option<String>,
}

impl CaptureHandle {
    pub(crate) fn open(
        device: &str,
        snaplen: i32,
        promisc: bool,
        timeout_ms: i32,
        filter: Option<&str>,
    ) -> Result<Self, LiveError> {
        let api = api()?;
        let device_c = CString::new(device)
            .map_err(|_| LiveError::DeviceNotFound(device.to_string()))?;
        let mut errbuf = [0 as c_char; PCAP_ERRBUF_SIZE];

        // SAFETY: device_c 为有效 C 字符串；errbuf 大小符合 pcap.h。
        let handle = unsafe {
            (api.open_live)(
                device_c.as_ptr(),
                snaplen,
                if promisc { 1 } else { 0 },
                timeout_ms,
                errbuf.as_mut_ptr(),
            )
        };
        if handle.is_null() {
            return Err(LiveError::OpenFailed {
                device: device.to_string(),
                message: errbuf_to_string(&errbuf),
            });
        }

        let mut capture = Self {
            api,
            handle,
            datalink: 0,
            snaplen,
            backend_version: None,
        };

        // SAFETY: handle 由 pcap_open_live 返回且非空。
        capture.datalink = unsafe { (capture.api.datalink)(capture.handle) };
        if capture.datalink != DLT_EN10MB {
            return Err(LiveError::UnsupportedDatalink(capture.datalink));
        }

        capture.backend_version = capture
            .api
            .lib_version
            .map(|version| unsafe { c_ptr_to_string(version()) }.unwrap_or_default());

        if let Some(expression) = filter {
            capture.apply_filter(expression)?;
        }

        Ok(capture)
    }

    pub(crate) fn datalink(&self) -> i32 {
        self.datalink
    }

    pub(crate) fn backend_version(&self) -> Option<String> {
        self.backend_version.clone()
    }

    fn apply_filter(&self, expression: &str) -> Result<(), LiveError> {
        let expression_c = CString::new(expression).map_err(|_| LiveError::Filter {
            expression: expression.to_string(),
            message: "expression contains NUL".to_string(),
        })?;
        let mut program = BpfProgram {
            bf_len: 0,
            bf_insns: std::ptr::null_mut(),
        };

        // SAFETY: handle 有效；program 由 pcap_compile 初始化。
        let rc = unsafe {
            (self.api.compile)(
                self.handle,
                &mut program,
                expression_c.as_ptr(),
                1,
                PCAP_NETMASK_UNKNOWN,
            )
        };
        if rc != 0 {
            return Err(LiveError::Filter {
                expression: expression.to_string(),
                message: self.last_error(),
            });
        }

        let guard = BpfProgramGuard {
            api: self.api,
            program: &mut program as *mut BpfProgram,
        };

        // SAFETY: program 已由 pcap_compile 成功初始化。
        let rc = unsafe { (self.api.setfilter)(self.handle, &mut program) };
        if rc != 0 {
            return Err(LiveError::Filter {
                expression: expression.to_string(),
                message: self.last_error(),
            });
        }

        drop(guard);
        Ok(())
    }

    pub(crate) fn poll(&mut self) -> Result<PollResult, LiveError> {
        let mut header: *mut PcapPkthdr = std::ptr::null_mut();
        let mut data: *const c_uchar = std::ptr::null();

        // SAFETY: handle 有效；header/data 由 pcap 填写，只在下一次 poll 前有效。
        let rc = unsafe { (self.api.next_ex)(self.handle, &mut header, &mut data) };

        match rc {
            1 => {
                if header.is_null() || data.is_null() {
                    return Err(LiveError::Capture(
                        "pcap returned a null packet".to_string(),
                    ));
                }
                // SAFETY: pcap_next_ex 返回 1 时 header 指向有效抓包头。
                let header = unsafe { &*header };
                let caplen = header.caplen as usize;
                if caplen > self.snaplen.max(0) as usize {
                    return Err(LiveError::Capture(format!(
                        "captured length {caplen} exceeds snaplen {}",
                        self.snaplen
                    )));
                }
                // SAFETY: data 指向 caplen 字节的有效载荷。
                let bytes = unsafe { std::slice::from_raw_parts(data, caplen) };
                Ok(PollResult::Packet {
                    data: bytes.to_vec(),
                    timestamp_us: timeval_to_us(header.ts),
                    original_len: header.len,
                })
            }
            0 => Ok(PollResult::Timeout),
            -2 => Ok(PollResult::End),
            _ => Err(LiveError::Capture(self.last_error())),
        }
    }

    fn last_error(&self) -> String {
        // SAFETY: handle 有效；返回指针由 pcap 管理，立即复制。
        let ptr = unsafe { (self.api.geterr)(self.handle) };
        unsafe { c_ptr_to_string(ptr) }.unwrap_or_else(|| "unknown pcap error".to_string())
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: handle 来自 pcap_open_live，且只关闭一次。
            unsafe { (self.api.close)(self.handle) };
        }
    }
}

/// `pcap_compile` 产物的 RAII 释放器。
struct BpfProgramGuard {
    api: &'static PcapApi,
    program: *mut BpfProgram,
}

impl Drop for BpfProgramGuard {
    fn drop(&mut self) {
        // SAFETY: program 已由 pcap_compile 初始化。
        unsafe { (self.api.freecode)(self.program) };
    }
}

/// `timeval` 转微秒；负值按 0 处理。
fn timeval_to_us(ts: Timeval) -> u64 {
    let seconds = ts.tv_sec.max(0) as u64;
    let micros = ts.tv_usec.max(0) as u64;
    seconds
        .saturating_mul(1_000_000)
        .saturating_add(micros.min(999_999))
}
```

- [ ] **Step 4: 在 mod.rs 实现 LiveCapture**

在 `src/live/mod.rs` 的 `use`/类型定义之后加入：

```rust
use ffi::{CaptureHandle, PollResult};

/// 实时抓包迭代器。
///
/// 每个线程必须独立 `open`；该类型不是 `Send`/`Sync`。
pub struct LiveCapture {
    handle: CaptureHandle,
}

/// 内部读取结果：区分超时与结束，供 `Iterator` 跳过超时。
enum PollOutcome {
    Frame(CapturedFrame),
    Timeout,
    End,
}

impl LiveCapture {
    /// 打开设备并应用 BPF 过滤器。
    pub fn open(config: CaptureConfig) -> Result<Self, LiveError> {
        if config.device.is_empty() {
            return Err(LiveError::DeviceNotFound(String::new()));
        }
        if config.snaplen <= 0 {
            return Err(LiveError::OpenFailed {
                device: config.device,
                message: "snaplen must be positive".to_string(),
            });
        }
        if config.timeout_ms < 0 {
            return Err(LiveError::OpenFailed {
                device: config.device,
                message: "timeout_ms must be non-negative".to_string(),
            });
        }

        let handle = CaptureHandle::open(
            &config.device,
            config.snaplen,
            config.promisc,
            config.timeout_ms,
            config.filter.as_deref(),
        )?;
        Ok(Self { handle })
    }

    /// 读取下一帧；`Ok(None)` 表示读超时（未捕获到包）或读取结束。
    pub fn next_frame(&mut self) -> Result<Option<CapturedFrame>, LiveError> {
        match self.poll_outcome()? {
            PollOutcome::Frame(frame) => Ok(Some(frame)),
            PollOutcome::Timeout | PollOutcome::End => Ok(None),
        }
    }

    /// pcap 链路层类型（正常为 1 = DLT_EN10MB）。
    pub fn datalink(&self) -> i32 {
        self.handle.datalink()
    }

    /// 底层 pcap 版本字符串。
    pub fn backend_version(&self) -> Option<String> {
        self.handle.backend_version()
    }

    fn poll_outcome(&mut self) -> Result<PollOutcome, LiveError> {
        match self.handle.poll()? {
            PollResult::Packet {
                data,
                timestamp_us,
                original_len,
            } => Ok(PollOutcome::Frame(CapturedFrame {
                data,
                timestamp_us,
                original_len,
            })),
            PollResult::Timeout => Ok(PollOutcome::Timeout),
            PollResult::End => Ok(PollOutcome::End),
        }
    }
}

impl Iterator for LiveCapture {
    type Item = Result<CapturedFrame, LiveError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.poll_outcome() {
                Ok(PollOutcome::Frame(frame)) => return Some(Ok(frame)),
                Ok(PollOutcome::Timeout) => continue,
                Ok(PollOutcome::End) => return None,
                Err(error) => return Some(Err(error)),
            }
        }
    }
}
```

- [ ] **Step 5: 运行测试确认通过**

Run: `cargo test --features live --test test_live`

Expected: 6 passed（无后端环境时依赖后端的用例走跳过分支）。

- [ ] **Step 6: 提交**

```bash
git add src/live/ffi.rs src/live/mod.rs tests/test_live.rs
git commit -m "Add live capture stream"
```

---

### Task 5: CLI 输出与统计复用（行为不变）

**Files:**
- Modify: `src/bin/rdpi.rs:46-162`

**Interfaces:**
- Consumes: 现有 `PacketRecord`、`UnknownRecord`、`Summary`、`JsonlLine`、`print_detection`、`print_text_summary`、`print_json_summary`、`print_csv_summary`。
- Produces: `OutputSink`（`new`、`on_packet`、`finish`、`total`、`detected`、`protocol_counts`）、`run_file`。

- [ ] **Step 1: 写失败测试**

在 `src/bin/rdpi.rs` 的 `#[cfg(test)] mod tests` 内（现有 `json_tests` 之外）加入：

```rust
#[test]
fn output_sink_counts_packets() {
    use rdpi::core::types::Protocol;

    let mut sink = OutputSink::new("csv", false);
    sink.on_packet(0, Some(DetectionResult::new(Protocol::Tcp)))
        .unwrap();
    sink.on_packet(0, None).unwrap();

    assert_eq!(sink.total(), 2);
    assert_eq!(sink.detected(), 1);
    assert_eq!(sink.protocol_counts().get("Tcp"), Some(&1));
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features pcap --bin rdpi output_sink_counts_packets`

Expected: 编译失败，报 `cannot find type OutputSink`。

- [ ] **Step 3: 抽取 OutputSink 与 run_file**

在 `src/bin/rdpi.rs` 的 `fn main` 之前加入：

```rust
use rdpi::Detector;
use std::path::Path;

/// 文件/实时两条路径共用的统计与输出。
struct OutputSink<'a> {
    output: &'a str,
    verbose: bool,
    total_packets: u64,
    detected_packets: u64,
    protocol_counts: HashMap<String, u64>,
    #[cfg(feature = "json")]
    packet_records: Vec<PacketRecord>,
}

impl<'a> OutputSink<'a> {
    fn new(output: &'a str, verbose: bool) -> Self {
        Self {
            output,
            verbose,
            total_packets: 0,
            detected_packets: 0,
            protocol_counts: HashMap::new(),
            #[cfg(feature = "json")]
            packet_records: Vec::new(),
        }
    }

    fn total(&self) -> u64 {
        self.total_packets
    }

    fn detected(&self) -> u64 {
        self.detected_packets
    }

    fn protocol_counts(&self) -> &HashMap<String, u64> {
        &self.protocol_counts
    }

    fn on_packet(
        &mut self,
        timestamp_us: u64,
        detection: Option<DetectionResult>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(feature = "json"))]
        let _ = timestamp_us;

        self.total_packets += 1;
        let packet_no = self.total_packets;

        match detection {
            Some(detection) => {
                self.detected_packets += 1;
                *self
                    .protocol_counts
                    .entry(format!("{:?}", detection.protocol))
                    .or_insert(0) += 1;

                if !self.verbose || self.output == "flows-jsonl" {
                    return Ok(());
                }

                #[cfg(feature = "json")]
                match self.output {
                    "jsonl" => {
                        println!(
                            "{}",
                            serde_json::to_string(&PacketRecord::new(
                                packet_no,
                                timestamp_us,
                                detection
                            ))?
                        );
                        return Ok(());
                    }
                    "json" => {
                        self.packet_records.push(PacketRecord::new(
                            packet_no,
                            timestamp_us,
                            detection,
                        ));
                        return Ok(());
                    }
                    _ => {}
                }

                print_detection(packet_no, &detection);
            }
            None => {
                if !self.verbose || self.output == "flows-jsonl" {
                    return Ok(());
                }

                #[cfg(feature = "json")]
                if self.output == "jsonl" {
                    println!(
                        "{}",
                        serde_json::to_string(&UnknownRecord {
                            r#type: "unknown",
                            packet_no,
                        })?
                    );
                    return Ok(());
                }

                println!("[{:6}] UNKNOWN", packet_no);
            }
        }

        Ok(())
    }

    fn finish(
        &self,
        elapsed: std::time::Duration,
        detector: Option<&Detector>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(feature = "json"))]
        let _ = detector;

        if self.output == "flows-jsonl" {
            #[cfg(feature = "json")]
            if let Some(detector) = detector {
                for flow in detector.normalized_flows() {
                    println!("{}", serde_json::to_string(&flow)?);
                }
            }
            return Ok(());
        }

        match self.output {
            "json" => {
                #[cfg(feature = "json")]
                {
                    let summary = Summary::build(
                        self.total_packets,
                        self.detected_packets,
                        &self.protocol_counts,
                        elapsed,
                    );
                    let doc = serde_json::json!({
                        "summary": summary,
                        "packets": &self.packet_records
                    });
                    println!("{}", serde_json::to_string_pretty(&doc)?);
                }
                #[cfg(not(feature = "json"))]
                print_json_summary(
                    self.total_packets,
                    self.detected_packets,
                    &self.protocol_counts,
                    elapsed,
                );
            }
            "jsonl" => {
                #[cfg(feature = "json")]
                {
                    let summary = Summary::build(
                        self.total_packets,
                        self.detected_packets,
                        &self.protocol_counts,
                        elapsed,
                    );
                    println!(
                        "{}",
                        serde_json::to_string(&JsonlLine {
                            r#type: "summary",
                            summary: &summary,
                        })?
                    );
                }
            }
            "csv" => print_csv_summary(&self.protocol_counts),
            _ => print_text_summary(
                self.total_packets,
                self.detected_packets,
                &self.protocol_counts,
                elapsed,
            ),
        }

        Ok(())
    }
}

fn run_file(
    path: &Path,
    output: &str,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let processor = PcapProcessor::new();
    let mut iter = processor.process_file(path)?;
    let mut sink = OutputSink::new(output, verbose);

    for item in iter.by_ref() {
        match item? {
            Some((timestamp_us, detection)) => {
                sink.on_packet(timestamp_us, Some(detection))?;
            }
            None => sink.on_packet(0, None)?,
        }
    }

    sink.finish(start.elapsed(), Some(iter.detector()))?;
    Ok(())
}
```

用下面的内容替换 `src/bin/rdpi.rs:46-162` 的 `fn main`：

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // json/jsonl/flows-jsonl 依赖 json feature（库类型 Serialize 派生）；
    // 未启用时 json 降级为仅 summary 的手写兼容输出，其余直接报错退出
    if (cli.output == "jsonl" || cli.output == "flows-jsonl") && !cfg!(feature = "json") {
        eprintln!(
            "error: output format '{}' requires building with --features json",
            cli.output
        );
        std::process::exit(2);
    }

    run_file(&cli.input, &cli.output, cli.verbose)
}
```

- [ ] **Step 4: 运行测试与回归验证**

Run:

```bash
cargo test --features pcap --bin rdpi
cargo test --features pcap
```

Expected: 全部通过；文件回放的 text/json/jsonl/csv/flows-jsonl 输出与改动前一致。

- [ ] **Step 5: 提交**

```bash
git add src/bin/rdpi.rs
git commit -m "Extract CLI output sink"
```

---

### Task 6: CLI 实时抓包集成

**Files:**
- Modify: `src/bin/rdpi.rs:29-44`（`Cli`）
- Modify: `src/bin/rdpi.rs`（`main` 及新增函数）
- Modify: `src/bin/rdpi.rs` 的 `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `rdpi::live::{CaptureConfig, LiveCapture, devices}`（Task 1-4）、`OutputSink`/`run_file`（Task 5）。
- Produces: `Source`、`resolve_source`、`validate_file_options`、`run_live`、`list_ifaces`；CLI 参数 `--iface`、`--list-ifaces`、`-f/--filter`、`--count`、`--duration`。

- [ ] **Step 1: 写失败测试**

在 `src/bin/rdpi.rs` 的 `#[cfg(test)] mod tests` 内加入：

```rust
#[test]
fn resolve_existing_file() {
    assert_eq!(
        resolve_source(Some("Cargo.toml"), None, false).unwrap(),
        Source::File(PathBuf::from("Cargo.toml"))
    );
}

#[test]
fn resolve_missing_path_as_live_device() {
    assert_eq!(
        resolve_source(Some("rdpi-no-such-iface"), None, false).unwrap(),
        Source::Live("rdpi-no-such-iface".to_string())
    );
}

#[test]
fn explicit_iface_wins_over_input() {
    assert_eq!(
        resolve_source(Some("Cargo.toml"), Some("eth0"), false).unwrap(),
        Source::Live("eth0".to_string())
    );
}

#[test]
fn list_ifaces_mode() {
    assert_eq!(
        resolve_source(None, None, true).unwrap(),
        Source::ListIfaces
    );
}

#[test]
fn file_mode_rejects_live_options() {
    assert!(validate_file_options(Some("tcp"), None, None).is_err());
    assert!(validate_file_options(None, Some(1), None).is_err());
    assert!(validate_file_options(None, None, Some(1)).is_err());
    assert!(validate_file_options(None, None, None).is_ok());
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features pcap --bin rdpi resolve_existing_file`

Expected: 编译失败，报 `cannot find type Source` / `cannot find function resolve_source`。

- [ ] **Step 3: 替换 Cli 参数结构**

用下面的内容替换 `src/bin/rdpi.rs:29-44` 的 `struct Cli` 及其文档注释：

```rust
/// rDpi — Rust Deep Packet Inspection CLI
#[derive(Parser)]
#[command(
    name = "rdpi",
    version = env!("CARGO_PKG_VERSION"),
    about = "Network traffic protocol identification tool"
)]
struct Cli {
    /// 输入的 pcap/pcapng 文件路径或网卡名（路径存在时按文件处理）
    #[arg(
        short = 'i',
        long = "input",
        value_name = "FILE|IFACE",
        required_unless_present_any = ["iface", "list_ifaces"],
        conflicts_with = "iface"
    )]
    input: Option<String>,

    /// 显式指定实时抓包网卡（与 -i 互斥）
    #[arg(long = "iface", value_name = "NAME", conflicts_with = "input")]
    iface: Option<String>,

    /// 列出可抓包设备后退出
    #[arg(long = "list-ifaces", conflicts_with_all = ["input", "iface"])]
    list_ifaces: bool,

    /// BPF 过滤表达式（仅实时抓包）
    #[arg(short = 'f', long = "filter", value_name = "BPF")]
    filter: Option<String>,

    /// 捕获指定帧数后停止（仅实时抓包）
    #[arg(long = "count", value_name = "N")]
    count: Option<u64>,

    /// 运行指定秒数后停止（仅实时抓包）
    #[arg(long = "duration", value_name = "SECS")]
    duration: Option<u64>,

    /// 输出格式（text / json / jsonl / csv / flows-jsonl）
    #[arg(short = 'o', long = "output", default_value = "text")]
    output: String,

    /// 显示每个包的检测结果（json 形态下加入 packets 数组 / jsonl 输出逐包行）
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}
```

- [ ] **Step 4: 实现来源解析、实时循环与设备列表**

在 `src/bin/rdpi.rs` 的 `OutputSink`/`run_file` 之后、`fn main` 之前加入：

```rust
/// CLI 输入来源。
#[derive(Debug, PartialEq, Eq)]
enum Source {
    File(PathBuf),
    Live(String),
    ListIfaces,
}

fn resolve_source(
    input: Option<&str>,
    iface: Option<&str>,
    list_ifaces: bool,
) -> Result<Source, String> {
    if list_ifaces {
        return Ok(Source::ListIfaces);
    }
    if let Some(iface) = iface {
        return Ok(Source::Live(iface.to_string()));
    }

    let input = input.ok_or_else(|| "missing -i/--input or --iface".to_string())?;
    let path = PathBuf::from(input);
    if path.is_file() {
        Ok(Source::File(path))
    } else {
        Ok(Source::Live(input.to_string()))
    }
}

fn validate_file_options(
    filter: Option<&str>,
    count: Option<u64>,
    duration: Option<u64>,
) -> Result<(), String> {
    if filter.is_some() {
        return Err("--filter requires a live capture interface".to_string());
    }
    if count.is_some() {
        return Err("--count requires a live capture interface".to_string());
    }
    if duration.is_some() {
        return Err("--duration requires a live capture interface".to_string());
    }
    Ok(())
}

#[cfg(feature = "live")]
fn run_live(
    device: String,
    filter: Option<String>,
    count: Option<u64>,
    duration: Option<u64>,
    output: &str,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use rdpi::live::{CaptureConfig, LiveCapture};

    let mut config = CaptureConfig::new(device);
    if let Some(filter) = filter {
        config = config.filter(filter);
    }

    let mut capture = LiveCapture::open(config)?;
    let mut detector = Detector::new();
    let mut sink = OutputSink::new(output, verbose);
    let start = Instant::now();
    let duration = duration.map(std::time::Duration::from_secs);

    loop {
        if let Some(limit) = count {
            if sink.total() >= limit {
                break;
            }
        }
        if let Some(limit) = duration {
            if start.elapsed() >= limit {
                break;
            }
        }

        let Some(frame) = capture.next_frame()? else {
            continue;
        };
        let detection = detector.process_packet(&frame.data, frame.timestamp_us / 1000)?;
        sink.on_packet(frame.timestamp_us, detection)?;
    }

    sink.finish(start.elapsed(), Some(&detector))?;
    Ok(())
}

#[cfg(not(feature = "live"))]
fn run_live(
    _device: String,
    _filter: Option<String>,
    _count: Option<u64>,
    _duration: Option<u64>,
    _output: &str,
    _verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("error: live capture requires building with --features \"pcap live\"");
    std::process::exit(2);
}

#[cfg(feature = "live")]
fn list_ifaces() -> Result<(), Box<dyn std::error::Error>> {
    let devices = rdpi::live::devices()?;
    if devices.is_empty() {
        println!("no capture devices found");
        return Ok(());
    }

    for device in devices {
        let mut flags = Vec::new();
        if device.is_loopback {
            flags.push("loopback");
        }
        if device.is_up {
            flags.push("up");
        }
        let flags = if flags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", flags.join(","))
        };

        match device.description.as_deref() {
            Some(description) if !description.is_empty() => {
                println!("{}{}  {}", device.name, flags, description);
            }
            _ => println!("{}{}", device.name, flags),
        }
    }

    Ok(())
}

#[cfg(not(feature = "live"))]
fn list_ifaces() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("error: live capture requires building with --features \"pcap live\"");
    std::process::exit(2);
}
```

用下面的内容替换 Task 5 的 `fn main`：

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // json/jsonl/flows-jsonl 依赖 json feature（库类型 Serialize 派生）；
    // 未启用时 json 降级为仅 summary 的手写兼容输出，其余直接报错退出
    if (cli.output == "jsonl" || cli.output == "flows-jsonl") && !cfg!(feature = "json") {
        eprintln!(
            "error: output format '{}' requires building with --features json",
            cli.output
        );
        std::process::exit(2);
    }

    let source = match resolve_source(
        cli.input.as_deref(),
        cli.iface.as_deref(),
        cli.list_ifaces,
    ) {
        Ok(source) => source,
        Err(message) => {
            eprintln!("error: {message}");
            std::process::exit(2);
        }
    };

    match source {
        Source::ListIfaces => list_ifaces(),
        Source::Live(device) => run_live(
            device,
            cli.filter,
            cli.count,
            cli.duration,
            &cli.output,
            cli.verbose,
        ),
        Source::File(path) => {
            if let Err(message) =
                validate_file_options(cli.filter.as_deref(), cli.count, cli.duration)
            {
                eprintln!("error: {message}");
                std::process::exit(2);
            }
            run_file(&path, &cli.output, cli.verbose)
        }
    }
}
```

- [ ] **Step 5: 运行测试确认通过**

Run:

```bash
cargo test --features pcap --bin rdpi
cargo test --features "pcap live" --bin rdpi
```

Expected: 全部通过（实时抓包用例在无后端环境走跳过分支）。

- [ ] **Step 6: 编译验证无 live feature**

Run: `cargo check --features pcap --bin rdpi`

Expected: 通过；使用 `--iface`/`--list-ifaces`/`-f` 时运行期给出 `--features "pcap live"` 提示。

- [ ] **Step 7: 提交**

```bash
git add src/bin/rdpi.rs
git commit -m "Add CLI live capture"
```

---

### Task 7: 示例、文档与最终验证

**Files:**
- Create: `examples/live_capture.rs`
- Modify: `Cargo.toml`（`[[example]]`）
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `docs/architecture/ndpi-pure-rust-plan.md`

**Interfaces:**
- Consumes: Task 1-6 的全部公共 API。
- Produces: 可运行示例与文档；无新增代码接口。

- [ ] **Step 1: 创建示例**

创建 `examples/live_capture.rs`：

```rust
//! 实时抓包示例。
//!
//! 用法：
//! `cargo run --features live --example live_capture -- <iface> [count]`

use rdpi::Detector;
use rdpi::live::{CaptureConfig, LiveCapture};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = std::env::args()
        .nth(1)
        .ok_or("usage: live_capture <iface> [count]")?;
    let count: usize = std::env::args()
        .nth(2)
        .and_then(|value| value.parse().ok())
        .unwrap_or(10);

    let capture = LiveCapture::open(CaptureConfig::new(device.clone()).timeout_ms(200))?;
    println!(
        "capturing on {device} (datalink={}, backend={:?})",
        capture.datalink(),
        capture.backend_version()
    );

    let mut detector = Detector::new();
    for frame in capture.take(count) {
        let frame = frame?;
        if let Some(result) = detector.process_packet(&frame.data, frame.timestamp_us / 1000)? {
            println!(
                "{} bytes -> {:?} [{:?}]",
                frame.original_len, result.protocol, result.confidence
            );
        }
    }

    Ok(())
}
```

在 `Cargo.toml` 的 `[[bin]]` 之后加入：

```toml
[[example]]
name = "live_capture"
required-features = ["live"]
```

- [ ] **Step 2: 更新 README**

在 Feature Gates 表的 `misc` 行之后加入：

```markdown
| `live` | ❌ | 实时抓包适配层（动态加载 Npcap/libpcap；配合 `pcap` 构建 CLI） |
```

在 Feature Gates 章节之后、`## 支持的协议` 之前加入：

````markdown
## 实时抓包

实时抓包需要同时启用 `pcap` 与 `live`：

```bash
cargo run --features "pcap live" --bin rdpi -- --list-ifaces
cargo run --features "pcap live" --bin rdpi -- -i <iface> -f "tcp port 443" --duration 10
```

依赖与权限：

- Windows：安装 [Npcap](https://npcap.com/) 运行时；若安装时限制管理员访问驱动，请在管理员终端运行。
- Linux：安装 libpcap 运行时，抓包需要 root 或 `CAP_NET_RAW`。
- macOS：使用系统自带 libpcap。
- 仅支持以太网链路层（DLT_EN10MB）；Linux `any` 接口返回 SLL，不在支持范围，请改用具体网卡。
````

- [ ] **Step 3: 更新 AGENTS.md**

在 `AGENTS.md` 的 F46 条目之后加入：

```markdown
- **Live capture（F47，2026-11-08）**：新 `live` feature + `rdpi::live`——运行时动态加载 `wpcap.dll`/`libpcap`（`libloading`，无 Npcap SDK 编译依赖）；`devices()`/`CaptureConfig`/`LiveCapture`（`next_frame` 超时语义 + `Iterator` 跳过超时）/`CapturedFrame`/`LiveError`；仅接受 DLT_EN10MB；CLI `-i` 自动区分 pcap 文件与网卡、`--iface`、`--list-ifaces`、`-f`、`--count`、`--duration`；实时帧复用 `Detector::process_packet` 与现有输出；`unsafe` 仅限 `src/live/ffi.rs`。
```

在「常用命令」的 `cargo build --features pcap` 行之后加入：

```bash
cargo test --features live          # 实时抓包类型/加载器测试（无后端时走 BackendUnavailable）
cargo build --features "pcap live"  # 构建实时抓包 CLI
```

- [ ] **Step 4: 回写路线图**

在 `docs/architecture/ndpi-pure-rust-plan.md` 的 §9「已完成」列表末尾加入：

```markdown
- **P4 首个切片：Live capture（F47）**
  - `live` feature + `rdpi::live`：动态加载 Npcap/libpcap（`libloading`，无编译期 C 依赖）；
  - `devices()` / `CaptureConfig` / `LiveCapture` / `CapturedFrame` / `LiveError`；仅 DLT_EN10MB；
  - CLI `-i` 自动区分 pcap 文件与网卡、`--iface`、`--list-ifaces`、`-f`、`--count`、`--duration`；
  - 实时帧经 `Detector::process_packet` 复用现有输出与 flows-jsonl；
  - `unsafe` 仅限 `src/live/ffi.rs`。
```

- [ ] **Step 5: 最终验证**

Run:

```bash
cargo fmt --check
cargo test
cargo test --all-features
cargo clippy --all-features --all-targets -- -D warnings
cargo build --features "pcap live"
cargo check --features live
```

Expected: 全部通过；`cargo test --all-features` 在无 libpcap 环境下也通过（后端缺失用例走 `BackendUnavailable` 分支）。

- [ ] **Step 6: 手工验收（Windows 本机）**

Run:

```bash
cargo run --features "pcap live" --bin rdpi -- --list-ifaces
cargo run --features "pcap live" --bin rdpi -- -i '<网卡名>' --count 200 -o jsonl -v
cargo run --features "pcap live" --bin rdpi -- -i '<网卡名>' -f "tcp port 443" --duration 10
cargo run --features "pcap live" --example live_capture -- '<网卡名>' 20
```

Expected: `--list-ifaces` 列出设备；实时路径输出逐包记录并在 200 帧/10 秒后打印汇总；BPF 只保留 443 流量；示例程序打印前 20 帧协议。

- [ ] **Step 7: 提交**

```bash
git add Cargo.toml examples/live_capture.rs README.md AGENTS.md docs/architecture/ndpi-pure-rust-plan.md
git commit -m "Document live capture"
```

---

## 计划自检

### 规格覆盖

| 设计章节 | 对应任务 |
|---|---|
| §2 Feature 与模块 | Task 1（feature/模块）、Task 2（ffi 拆分） |
| §3 公共 API | Task 1（类型/错误）、Task 3（`devices`）、Task 4（`LiveCapture`） |
| §4 FFI 后端（动态库/符号/布局/RAII/链路层） | Task 2（加载器/布局）、Task 3（设备链表 RAII）、Task 4（句柄/BPF/读取） |
| §5 CLI 行为（参数/解析/循环/输出复用） | Task 5（输出复用）、Task 6（参数与实时循环） |
| §6 测试策略 | 各任务 TDD 步骤 + Task 7 最终验证 |
| §7 文档与安全 | Task 7（README/AGENTS/路线图）；安全约束见 Global Constraints |
| §8 验收标准 | Task 7 Step 5/6 |
| §9 风险（timeval/权限/SLL/无 Ctrl-C） | Task 2（timeval 测试）、Task 4（链路层/错误）、Global Constraints |

### 占位符检查

- 无 TBD/TODO/「稍后实现」；每个代码步骤都给出完整代码。
- 所有命令均带预期结果。

### 类型一致性

- `CaptureConfig` 字段与 builder 在 Task 1 定义，Task 4/Task 6 使用一致。
- `LiveError` 变体在 Task 1 定义，Task 2/3/4 使用一致。
- `PollResult`（ffi）与 `PollOutcome`（mod）职责分离，名称不混用。
- `OutputSink::on_packet(timestamp_us, Option<DetectionResult>)` 在 Task 5 定义，Task 6 调用一致。
- `run_file(&Path, &str, bool)` 在 Task 5 定义，Task 6 调用一致。
