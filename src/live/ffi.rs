//! pcap 动态加载与 FFI 声明。
//!
//! 所有 `unsafe` 集中在本文件。

use std::ffi::{CString, c_char, c_int, c_uchar, c_void};
use std::sync::OnceLock;

use super::{Device, LiveError};

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

unsafe fn optional<T: Copy + 'static>(library: &libloading::Library, name: &str) -> Option<T> {
    let name = CString::new(name).ok()?;
    // SAFETY: 调用方保证 T 与 C 声明一致。
    unsafe { library.get::<T>(name.as_bytes_with_nul()) }
        .ok()
        .map(|symbol| *symbol)
}

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
    // SAFETY: 调用方保证 ptr 指向以 NUL 结尾的有效 C 字符串。
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
