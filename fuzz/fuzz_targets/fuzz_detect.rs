#![no_main]

use libfuzzer_sys::fuzz_target;
use rdpi::Detector;

/// 模糊测试：随机字节 → Detector::detect()
/// 运行: cargo +nightly fuzz run fuzz_detect
fuzz_target!(|data: &[u8]| {
    let mut detector = Detector::new();
    let _ = detector.detect(data);
});
