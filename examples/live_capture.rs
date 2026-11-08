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
        // 实时链路会混有 ARP/LLDP 等非 IP 帧；解析失败时跳过。
        let Ok(detection) = detector.process_packet(&frame.data, frame.timestamp_us / 1000) else {
            continue;
        };
        if let Some(result) = detection {
            println!(
                "{} bytes -> {:?} [{:?}]",
                frame.original_len, result.protocol, result.confidence
            );
        }
    }

    Ok(())
}
