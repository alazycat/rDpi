//! 实时抓包示例。
//!
//! 用法：
//! `cargo run --features live --example live_capture -- <iface> [count]`

use rdpi::Detector;
use rdpi::live::{CaptureConfig, LinkType, LiveCapture};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = std::env::args()
        .nth(1)
        .ok_or("usage: live_capture <iface> [count]")?;
    let count: usize = std::env::args()
        .nth(2)
        .and_then(|value| value.parse().ok())
        .unwrap_or(10);

    let capture = LiveCapture::open(CaptureConfig::new(device.clone()).timeout_ms(200))?;
    let link_type = capture.link_type();
    println!(
        "capturing on {device} (link={link_type:?}, datalink={}, backend={:?})",
        capture.datalink(),
        capture.backend_version()
    );

    let mut detector = Detector::new();
    for frame in capture.take(count) {
        let frame = frame?;
        let Some(l3) = link_type.l3_payload(&frame.data) else {
            // 实时链路会混有 ARP/LLDP 等非 IP 帧；跳过。
            continue;
        };
        let detection = match link_type {
            LinkType::Ethernet => detector.process_packet(&frame.data, frame.timestamp_us / 1000),
            _ => detector.process_ip_packet(l3, frame.timestamp_us / 1000),
        };
        let Ok(Some(result)) = detection else {
            continue;
        };
        println!(
            "{} bytes -> {:?} [{:?}]",
            frame.original_len, result.protocol, result.confidence
        );
    }

    Ok(())
}
