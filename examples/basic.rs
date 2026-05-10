 //! Basic usage example for rDpi
//!
//! Demonstrates single packet detection with automatic flow tracking.

use rdpi::{Detector, Protocol, Result};

fn main() -> Result<()> {
    // Create a detector with default configuration
    let mut detector = Detector::new();

    // Simulate a DNS query packet (simplified)
    // In real usage, you would read from a pcap file or network interface
    let dns_packet = build_dns_packet();

    // Detect protocol
    match detector.detect(&dns_packet)? {
        Some(result) => {
            println!("Detected protocol: {:?}", result.protocol);
            println!("Confidence: {}", result.confidence);
        }
        None => {
            println!("Unknown protocol");
        }
    }

    // Check flow statistics
    println!("\nFlow statistics:");
    for (key, flow) in detector.flows() {
        println!(
            "  {}:{} -> {}:{} ({:?}): {} packets, {} bytes",
            key.src_ip,
            key.src_port,
            key.dst_ip,
            key.dst_port,
            flow.protocol.unwrap_or(Protocol::Other(0)),
            flow.stats.packets,
            flow.stats.bytes
        );
    }

    // Clean up expired flows (optional)
    let expired = detector.expire_flows();
    if !expired.is_empty() {
        println!("\nExpired {} flows", expired.len());
    }

    Ok(())
}

/// Build a minimal DNS query packet for demonstration
fn build_dns_packet() -> Vec<u8> {
    // Ethernet header (14 bytes)
    let eth = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
        0x08, 0x00, // EtherType: IPv4
    ];

    // IP header (20 bytes) - UDP protocol
    let ip = vec![
        0x45, // Version 4, IHL 5
        0x00, // DSCP
        0x00, 0x2c, // Total length (44 bytes)
        0x00, 0x01, // Identification
        0x00, 0x00, // Flags, Fragment offset
        0x40, // TTL
        0x11, // Protocol: UDP
        0x00, 0x00, // Header checksum (ignored for detection)
        0xc0, 0xa8, 0x01, 0x01, // Src IP: 192.168.1.1
        0xc0, 0xa8, 0x01, 0x02, // Dst IP: 192.168.1.2
    ];

    // UDP header (8 bytes)
    let udp = vec![
        0x00, 0x35, // Src port: 53 (DNS)
        0x00, 0x35, // Dst port: 53
        0x00, 0x18, // Length (24 bytes)
        0x00, 0x00, // Checksum (ignored)
    ];

    // DNS query for "example.com"
    let dns = vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Query: example.com
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // End of name
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
    ];

    [eth, ip, udp, dns].concat()
}
