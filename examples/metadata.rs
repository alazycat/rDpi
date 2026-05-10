//! Metadata extraction example for rDpi
//!
//! Demonstrates extracting protocol-specific metadata:
//! - TLS SNI and Application identification
//! - HTTP Host, Method, Path
//! - DNS query domain
//! - SSH version and software
//! - NTP version, mode, stratum

use rdpi::{Detector, Metadata, Result};

fn main() -> Result<()> {
    let mut detector = Detector::new();

    println!("=== rDpi Metadata Extraction Examples ===\n");

    // TLS with SNI
    println!("--- TLS ClientHello with SNI ---");
    let tls_packet = build_tls_client_hello();
    if let Some(result) = detector.detect(&tls_packet)? {
        println!("Protocol: {:?}", result.protocol);
        if let Metadata::Tls(tls) = &result.metadata {
            if let Some(sni) = &tls.sni {
                println!("SNI: {}", sni);
            }
            if let Some(ver) = &tls.version {
                println!("TLS Version: {}", ver);
            }
            if let Some(app) = tls.application {
                println!("Application: {:?}", app);
            }
        }
    }

    println!("\n--- HTTP Request ---");
    let http_packet = build_http_request();
    if let Some(result) = detector.detect(&http_packet)? {
        println!("Protocol: {:?}", result.protocol);
        if let Metadata::Http(http) = &result.metadata {
            if let Some(method) = &http.method {
                println!("Method: {}", method);
            }
            if let Some(path) = &http.path {
                println!("Path: {}", path);
            }
            if let Some(host) = &http.host {
                println!("Host: {}", host);
            }
        }
    }

    println!("\n--- DNS Query ---");
    let dns_packet = build_dns_packet();
    if let Some(result) = detector.detect(&dns_packet)? {
        println!("Protocol: {:?}", result.protocol);
        if let Metadata::Dns(dns) = &result.metadata {
            if let Some(domain) = &dns.query_domain {
                println!("Query Domain: {}", domain);
            }
        }
    }

    println!("\n--- SSH Banner ---");
    let ssh_packet = build_ssh_banner();
    if let Some(result) = detector.detect(&ssh_packet)? {
        println!("Protocol: {:?}", result.protocol);
        if let Metadata::Ssh(ssh) = &result.metadata {
            if let Some(ver) = &ssh.version {
                println!("Protocol Version: {}", ver);
            }
            if let Some(soft) = &ssh.software {
                println!("Software: {}", soft);
            }
        }
    }

    println!("\n--- NTP Packet ---");
    let ntp_packet = build_ntp_packet();
    if let Some(result) = detector.detect(&ntp_packet)? {
        println!("Protocol: {:?}", result.protocol);
        if let Metadata::Ntp(ntp) = &result.metadata {
            println!("Version: {}", ntp.version);
            println!("Mode: {} ({})", ntp.mode, ntp_mode_name(ntp.mode));
            println!("Stratum: {}", ntp.stratum);
        }
    }

    println!("\n--- Flow Summary ---");
    println!("Total flows: {}", detector.flow_count());
    for (key, flow) in detector.flows() {
        if let Some(proto) = flow.protocol {
            println!(
                "  {}:{} -> {}:{:?}: {:?} ({} pkts, {} bytes)",
                key.src_ip, key.src_port, key.dst_ip, key.dst_port,
                proto,
                flow.stats.packets,
                flow.stats.bytes
            );
        }
    }

    Ok(())
}

fn ntp_mode_name(mode: u8) -> &'static str {
    match mode {
        1 => "symmetric active",
        2 => "symmetric passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "NTP control",
        7 => "reserved",
        _ => "unknown",
    }
}

// Packet builders (simplified for demonstration)

fn build_tls_client_hello() -> Vec<u8> {
    // Simplified TLS ClientHello for youtube.com
    let eth = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
    ];
    let ip = vec![
        0x45, 0x00, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02,
    ];
    let tcp = vec![
        0x12, 0x34, 0x01, 0xbb,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    // TLS record with SNI for youtube.com
    let tls = vec![
        0x16, // Handshake
        0x03, 0x01, // TLS 1.0 (legacy, actual version in extensions)
        0x00, 0x50, // Length
        0x01, // ClientHello
        0x00, 0x00, 0x4c, // Length
        0x03, 0x03, // Version
        // Random (32 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x00, // Session ID length
        0x00, 0x02, 0xc0, 0x2f, // Cipher suites
        0x01, 0x00, // Compression methods
        0x00, 0x1a, // Extensions length
        0x00, 0x18, 0x00, 0x16, // SNI extension
        0x00, 0x14, 0x00, 0x00, 0x11,
        // SNI: youtube.com
        b'y', b'o', b'u', b't', b'u', b'b', b'e', b'.',
        b'c', b'o', b'm',
    ];
    [eth, ip, tcp, tls].concat()
}

fn build_http_request() -> Vec<u8> {
    let eth = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
    ];
    let ip = vec![
        0x45, 0x00, 0x00, 0x80,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02,
    ];
    let tcp = vec![
        0x12, 0x34, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    let http = b"GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\nUser-Agent: rDpi-test\r\n\r\n".to_vec();
    [eth, ip, tcp, http].concat()
}

fn build_dns_packet() -> Vec<u8> {
    // Reuse the DNS packet from basic.rs
    let eth = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
    ];
    let ip = vec![
        0x45, 0x00, 0x00, 0x2c,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02,
    ];
    let udp = vec![
        0x00, 0x35, 0x00, 0x35,
        0x00, 0x18, 0x00, 0x00,
    ];
    let dns = vec![
        0x12, 0x34, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    [eth, ip, udp, dns].concat()
}

fn build_ssh_banner() -> Vec<u8> {
    let eth = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
    ];
    let ip = vec![
        0x45, 0x00, 0x00, 0x50,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02,
    ];
    let tcp = vec![
        0x12, 0x34, 0x00, 0x16,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    let ssh = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n".to_vec();
    [eth, ip, tcp, ssh].concat()
}

fn build_ntp_packet() -> Vec<u8> {
    let eth = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
    ];
    let ip = vec![
        0x45, 0x00, 0x00, 0x4c,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02,
    ];
    let udp = vec![
        0x12, 0x34, 0x00, 0x7b,
        0x00, 0x38, 0x00, 0x00,
    ];
    // NTP packet: version 4, mode 3 (client), stratum 1
    let mut ntp = vec![0u8; 48];
    ntp[0] = (4 << 3) | 3; // LI=0, VN=4, Mode=3
    ntp[1] = 1; // Stratum 1
    [eth, ip, udp, ntp].concat()
}
