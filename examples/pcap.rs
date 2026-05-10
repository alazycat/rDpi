//! PCAP file processing example for rDpi
//!
//! Demonstrates batch processing of pcap files with flow statistics.
//!
//! Usage: cargo run --example pcap --features pcap -- <pcap-file>

#[cfg(feature = "pcap")]
use rdpi::Result;
#[cfg(feature = "pcap")]
use rdpi::pcap::PcapProcessor;
#[cfg(feature = "pcap")]
use std::env;

#[cfg(feature = "pcap")]
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <pcap-file>", args[0]);
        eprintln!("  Reads a pcap or pcapng file and displays detected protocols.");
        std::process::exit(1);
    }

    let pcap_file = &args[1];
    println!("Processing: {}", pcap_file);
    println!("{}", "-".repeat(60));

    // Create processor and process file
    let detector = rdpi::Detector::new();
    let processor = PcapProcessor::with_detector(detector);
    let iter = processor.process_file(pcap_file)?;

    let mut packet_count = 0;
    let mut detected_count = 0;

    for result in iter {
        match result {
            Ok(Some((ts, detection))) => {
                packet_count += 1;
                detected_count += 1;
                println!(
                    "[{}] {:?} (confidence: {:.2})",
                    format_timestamp(ts),
                    detection.protocol,
                    detection.confidence
                );

                // Print metadata if available
                if let Some(meta) = extract_metadata_summary(&detection) {
                    println!("    Metadata: {}", meta);
                }
            }
            Ok(None) => {
                packet_count += 1;
                // Unknown protocol, skip
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
    }

    println!("{}", "-".repeat(60));
    println!(
        "Processed {} packets, {} detected",
        packet_count, detected_count
    );

    Ok(())
}

#[cfg(feature = "pcap")]
fn format_timestamp(ts: u64) -> String {
    // Convert microseconds to human-readable format
    let secs = ts / 1_000_000;
    let usecs = ts % 1_000_000;
    format!("{:>6}.{:06}", secs, usecs)
}

#[cfg(feature = "pcap")]
fn extract_metadata_summary(result: &rdpi::DetectionResult) -> Option<String> {
    use rdpi::Metadata;
    match &result.metadata {
        Metadata::Dns(dns) => dns.query_domain.as_ref().map(|d| format!("DNS query: {}", d)),
        Metadata::Tls(tls) => {
            let mut parts = vec![];
            if let Some(sni) = &tls.sni {
                parts.push(format!("SNI: {}", sni));
            }
            if let Some(ver) = &tls.version {
                parts.push(format!("Version: {}", ver));
            }
            if let Some(app) = tls.application {
                parts.push(format!("Application: {:?}", app));
            }
            if parts.is_empty() { None } else { Some(parts.join(", ")) }
        }
        Metadata::Http(http) => {
            let mut parts = vec![];
            if let Some(method) = &http.method {
                parts.push(format!("Method: {}", method));
            }
            if let Some(path) = &http.path {
                parts.push(format!("Path: {}", path));
            }
            if let Some(host) = &http.host {
                parts.push(format!("Host: {}", host));
            }
            if parts.is_empty() { None } else { Some(parts.join(", ")) }
        }
        Metadata::Ssh(ssh) => {
            let mut parts = vec![];
            if let Some(ver) = &ssh.version {
                parts.push(format!("Version: {}", ver));
            }
            if let Some(soft) = &ssh.software {
                parts.push(format!("Software: {}", soft));
            }
            if parts.is_empty() { None } else { Some(parts.join(", ")) }
        }
        Metadata::Smtp(smtp) => {
            smtp.hostname.as_ref().map(|h| {
                format!("Hostname: {} ({})", h, if smtp.is_client { "client" } else { "server" })
            })
        }
        Metadata::Ntp(ntp) => {
            Some(format!(
                "Version: {}, Mode: {}, Stratum: {}",
                ntp.version, ntp.mode, ntp.stratum
            ))
        }
        Metadata::Dhcp(dhcp) => {
            Some(format!(
                "Opcode: {}, Client MAC: {:02x?}",
                dhcp.opcode, dhcp.client_mac
            ))
        }
        _ => None,
    }
}

#[cfg(not(feature = "pcap"))]
fn main() {
    eprintln!("This example requires the 'pcap' feature.");
    eprintln!("Run with: cargo run --example pcap --features pcap -- <pcap-file>");
    std::process::exit(1);
}
