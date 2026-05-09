use rdpi::core::types::*;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_protocol_tcp() {
    let p = Protocol::Tcp;
    assert!(matches!(p, Protocol::Tcp));
}

#[test]
fn test_protocol_dns() {
    let p = Protocol::Dns;
    assert!(matches!(p, Protocol::Dns));
}

#[test]
fn test_protocol_other() {
    let p = Protocol::Other(999);
    assert!(matches!(p, Protocol::Other(999)));
}

#[test]
fn test_flow_key() {
    let key = FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 12345,
        dst_port: 53,
        transport: TransportProto::Udp,
    };
    assert_eq!(key.src_port, 12345);
    assert_eq!(key.transport, TransportProto::Udp);
}

// ============================================================================
// DetectContext Tests
// ============================================================================

#[test]
fn test_detect_context_creation() {
    use rdpi::core::types::DetectContext;

    let ctx = DetectContext {
        src_port: 12345,
        dst_port: 443,
        is_http3_port: true,
    };

    assert_eq!(ctx.src_port, 12345);
    assert_eq!(ctx.dst_port, 443);
    assert!(ctx.is_http3_port);
}

#[test]
fn test_detect_context_non_http3_port() {
    use rdpi::core::types::DetectContext;

    let ctx = DetectContext {
        src_port: 8080,
        dst_port: 8443,
        is_http3_port: false,
    };

    assert!(!ctx.is_http3_port);
}

// ============================================================================
// Application Tests
// ============================================================================

#[test]
fn test_application_variants() {
    use rdpi::core::types::Application;

    // 流媒体
    let _ = Application::YouTube;
    let _ = Application::Netflix;
    let _ = Application::Bilibili;
    let _ = Application::Douyin;
    let _ = Application::Iqiyi;
    let _ = Application::TencentVideo;
    let _ = Application::Youku;
    let _ = Application::Hulu;
    let _ = Application::DisneyPlus;
    let _ = Application::AmazonPrime;
    // IM
    let _ = Application::WeChat;
    let _ = Application::Telegram;
    let _ = Application::WhatsApp;
    let _ = Application::Discord;
    let _ = Application::QQ;
    let _ = Application::Slack;
    let _ = Application::Line;
    let _ = Application::Signal;
}

#[test]
fn test_application_category() {
    use rdpi::core::types::{Application, ApplicationCategory};

    assert_eq!(Application::YouTube.category(), ApplicationCategory::Streaming);
    assert_eq!(Application::Netflix.category(), ApplicationCategory::Streaming);
    assert_eq!(Application::WeChat.category(), ApplicationCategory::Im);
    assert_eq!(Application::Telegram.category(), ApplicationCategory::Im);
}

#[test]
fn test_application_name() {
    use rdpi::core::types::Application;

    assert_eq!(Application::YouTube.name(), "YouTube");
    assert_eq!(Application::Netflix.name(), "Netflix");
    assert_eq!(Application::WeChat.name(), "WeChat");
}

// ============================================================================
// TlsMetadata / QuicMetadata Application Field Tests
// ============================================================================

#[test]
fn test_tls_metadata_with_application() {
    use rdpi::core::types::{Application, TlsMetadata};

    let metadata = TlsMetadata {
        sni: Some("www.youtube.com".to_string()),
        version: Some("TLSv1.3".to_string()),
        application: Some(Application::YouTube),
    };

    assert_eq!(metadata.sni, Some("www.youtube.com".to_string()));
    assert_eq!(metadata.application, Some(Application::YouTube));
}

#[test]
fn test_quic_metadata_with_application() {
    use rdpi::core::types::QuicMetadata;

    let metadata = QuicMetadata {
        sni: None,
        version: Some("00000001".to_string()),
        destination_connection_id: Some(vec![0x01, 0x02]),
        application: None, // 预留，目前为 None
    };

    assert!(metadata.application.is_none());
}
