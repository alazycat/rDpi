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

    assert_eq!(
        Application::YouTube.category(),
        ApplicationCategory::Streaming
    );
    assert_eq!(
        Application::Netflix.category(),
        ApplicationCategory::Streaming
    );
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
        ja4: None,
        cipher_suites: vec![],
        alpn: None,
    };
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

// ============================================================================
// Confidence Tests (Phase 1)
// ============================================================================

#[test]
fn test_confidence_ordering() {
    assert!(Confidence::Dpi > Confidence::DpiPartial);
    assert!(Confidence::DpiPartial > Confidence::MatchByIp);
    assert!(Confidence::MatchByIp > Confidence::MatchByPort);
    assert!(Confidence::MatchByPort > Confidence::Unknown);
    assert!(Confidence::CustomRule > Confidence::Dpi);
}

#[test]
fn test_confidence_default() {
    let result = DetectionResult::new(Protocol::Dns);
    assert_eq!(result.confidence, Confidence::Dpi);
}

#[test]
fn test_confidence_as_u8() {
    assert_eq!(Confidence::Unknown as u8, 0);
    assert_eq!(Confidence::MatchByPort as u8, 1);
    assert_eq!(Confidence::MatchByIp as u8, 2);
    assert_eq!(Confidence::DpiCache as u8, 3);
    assert_eq!(Confidence::DpiPartial as u8, 4);
    assert_eq!(Confidence::Dpi as u8, 5);
    assert_eq!(Confidence::CustomRule as u8, 6);
}

#[test]
fn test_confidence_equality() {
    assert_eq!(Confidence::Dpi, Confidence::Dpi);
    assert_ne!(Confidence::Dpi, Confidence::DpiPartial);
}

#[test]
fn test_confidence_display() {
    assert_eq!(format!("{}", Confidence::Dpi), "Dpi");
    assert_eq!(format!("{}", Confidence::MatchByPort), "MatchByPort");
    assert_eq!(format!("{}", Confidence::Unknown), "Unknown");
}

// ============================================================================
// Protocol Classification Tests (Phase 2)
// ============================================================================

#[test]
fn test_protocol_category() {
    assert_eq!(Protocol::Http.category(), ProtocolCategory::Web);
    assert_eq!(Protocol::Tls.category(), ProtocolCategory::EncryptedTunnel);
    assert_eq!(Protocol::Dns.category(), ProtocolCategory::Dns);
    assert_eq!(Protocol::Smtp.category(), ProtocolCategory::Mail);
    assert_eq!(Protocol::Mysql.category(), ProtocolCategory::Database);
    assert_eq!(Protocol::Ssh.category(), ProtocolCategory::RemoteAccess);
    assert_eq!(Protocol::Ntp.category(), ProtocolCategory::Infrastructure);
    assert_eq!(Protocol::Snmp.category(), ProtocolCategory::NetworkManagement);
    assert_eq!(Protocol::Modbus.category(), ProtocolCategory::Industrial);
    #[cfg(feature = "proto3")]
    assert_eq!(Protocol::Ftp.category(), ProtocolCategory::FileTransfer);
    assert_eq!(Protocol::Tcp.category(), ProtocolCategory::Network);
    assert_eq!(Protocol::Other(999).category(), ProtocolCategory::Other);
}

#[test]
fn test_protocol_breed() {
    assert_eq!(Protocol::Http.breed(), ProtocolBreed::Safe);
    assert_eq!(Protocol::Mysql.breed(), ProtocolBreed::Acceptable);
    #[cfg(feature = "proto3")]
    assert_eq!(Protocol::Ftp.breed(), ProtocolBreed::Fun);
    assert_eq!(Protocol::Tcp.breed(), ProtocolBreed::Unrated);
}

#[test]
fn test_protocol_master() {
    assert_eq!(Protocol::Http.master(), Protocol::Http);
    assert_eq!(Protocol::Tls.master(), Protocol::Tls);
}

#[test]
fn test_application_master_protocol() {
    assert_eq!(Application::YouTube.master_protocol(), Protocol::Http);
    assert_eq!(Application::Netflix.master_protocol(), Protocol::Http);
    assert_eq!(Application::WeChat.master_protocol(), Protocol::Tls);
    assert_eq!(Application::Telegram.master_protocol(), Protocol::Tls);
    assert_eq!(Application::Google.master_protocol(), Protocol::Tls);
}

#[test]
fn test_new_application_variants() {
    // 流媒体新变体
    assert_eq!(Application::HBO.category(), ApplicationCategory::Streaming);
    assert_eq!(Application::DAZN.category(), ApplicationCategory::Streaming);
    assert_eq!(Application::Spotify.category(), ApplicationCategory::Streaming);
    // 社交
    assert_eq!(Application::Facebook.category(), ApplicationCategory::Im);
    assert_eq!(Application::Twitter.category(), ApplicationCategory::Im);
    assert_eq!(Application::Instagram.category(), ApplicationCategory::Im);
    // 云服务
    assert_eq!(Application::GitHub.category(), ApplicationCategory::Other);
    // 通讯
    assert_eq!(Application::Teams.category(), ApplicationCategory::Im);
}

#[test]
fn test_new_application_names() {
    assert_eq!(Application::HBO.name(), "HBO");
    assert_eq!(Application::Spotify.name(), "Spotify");
    assert_eq!(Application::Facebook.name(), "Facebook");
    assert_eq!(Application::GitHub.name(), "GitHub");
    assert_eq!(Application::Teams.name(), "Teams");
}

#[test]
fn test_detection_result_default_fields() {
    let result = DetectionResult::new(Protocol::Dns);
    assert_eq!(result.category, ProtocolCategory::Dns);
    assert_eq!(result.breed, ProtocolBreed::Safe);
    assert!(result.app_protocol.is_none());
}

#[test]
fn test_detection_result_app_protocol_from_tls() {
    let metadata = Metadata::Tls(TlsMetadata {
        sni: Some("www.youtube.com".to_string()),
        version: Some("1.3".to_string()),
        application: Some(Application::YouTube),
        ja4: None,
        cipher_suites: vec![],
        alpn: None,
    });
    let result = DetectionResult::new(Protocol::Tls)
        .with_metadata(metadata);
    assert_eq!(result.app_protocol, Some(Application::YouTube));
}

#[test]
fn test_protocol_category_exhaustive() {
    let protocols = vec![
        Protocol::Tcp, Protocol::Udp, Protocol::Icmp,
        Protocol::Dns, Protocol::Http, Protocol::Tls,
        Protocol::Ssh, Protocol::Smtp, Protocol::Quic,
        Protocol::Http3, Protocol::Pop3, Protocol::Pop3s,
        Protocol::Imap, Protocol::Imaps, Protocol::Ntp,
        Protocol::Dhcp, Protocol::Snmp, Protocol::Modbus,
        Protocol::Mysql, Protocol::Postgresql, Protocol::Redis,
        #[cfg(feature = "proto3")]
        Protocol::Ftp,
    ];

    for p in protocols {
        let cat = p.category();
        assert_ne!(cat, ProtocolCategory::Other, "Known protocol {:?} should not map to Other", p);
    }
}
