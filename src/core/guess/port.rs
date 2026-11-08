//! 端口回退检测
//!
//! 当 DPI 无法识别协议时，通过端口号做合理猜测。

use crate::core::types::{Confidence, DetectionResult, Protocol};

/// 常见端口→协议映射（用于 DPI 失败后的回退猜测）
pub(crate) static PORT_MAP: &[(u16, &[Protocol])] = &[
    #[cfg(feature = "proto3")]
    (20u16, &[Protocol::Ftp]),
    #[cfg(feature = "proto3")]
    (21u16, &[Protocol::Ftp]),
    (22u16, &[Protocol::Ssh]),
    (25u16, &[Protocol::Smtp]),
    (53u16, &[Protocol::Dns]),
    (80u16, &[Protocol::Http]),
    (110u16, &[Protocol::Pop3]),
    (123u16, &[Protocol::Ntp]),
    (143u16, &[Protocol::Imap]),
    (161u16, &[Protocol::Snmp]),
    (
        443u16,
        &[
            Protocol::Tls,
            Protocol::Quic,
            Protocol::Http3,
            Protocol::Dtls,
        ],
    ),
    (465u16, &[Protocol::Smtp]),
    (502u16, &[Protocol::Modbus]),
    (587u16, &[Protocol::Smtp]),
    (993u16, &[Protocol::Imaps]),
    (995u16, &[Protocol::Pop3s]),
    (3306u16, &[Protocol::Mysql]),
    (5432u16, &[Protocol::Postgresql]),
    (6379u16, &[Protocol::Redis]),
    #[cfg(feature = "proto3")]
    (5060u16, &[Protocol::Sip]),
    #[cfg(feature = "proto3")]
    (5061u16, &[Protocol::Sip]),
    #[cfg(feature = "database")]
    (1433u16, &[Protocol::Mssql]),
    #[cfg(feature = "database")]
    (1434u16, &[Protocol::Mssql]),
    #[cfg(feature = "database")]
    (1521u16, &[Protocol::Oracle]),
    #[cfg(feature = "database")]
    (7000u16, &[Protocol::Cassandra]),
    #[cfg(feature = "database")]
    (9042u16, &[Protocol::Cassandra]),
    #[cfg(feature = "messaging")]
    (9092u16, &[Protocol::Kafka]),
];

/// 通过端口匹配协议
pub fn match_port(port: u16) -> Option<DetectionResult> {
    PORT_MAP
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, protocols)| {
            DetectionResult::new(protocols[0]).with_confidence(Confidence::MatchByPort)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_ports() {
        assert_eq!(match_port(80).unwrap().protocol, Protocol::Http);
        assert_eq!(match_port(22).unwrap().protocol, Protocol::Ssh);
        assert_eq!(match_port(53).unwrap().protocol, Protocol::Dns);
    }

    #[test]
    fn test_unknown_port() {
        assert!(match_port(9999).is_none());
    }

    #[test]
    fn test_port_confidence() {
        let result = match_port(443).unwrap();
        assert_eq!(result.confidence, Confidence::MatchByPort);
    }

    #[test]
    fn test_multi_protocol_port() {
        let result = match_port(443).unwrap();
        assert_eq!(result.protocol, Protocol::Tls);
    }

    #[cfg(feature = "database")]
    #[test]
    fn test_mssql_ports() {
        assert_eq!(match_port(1433).unwrap().protocol, Protocol::Mssql);
        assert_eq!(match_port(1434).unwrap().protocol, Protocol::Mssql);
        assert_eq!(
            match_port(1433).unwrap().confidence,
            Confidence::MatchByPort
        );
    }

    #[cfg(feature = "messaging")]
    #[test]
    fn test_kafka_port() {
        assert_eq!(match_port(9092).unwrap().protocol, Protocol::Kafka);
        assert_eq!(
            match_port(9092).unwrap().confidence,
            Confidence::MatchByPort
        );
    }

    #[cfg(feature = "database")]
    #[test]
    fn test_oracle_cassandra_ports() {
        assert_eq!(match_port(1521).unwrap().protocol, Protocol::Oracle);
        assert_eq!(match_port(7000).unwrap().protocol, Protocol::Cassandra);
        assert_eq!(match_port(9042).unwrap().protocol, Protocol::Cassandra);
        assert_eq!(
            match_port(9042).unwrap().confidence,
            Confidence::MatchByPort
        );
    }
}
