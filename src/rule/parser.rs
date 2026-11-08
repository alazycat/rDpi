use super::{Rule, RuleCondition};
use crate::core::types::*;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RuleEntry {
    id: String,
    protocol: String,
    condition: RuleConditionEntry,
}

#[derive(Debug, Deserialize)]
struct RuleConditionEntry {
    dst_port: Option<u16>,
    src_port: Option<u16>,
    sni_contains: Option<String>,
    payload_contains: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RuleFile {
    rules: Vec<RuleEntry>,
}

impl RuleFile {
    pub(crate) fn into_rules(self) -> Vec<Rule> {
        self.rules
            .into_iter()
            .map(|entry| {
                let protocol = match entry.protocol.to_lowercase().as_str() {
                    "tcp" => Protocol::Tcp,
                    "udp" => Protocol::Udp,
                    "http" => Protocol::Http,
                    "http_connect" | "httpconnect" => Protocol::HttpConnect,
                    "http_proxy" | "httpproxy" => Protocol::HttpProxy,
                    "doh" => Protocol::Doh,
                    "dot" => Protocol::Dot,
                    "doq" => Protocol::Doq,
                    "tls" => Protocol::Tls,
                    "dns" => Protocol::Dns,
                    "ssh" => Protocol::Ssh,
                    "smtp" => Protocol::Smtp,
                    "quic" => Protocol::Quic,
                    "dtls" => Protocol::Dtls,
                    "pop3" => Protocol::Pop3,
                    "imap" => Protocol::Imap,
                    "ntp" => Protocol::Ntp,
                    "dhcp" => Protocol::Dhcp,
                    "snmp" => Protocol::Snmp,
                    "modbus" => Protocol::Modbus,
                    "mysql" => Protocol::Mysql,
                    "postgresql" => Protocol::Postgresql,
                    "redis" => Protocol::Redis,
                    #[cfg(feature = "database")]
                    "mssql" | "mssql_tds" => Protocol::Mssql,
                    #[cfg(feature = "database")]
                    "oracle" => Protocol::Oracle,
                    #[cfg(feature = "database")]
                    "cassandra" => Protocol::Cassandra,
                    #[cfg(feature = "database")]
                    "memcached" => Protocol::Memcached,
                    #[cfg(feature = "database")]
                    "elasticsearch" => Protocol::Elasticsearch,
                    #[cfg(feature = "messaging")]
                    "amqp" => Protocol::Amqp,
                    #[cfg(feature = "messaging")]
                    "kafka" => Protocol::Kafka,
                    #[cfg(feature = "proto3")]
                    "ftp" => Protocol::Ftp,
                    #[cfg(feature = "proto3")]
                    "sip" => Protocol::Sip,
                    #[cfg(feature = "proto3")]
                    "rtp" => Protocol::Rtp,
                    #[cfg(feature = "proto3")]
                    "rtcp" => Protocol::Rtcp,
                    #[cfg(feature = "smb")]
                    "netbios" => Protocol::NetBios,
                    #[cfg(feature = "smb")]
                    "smb1" => Protocol::Smb1,
                    #[cfg(feature = "smb")]
                    "smb23" => Protocol::Smb23,
                    _ => Protocol::Other(0),
                };
                Rule {
                    id: entry.id,
                    protocol,
                    condition: RuleCondition {
                        dst_port: entry.condition.dst_port,
                        src_port: entry.condition.src_port,
                        sni_contains: entry.condition.sni_contains,
                        payload_contains: entry.condition.payload_contains,
                    },
                    metadata: None,
                }
            })
            .collect()
    }
}
