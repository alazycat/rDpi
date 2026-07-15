use std::time::{SystemTime, UNIX_EPOCH};
use crate::core::flow::Flow;
use crate::core::types::{Metadata, Protocol, TlsMetadata};
use crate::risk::types::{RiskFlag, RiskResult, RiskSeverity};
use crate::parser::ParsedPacket;
use crate::risk::RiskProcessor;

const MAX_CERT_DAYS: u64 = 398;

pub struct TlsCertRiskProcessor;
impl TlsCertRiskProcessor { pub fn new() -> Self { Self } }
impl Default for TlsCertRiskProcessor { fn default() -> Self { Self::new() } }

fn get_tls(flow: &Flow) -> Option<&TlsMetadata> {
    match &flow.metadata {
        Some(Metadata::Tls(tls)) if flow.protocol == Some(Protocol::Tls) => Some(tls),
        _ => None,
    }
}

impl RiskProcessor for TlsCertRiskProcessor {
    fn name(&self) -> &'static str { "tls_cert_risk" }

    fn analyze_packet(&self, _parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult> {
        let tls = match get_tls(flow) { Some(t) => t, None => return vec![] };
        let mut results = Vec::new();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        // 1. SelfSignedCert
        if let (Some(subj), Some(iss)) = (&tls.cert_subject, &tls.cert_issuer) {
            if subj == iss {
                results.push(RiskResult::new(RiskFlag::TlsSelfSignedCert, RiskSeverity::High,
                    format!("Self-signed TLS certificate: subject = issuer = \"{}\"", subj)));
            }
        }

        // 2. Expired
        if let Some(not_after) = tls.cert_valid_to {
            if not_after < now {
                results.push(RiskResult::new(RiskFlag::TlsCertExpired, RiskSeverity::High,
                    format!("TLS certificate expired {} seconds ago", now - not_after)));
            }
        }

        // 3. Validity too long
        if let (Some(from), Some(to)) = (tls.cert_valid_from, tls.cert_valid_to) {
            if to > from {
                let days = (to - from) / 86400;
                if days > MAX_CERT_DAYS {
                    results.push(RiskResult::new(RiskFlag::TlsCertValidityTooLong, RiskSeverity::Medium,
                        format!("Certificate valid for {} days (max recommended: {})", days, MAX_CERT_DAYS)));
                }
            }
        }

        results
    }

    fn analyze_flow(&self, _flow: &Flow) -> Vec<RiskResult> { vec![] }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::flow::Flow;
    use crate::core::types::FlowKey;
    use crate::core::types::TransportProto;
    fn flow(s: Option<&str>, i: Option<&str>, f: Option<u64>, t: Option<u64>) -> Flow {
        let mut f2 = Flow::new(FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(), dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 54321, dst_port: 443, transport: TransportProto::Tcp,
        });
        f2.protocol = Some(Protocol::Tls);
        f2.metadata = Some(Metadata::Tls(TlsMetadata {
            sni: None, version: Some("1.3".into()), application: None, ja4: None,
            cipher_suites: vec![], alpn: None,
            cert_subject: s.map(String::from), cert_issuer: i.map(String::from),
            cert_valid_from: f, cert_valid_to: t,
        }));
        f2
    }
    fn p() -> ParsedPacket { ParsedPacket {
        src_ip: "10.0.0.1".parse().unwrap(), dst_ip: "10.0.0.2".parse().unwrap(),
        src_port: 54321, dst_port: 443, transport: TransportProto::Tcp, payload: vec![],
    }}

    #[test] fn self_signed() { let r=TlsCertRiskProcessor::new().analyze_packet(&p(),&flow(Some("a"),Some("a"),None,None)); assert!(r.iter().any(|x|x.flag==RiskFlag::TlsSelfSignedCert)); }
    #[test] fn ca_signed() { let r=TlsCertRiskProcessor::new().analyze_packet(&p(),&flow(Some("a"),Some("b"),None,None)); assert!(!r.iter().any(|x|x.flag==RiskFlag::TlsSelfSignedCert)); }
    #[test] fn expired() { let r=TlsCertRiskProcessor::new().analyze_packet(&p(),&flow(Some("a"),Some("b"),Some(1000),Some(9999))); assert!(r.iter().any(|x|x.flag==RiskFlag::TlsCertExpired)); }
    #[test] fn valid() { let n=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(); let r=TlsCertRiskProcessor::new().analyze_packet(&p(),&flow(Some("a"),Some("b"),Some(n-86400),Some(n+86400*30))); assert!(!r.iter().any(|x|x.flag==RiskFlag::TlsCertExpired)); }
    #[test] fn too_long() { let n=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(); let r=TlsCertRiskProcessor::new().analyze_packet(&p(),&flow(Some("a"),Some("b"),Some(n),Some(n+86400*500))); assert!(r.iter().any(|x|x.flag==RiskFlag::TlsCertValidityTooLong)); }
    #[test] fn short_valid() { let n=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(); let r=TlsCertRiskProcessor::new().analyze_packet(&p(),&flow(Some("a"),Some("b"),Some(n),Some(n+86400*90))); assert!(!r.iter().any(|x|x.flag==RiskFlag::TlsCertValidityTooLong)); }
}
