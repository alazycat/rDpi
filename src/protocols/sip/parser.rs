/// SIP 方法列表
const SIP_METHODS: &[&str] = &[
    "INVITE", "REGISTER", "BYE", "ACK", "CANCEL", "OPTIONS",
    "SUBSCRIBE", "NOTIFY", "MESSAGE", "PUBLISH", "INFO",
    "PRACK", "UPDATE", "REFER",
];

#[derive(Debug, Clone)]
pub struct SipRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct SipResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
}

/// 解析 SIP 请求行：METHOD sip:uri SIP/2.0
pub fn parse_sip_request(payload: &[u8]) -> Option<SipRequest> {
    let s = std::str::from_utf8(payload).ok()?;
    let end = s.find("\r\n").or_else(|| s.find('\n'))?;
    let line = s[..end].trim_end_matches('\r');

    for method in SIP_METHODS {
        if line.starts_with(method) && line.as_bytes().get(method.len()) == Some(&b' ') {
            let rest = line[method.len() + 1..].trim();
            let parts: Vec<&str> = rest.rsplitn(2, ' ').collect();
            if parts.len() == 2 && parts[1].starts_with("sip:") {
                return Some(SipRequest {
                    method: method.to_string(),
                    uri: parts[1].to_string(),
                    version: parts[0].to_string(),
                });
            }
        }
    }
    None
}

/// 解析 SIP 状态行：SIP/2.0 XXX Reason
pub fn parse_sip_response(payload: &[u8]) -> Option<SipResponse> {
    let s = std::str::from_utf8(payload).ok()?;
    let end = s.find("\r\n").or_else(|| s.find('\n'))?;
    let line = s[..end].trim_end_matches('\r');

    if !line.starts_with("SIP/2.0 ") {
        return None;
    }
    let rest = &line[8..];
    let space = rest.find(' ')?;
    let code: u16 = rest[..space].parse().ok()?;
    let reason = rest[space + 1..].to_string();
    Some(SipResponse {
        version: "2.0".to_string(),
        status_code: code,
        reason,
    })
}

/// 判断是否为 SIP 消息（首行匹配）
pub fn is_sip_message(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    // 优先检查 SIP 响应行，避免与 S 开头的方法名（如 SUBSCRIBE）冲突
    if payload.starts_with(b"SIP/2.0 ") {
        return true;
    }
    // 检查 SIP 请求（方法名）
    let first = payload[0];
    if (b'A'..=b'Z').contains(&first) {
        return SIP_METHODS
            .iter()
            .any(|m| payload.starts_with(m.as_bytes()));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sip_invite() {
        let req = parse_sip_request(
            b"INVITE sip:user@domain.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060\r\n",
        )
        .unwrap();
        assert_eq!(req.method, "INVITE");
        assert_eq!(req.uri, "sip:user@domain.com");
    }

    #[test]
    fn test_parse_sip_register() {
        let req = parse_sip_request(b"REGISTER sip:registrar.com SIP/2.0\r\n").unwrap();
        assert_eq!(req.method, "REGISTER");
    }

    #[test]
    fn test_parse_sip_response() {
        let resp = parse_sip_response(
            b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.1\r\n",
        )
        .unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "OK");
    }

    #[test]
    fn test_parse_sip_not_found() {
        let resp = parse_sip_response(b"SIP/2.0 404 Not Found\r\n").unwrap();
        assert_eq!(resp.status_code, 404);
    }

    #[test]
    fn test_is_sip_message_request() {
        assert!(is_sip_message(b"INVITE sip:user@domain.com SIP/2.0\r\n"));
    }

    #[test]
    fn test_is_sip_message_response() {
        assert!(is_sip_message(b"SIP/2.0 200 OK\r\n"));
    }

    #[test]
    fn test_not_sip() {
        assert!(!is_sip_message(b"GET / HTTP/1.1\r\n"));
    }
}
