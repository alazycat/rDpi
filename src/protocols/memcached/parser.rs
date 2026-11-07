//! Memcached 文本协议解析（与 nDPI 5.0 `memcached.c` 签名表一致）

/// UDP 请求头长度
pub const MEMCACHED_UDP_HEADER_LEN: usize = 8;

/// TCP 最少签名长度（`END\r\n`）
const MEMCACHED_MIN_LEN: usize = 5;

/// UDP 最少载荷（8 字节头 + 5 字节签名）
const MEMCACHED_MIN_UDP_LEN: usize = MEMCACHED_UDP_HEADER_LEN + MEMCACHED_MIN_LEN;

/// 签名条目：前缀字节 + 规范化 token
type Signature = (&'static [u8], &'static str);

/// 命令签名（小写、带尾随空格；`stats` 与 nDPI 一致不带空格）
const COMMANDS: &[Signature] = &[
    (b"set ", "set"),
    (b"add ", "add"),
    (b"replace ", "replace"),
    (b"append ", "append"),
    (b"prepend ", "prepend"),
    (b"cas ", "cas"),
    (b"get ", "get"),
    (b"gets ", "gets"),
    (b"delete ", "delete"),
    (b"incr ", "incr"),
    (b"decr ", "decr"),
    (b"touch ", "touch"),
    (b"gat ", "gat"),
    (b"gats ", "gats"),
    (b"stats", "stats"),
];

/// 响应签名
const RESPONSES: &[Signature] = &[
    (b"ERROR\r\n", "ERROR"),
    (b"CLIENT_ERROR ", "CLIENT_ERROR"),
    (b"SERVER_ERROR ", "SERVER_ERROR"),
    (b"STORED\r\n", "STORED"),
    (b"NOT_STORED\r\n", "NOT_STORED"),
    (b"EXISTS\r\n", "EXISTS"),
    (b"NOT_FOUND\r\n", "NOT_FOUND"),
    (b"END\r\n", "END"),
    (b"DELETED\r\n", "DELETED"),
    (b"TOUCHED\r\n", "TOUCHED"),
    (b"STAT ", "STAT"),
];

/// 解析结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemcachedParsed {
    /// 请求命令（小写）或响应状态（大写）
    pub token: &'static str,
    /// 是否为服务端响应
    pub is_response: bool,
}

fn match_prefix(
    payload: &[u8],
    table: &'static [Signature],
    is_response: bool,
) -> Option<MemcachedParsed> {
    table.iter().find_map(|(prefix, token)| {
        payload
            .starts_with(prefix)
            .then_some(MemcachedParsed { token, is_response })
    })
}

/// 解析 TCP 载荷起始处的 Memcached 命令或响应
pub fn parse_memcached(payload: &[u8]) -> Option<MemcachedParsed> {
    match_prefix(payload, COMMANDS, false).or_else(|| match_prefix(payload, RESPONSES, true))
}

/// 解析 UDP 载荷：8 字节请求头 + 命令/响应
pub fn parse_memcached_udp(payload: &[u8]) -> Option<MemcachedParsed> {
    if payload.len() < MEMCACHED_MIN_UDP_LEN {
        return None;
    }
    // nDPI：total datagrams 不得为 0，reserved 必须为 0
    let total_datagrams = u16::from_be_bytes([payload[4], payload[5]]);
    let reserved = u16::from_be_bytes([payload[6], payload[7]]);
    if total_datagrams == 0 || reserved != 0 {
        return None;
    }
    parse_memcached(&payload[MEMCACHED_UDP_HEADER_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commands() {
        let cases: &[(&[u8], &str)] = &[
            (b"set k 0 0 1\r\nx\r\n", "set"),
            (b"add k 0 0 1\r\n", "add"),
            (b"replace k 0 0 1\r\n", "replace"),
            (b"append k 0 0 1\r\n", "append"),
            (b"prepend k 0 0 1\r\n", "prepend"),
            (b"cas k 0 0 1 1\r\n", "cas"),
            (b"get foo\r\n", "get"),
            (b"gets foo\r\n", "gets"),
            (b"delete foo\r\n", "delete"),
            (b"incr foo 1\r\n", "incr"),
            (b"decr foo 1\r\n", "decr"),
            (b"touch foo 10\r\n", "touch"),
            (b"gat 10 foo\r\n", "gat"),
            (b"gats 10 foo\r\n", "gats"),
            (b"stats\r\n", "stats"),
        ];
        for (payload, token) in cases {
            let parsed = parse_memcached(payload).expect("command should match");
            assert_eq!(parsed.token, *token);
            assert!(!parsed.is_response);
        }
    }

    #[test]
    fn test_responses() {
        let cases: &[(&[u8], &str)] = &[
            (b"ERROR\r\n", "ERROR"),
            (b"CLIENT_ERROR bad command\r\n", "CLIENT_ERROR"),
            (b"SERVER_ERROR out of memory\r\n", "SERVER_ERROR"),
            (b"STORED\r\n", "STORED"),
            (b"NOT_STORED\r\n", "NOT_STORED"),
            (b"EXISTS\r\n", "EXISTS"),
            (b"NOT_FOUND\r\n", "NOT_FOUND"),
            (b"END\r\n", "END"),
            (b"DELETED\r\n", "DELETED"),
            (b"TOUCHED\r\n", "TOUCHED"),
            (b"STAT pid 1234\r\n", "STAT"),
        ];
        for (payload, token) in cases {
            let parsed = parse_memcached(payload).expect("response should match");
            assert_eq!(parsed.token, *token);
            assert!(parsed.is_response);
        }
    }

    #[test]
    fn test_rejects_case_mismatch_and_partial_prefixes() {
        assert!(parse_memcached(b"SET k 0 0 1\r\n").is_none());
        assert!(parse_memcached(b"end\r\n").is_none());
        assert!(parse_memcached(b"getaway\r\n").is_none());
        assert!(parse_memcached(b"GET / HTTP/1.1\r\n").is_none());
    }

    fn udp_payload(body: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x12, 0x34, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00];
        payload.extend_from_slice(body);
        payload
    }

    #[test]
    fn test_udp_header_and_command() {
        let payload = udp_payload(b"get foo\r\n");
        let parsed = parse_memcached_udp(&payload).expect("udp command should match");
        assert_eq!(parsed.token, "get");
        assert!(!parsed.is_response);
    }

    #[test]
    fn test_udp_rejects_bad_header() {
        let mut reserved = udp_payload(b"get foo\r\n");
        reserved[7] = 1;
        assert!(parse_memcached_udp(&reserved).is_none());

        let mut total = udp_payload(b"get foo\r\n");
        total[4] = 0;
        total[5] = 0;
        assert!(parse_memcached_udp(&total).is_none());

        let short = udp_payload(b"END\r\n");
        assert!(parse_memcached_udp(&short[..short.len() - 1]).is_none());
    }
}
