//! Redis protocol parser for rDpi
//!
//! Parses Redis RESP (Redis Serialization Protocol) commands.

use crate::core::types::RedisMetadata;

/// Top 30 Redis commands by frequency
const TOP_COMMANDS: &[&str] = &[
    "GET", "SET", "DEL", "EXISTS", "EXPIRE",
    "TTL", "INCR", "DECR", "INCRBY", "DECRBY",
    "LPUSH", "RPUSH", "LPOP", "RPOP", "LRANGE",
    "SADD", "SREM", "SMEMBERS", "SISMEMBER",
    "HSET", "HGET", "HDEL", "HGETALL", "HKEYS",
    "ZADD", "ZREM", "ZRANGE", "ZSCORE",
    "KEYS", "SCAN", "SELECT", "PING", "INFO",
    "FLUSHDB", "FLUSHALL", "AUTH", "MGET", "MSET",
];

/// Parse Redis RESP command
///
/// RESP format:
/// - Simple string: +OK\r\n
/// - Error: -ERR message\r\n
/// - Integer: :1000\r\n
/// - Bulk string: $6\r<arg_value>SELECT\r\n
/// - Array: *3\r\n$3\r\nSET\r\n...
pub fn parse_redis_command(data: &[u8]) -> Option<RedisMetadata> {
    if data.is_empty() {
        return None;
    }

    let first_byte = data[0];

    match first_byte {
        // Array (most commands are arrays)
        b'*' => parse_array_command(data),
        // Simple string (PING, INFO responses)
        b'+' => parse_simple_string_command(data),
        // Bulk string (inline commands)
        b'$' => parse_bulk_string_command(data),
        _ => None,
    }
}

/// Parse array-type command
/// Format: *<count>\r\n$<len>\r<arg_value><command>\r\n...
fn parse_array_command(data: &[u8]) -> Option<RedisMetadata> {
    // Find first \r\n after *
    let first_line_end = find_crlf(data)?;
    if first_line_end < 1 {
        return None;
    }

    // Parse array count
    let count_str = std::str::from_utf8(&data[1..first_line_end]).ok()?;
    let count: usize = count_str.parse().ok()?;
    if count == 0 {
        return None;
    }

    // Find first bulk string (the command)
    let offset = first_line_end + 2; // skip \r\n
    if offset >= data.len() || data[offset] != b'$' {
        return None;
    }

    // Find bulk string length line end
    let bulk_line_end = find_crlf(&data[offset..])?;
    let bulk_offset = offset + bulk_line_end + 2; // skip $len\r\n

    if bulk_offset >= data.len() {
        return None;
    }

    // Find command string end
    let cmd_end = find_crlf(&data[bulk_offset..])?;
    let command = std::str::from_utf8(&data[bulk_offset..bulk_offset + cmd_end]).ok()?;
    let command_upper = command.to_uppercase();

    // Check if it's a recognized command
    if TOP_COMMANDS.contains(&command_upper.as_str()) {
        Some(RedisMetadata {
            command: Some(command_upper),
        })
    } else {
        // Unknown command, still detect as Redis
        Some(RedisMetadata {
            command: None,
        })
    }
}

/// Parse simple string command
/// Format: +<string>\r\n
fn parse_simple_string_command(data: &[u8]) -> Option<RedisMetadata> {
    let line_end = find_crlf(data)?;
    if line_end < 2 {
        return None;
    }

    let content = std::str::from_utf8(&data[1..line_end]).ok()?;
    let content_upper = content.to_uppercase();

    // Common responses: OK, PONG, QUEUED, etc.
    // Also check for simple commands like PING
    if content_upper == "PING" {
        Some(RedisMetadata {
            command: Some("PING".to_string()),
        })
    } else if content_upper == "OK" || content_upper == "PONG" || content_upper == "QUEUED" {
        // Response, not command - still detect as Redis
        Some(RedisMetadata {
            command: None,
        })
    } else {
        None
    }
}

/// Parse bulk string command
/// Format: $<len>\r\n<data>\r\n
fn parse_bulk_string_command(data: &[u8]) -> Option<RedisMetadata> {
    let line_end = find_crlf(data)?;
    if line_end < 2 {
        return None;
    }

    // Parse length
    let len_str = std::str::from_utf8(&data[1..line_end]).ok()?;
    let len: usize = len_str.parse().ok()?;
    if len == 0 {
        return None;
    }

    let data_offset = line_end + 2;
    if data_offset + len > data.len() {
        return None;
    }

    // Check if this looks like a command
    let content = std::str::from_utf8(&data[data_offset..data_offset + len]).ok()?;
    let content_upper = content.to_uppercase();

    // If it's a known command, detect as Redis
    if TOP_COMMANDS.contains(&content_upper.as_str()) {
        Some(RedisMetadata {
            command: Some(content_upper),
        })
    } else {
        None
    }
}

/// Find CRLF position in data
fn find_crlf(data: &[u8]) -> Option<usize> {
    for i in 0..data.len() - 1 {
        if data[i] == '\r' as u8 && data[i + 1] == '\n' as u8 {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a Redis array command
    fn create_array_command(cmd: &str) -> Vec<u8> {
        let cmd_len = cmd.len();
        format!("*1\r\n${}\r\n{}\r\n", cmd_len, cmd).into_bytes()
    }

    /// Create a Redis multi-arg command
    fn create_multi_arg_command(cmd: &str, args: &[&str]) -> Vec<u8> {
        let mut result = format!("*{}\r\n", args.len() + 1);
        let cmd_len = cmd.len();
        result.push_str(&format!("${}\r\n{}\r\n", cmd_len, cmd));
        for arg in args {
            let arg_len = arg.len();
            result.push_str(&format!("${}\r\n{}\r\n", arg_len, arg));
        }
        result.into_bytes()
    }

    #[test]
    fn test_parse_redis_get_command() {
        let data = create_array_command("GET");
        let meta = parse_redis_command(&data).unwrap();
        assert_eq!(meta.command, Some("GET".to_string()));
    }

    #[test]
    fn test_parse_redis_set_command() {
        let data = create_multi_arg_command("SET", &["key", "value"]);
        let meta = parse_redis_command(&data).unwrap();
        assert_eq!(meta.command, Some("SET".to_string()));
    }

    #[test]
    fn test_parse_redis_ping_command() {
        let data = create_array_command("PING");
        let meta = parse_redis_command(&data).unwrap();
        assert_eq!(meta.command, Some("PING".to_string()));
    }

    #[test]
    fn test_parse_redis_simple_ping() {
        let data = b"+PING\r\n";
        let meta = parse_redis_command(data).unwrap();
        assert_eq!(meta.command, Some("PING".to_string()));
    }

    #[test]
    fn test_parse_redis_ok_response() {
        let data = b"+OK\r\n";
        let meta = parse_redis_command(data).unwrap();
        assert_eq!(meta.command, None); // Response, not command
    }

    #[test]
    fn test_parse_redis_pong_response() {
        let data = b"+PONG\r\n";
        let meta = parse_redis_command(data).unwrap();
        assert_eq!(meta.command, None);
    }

    #[test]
    fn test_parse_redis_select_command() {
        let data = create_multi_arg_command("SELECT", &["0"]);
        let meta = parse_redis_command(&data).unwrap();
        assert_eq!(meta.command, Some("SELECT".to_string()));
    }

    #[test]
    fn test_parse_redis_case_insensitive() {
        let data = create_array_command("get");
        let meta = parse_redis_command(&data).unwrap();
        assert_eq!(meta.command, Some("GET".to_string()));
    }

    #[test]
    fn test_parse_redis_unknown_command() {
        // Unknown command, still detected as Redis
        let data = create_array_command("CUSTOMCMD");
        let meta = parse_redis_command(&data).unwrap();
        assert_eq!(meta.command, None); // Unknown command
    }

    #[test]
    fn test_parse_redis_invalid_format() {
        assert!(parse_redis_command(b"").is_none());
        assert!(parse_redis_command(b"random data").is_none());
        assert!(parse_redis_command(b"*0\r\n").is_none());
        assert!(parse_redis_command(b"*abc\r\n").is_none());
    }

    #[test]
    fn test_find_crlf() {
        assert_eq!(find_crlf(b"hello\r\n"), Some(5));
        assert_eq!(find_crlf(b"test\r\nmore"), Some(4));
        assert_eq!(find_crlf(b"no terminator"), None);
    }
}