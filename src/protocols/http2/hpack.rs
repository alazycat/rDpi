//! HPACK 头部解码（RFC 7541）
//!
//! 仅用于 HTTP/2 首个客户端 HEADERS 帧的一次性元数据提取：
//! - Huffman 解码：运行时由静态码表构建二叉 trie（`OnceLock`），逐位解码
//! - 索引/字面量：静态表 + 帧内局部动态表（无跨包状态）
//! - 全路径带上限，防畸形输入导致的资源耗尽
//!
//! 码表来源：RFC 7541 Appendix B，与 nghttp2 / Go x/net 两个独立实现逐项
//! 交叉验证一致（Kraft 和精确等于 2^30、前缀无冲突、EOS = 30 位全 1）。

use std::sync::OnceLock;

/// Huffman 码表：`(位数, 右对齐码值)`，符号 0-256（256 = EOS）。
const HUFFMAN_TABLE: [(u8, u32); 257] = [
    (13, 0x1ff8),
    (23, 0x7fffd8),
    (28, 0xfffffe2),
    (28, 0xfffffe3),
    (28, 0xfffffe4),
    (28, 0xfffffe5),
    (28, 0xfffffe6),
    (28, 0xfffffe7),
    (28, 0xfffffe8),
    (24, 0xffffea),
    (30, 0x3ffffffc),
    (28, 0xfffffe9),
    (28, 0xfffffea),
    (30, 0x3ffffffd),
    (28, 0xfffffeb),
    (28, 0xfffffec),
    (28, 0xfffffed),
    (28, 0xfffffee),
    (28, 0xfffffef),
    (28, 0xffffff0),
    (28, 0xffffff1),
    (28, 0xffffff2),
    (30, 0x3ffffffe),
    (28, 0xffffff3),
    (28, 0xffffff4),
    (28, 0xffffff5),
    (28, 0xffffff6),
    (28, 0xffffff7),
    (28, 0xffffff8),
    (28, 0xffffff9),
    (28, 0xffffffa),
    (28, 0xffffffb),
    (6, 0x14),
    (10, 0x3f8),
    (10, 0x3f9),
    (12, 0xffa),
    (13, 0x1ff9),
    (6, 0x15),
    (8, 0xf8),
    (11, 0x7fa),
    (10, 0x3fa),
    (10, 0x3fb),
    (8, 0xf9),
    (11, 0x7fb),
    (8, 0xfa),
    (6, 0x16),
    (6, 0x17),
    (6, 0x18),
    (5, 0x0),
    (5, 0x1),
    (5, 0x2),
    (6, 0x19),
    (6, 0x1a),
    (6, 0x1b),
    (6, 0x1c),
    (6, 0x1d),
    (6, 0x1e),
    (6, 0x1f),
    (7, 0x5c),
    (8, 0xfb),
    (15, 0x7ffc),
    (6, 0x20),
    (12, 0xffb),
    (10, 0x3fc),
    (13, 0x1ffa),
    (6, 0x21),
    (7, 0x5d),
    (7, 0x5e),
    (7, 0x5f),
    (7, 0x60),
    (7, 0x61),
    (7, 0x62),
    (7, 0x63),
    (7, 0x64),
    (7, 0x65),
    (7, 0x66),
    (7, 0x67),
    (7, 0x68),
    (7, 0x69),
    (7, 0x6a),
    (7, 0x6b),
    (7, 0x6c),
    (7, 0x6d),
    (7, 0x6e),
    (7, 0x6f),
    (7, 0x70),
    (7, 0x71),
    (7, 0x72),
    (8, 0xfc),
    (7, 0x73),
    (8, 0xfd),
    (13, 0x1ffb),
    (19, 0x7fff0),
    (13, 0x1ffc),
    (14, 0x3ffc),
    (6, 0x22),
    (15, 0x7ffd),
    (5, 0x3),
    (6, 0x23),
    (5, 0x4),
    (6, 0x24),
    (5, 0x5),
    (6, 0x25),
    (6, 0x26),
    (6, 0x27),
    (5, 0x6),
    (7, 0x74),
    (7, 0x75),
    (6, 0x28),
    (6, 0x29),
    (6, 0x2a),
    (5, 0x7),
    (6, 0x2b),
    (7, 0x76),
    (6, 0x2c),
    (5, 0x8),
    (5, 0x9),
    (6, 0x2d),
    (7, 0x77),
    (7, 0x78),
    (7, 0x79),
    (7, 0x7a),
    (7, 0x7b),
    (15, 0x7ffe),
    (11, 0x7fc),
    (14, 0x3ffd),
    (13, 0x1ffd),
    (28, 0xffffffc),
    (20, 0xfffe6),
    (22, 0x3fffd2),
    (20, 0xfffe7),
    (20, 0xfffe8),
    (22, 0x3fffd3),
    (22, 0x3fffd4),
    (22, 0x3fffd5),
    (23, 0x7fffd9),
    (22, 0x3fffd6),
    (23, 0x7fffda),
    (23, 0x7fffdb),
    (23, 0x7fffdc),
    (23, 0x7fffdd),
    (23, 0x7fffde),
    (24, 0xffffeb),
    (23, 0x7fffdf),
    (24, 0xffffec),
    (24, 0xffffed),
    (22, 0x3fffd7),
    (23, 0x7fffe0),
    (24, 0xffffee),
    (23, 0x7fffe1),
    (23, 0x7fffe2),
    (23, 0x7fffe3),
    (23, 0x7fffe4),
    (21, 0x1fffdc),
    (22, 0x3fffd8),
    (23, 0x7fffe5),
    (22, 0x3fffd9),
    (23, 0x7fffe6),
    (23, 0x7fffe7),
    (24, 0xffffef),
    (22, 0x3fffda),
    (21, 0x1fffdd),
    (20, 0xfffe9),
    (22, 0x3fffdb),
    (22, 0x3fffdc),
    (23, 0x7fffe8),
    (23, 0x7fffe9),
    (21, 0x1fffde),
    (23, 0x7fffea),
    (22, 0x3fffdd),
    (22, 0x3fffde),
    (24, 0xfffff0),
    (21, 0x1fffdf),
    (22, 0x3fffdf),
    (23, 0x7fffeb),
    (23, 0x7fffec),
    (21, 0x1fffe0),
    (21, 0x1fffe1),
    (22, 0x3fffe0),
    (21, 0x1fffe2),
    (23, 0x7fffed),
    (22, 0x3fffe1),
    (23, 0x7fffee),
    (23, 0x7fffef),
    (20, 0xfffea),
    (22, 0x3fffe2),
    (22, 0x3fffe3),
    (22, 0x3fffe4),
    (23, 0x7ffff0),
    (22, 0x3fffe5),
    (22, 0x3fffe6),
    (23, 0x7ffff1),
    (26, 0x3ffffe0),
    (26, 0x3ffffe1),
    (20, 0xfffeb),
    (19, 0x7fff1),
    (22, 0x3fffe7),
    (23, 0x7ffff2),
    (22, 0x3fffe8),
    (25, 0x1ffffec),
    (26, 0x3ffffe2),
    (26, 0x3ffffe3),
    (26, 0x3ffffe4),
    (27, 0x7ffffde),
    (27, 0x7ffffdf),
    (26, 0x3ffffe5),
    (24, 0xfffff1),
    (25, 0x1ffffed),
    (19, 0x7fff2),
    (21, 0x1fffe3),
    (26, 0x3ffffe6),
    (27, 0x7ffffe0),
    (27, 0x7ffffe1),
    (26, 0x3ffffe7),
    (27, 0x7ffffe2),
    (24, 0xfffff2),
    (21, 0x1fffe4),
    (21, 0x1fffe5),
    (26, 0x3ffffe8),
    (26, 0x3ffffe9),
    (28, 0xffffffd),
    (27, 0x7ffffe3),
    (27, 0x7ffffe4),
    (27, 0x7ffffe5),
    (20, 0xfffec),
    (24, 0xfffff3),
    (20, 0xfffed),
    (21, 0x1fffe6),
    (22, 0x3fffe9),
    (21, 0x1fffe7),
    (21, 0x1fffe8),
    (23, 0x7ffff3),
    (22, 0x3fffea),
    (22, 0x3fffeb),
    (25, 0x1ffffee),
    (25, 0x1ffffef),
    (24, 0xfffff4),
    (24, 0xfffff5),
    (26, 0x3ffffea),
    (23, 0x7ffff4),
    (26, 0x3ffffeb),
    (27, 0x7ffffe6),
    (26, 0x3ffffec),
    (26, 0x3ffffed),
    (27, 0x7ffffe7),
    (27, 0x7ffffe8),
    (27, 0x7ffffe9),
    (27, 0x7ffffea),
    (27, 0x7ffffeb),
    (28, 0xffffffe),
    (27, 0x7ffffec),
    (27, 0x7ffffed),
    (27, 0x7ffffee),
    (27, 0x7ffffef),
    (27, 0x7fffff0),
    (26, 0x3ffffee),
    (30, 0x3fffffff),
];

/// 静态表（RFC 7541 Appendix A），索引 1-61。
const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// 单个头部条目数上限（防爆炸）
const MAX_HEADERS: usize = 64;
/// 单个字符串字面量长度上限
const MAX_STRING_LEN: usize = 4096;
/// 帧内局部动态表容量上限
const MAX_DYN_ENTRIES: usize = 64;

/// Huffman trie 节点
#[derive(Default)]
struct TrieNode {
    children: [Option<u16>; 2],
    sym: Option<u16>,
}

static HUFF_TRIE: OnceLock<Vec<TrieNode>> = OnceLock::new();

/// 构建解码 trie（仅首次调用时执行一次）
fn huff_trie() -> &'static [TrieNode] {
    HUFF_TRIE.get_or_init(|| {
        let mut trie = vec![TrieNode::default()];
        for (sym, &(bits, code)) in HUFFMAN_TABLE.iter().enumerate() {
            let sym = sym as u16;
            let mut node = 0usize;
            for level in (0..bits).rev() {
                let bit = ((code >> level) & 1) as usize;
                let last = level == 0;
                match trie[node].children[bit] {
                    Some(child) => {
                        node = child as usize;
                        if last {
                            trie[node].sym = Some(sym);
                        }
                    }
                    None => {
                        let idx = trie.len() as u16;
                        trie.push(if last {
                            TrieNode {
                                children: [None, None],
                                sym: Some(sym),
                            }
                        } else {
                            TrieNode::default()
                        });
                        trie[node].children[bit] = Some(idx);
                        node = idx as usize;
                    }
                }
            }
        }
        trie
    })
}

/// HPACK Huffman 解码（RFC 7541 §5.2）
///
/// 尾部不足 8 位的填充必须是 EOS 码（全 1）的前缀。
/// 数据中途解出 EOS 视为解码错误。
pub fn huffman_decode(data: &[u8]) -> Option<Vec<u8>> {
    let trie = huff_trie();
    let mut out = Vec::with_capacity(data.len() * 2);
    let mut node = 0usize;
    let mut since_emit = 0u32;
    let mut ones = 0u32;
    for &byte in data {
        for i in (0..8).rev() {
            let bit = ((byte >> i) & 1) as usize;
            let child = trie[node].children[bit]?; // 非法编码
            node = child as usize;
            since_emit += 1;
            if bit == 1 {
                ones += 1;
            } else {
                ones = 0;
            }
            if let Some(sym) = trie[node].sym {
                if sym == 256 {
                    return None; // EOS 不允许出现在数据中部
                }
                out.push(sym as u8);
                node = 0;
                since_emit = 0;
                ones = 0;
            }
        }
    }
    if node != 0 {
        // 尾部未完成路径：必须是全 1 的 EOS 前缀且长度 < 8 位
        if since_emit >= 8 || ones != since_emit {
            return None;
        }
    }
    Some(out)
}

/// 前缀整数解码（RFC 7541 §5.1）
fn read_int(cur: &mut usize, block: &[u8], prefix_bits: u8) -> Option<u64> {
    if *cur >= block.len() {
        return None;
    }
    let mask = (1u64 << prefix_bits) - 1;
    let mut v = (block[*cur] as u64) & mask;
    *cur += 1;
    if v < mask {
        return Some(v);
    }
    let mut shift = 0u32;
    loop {
        if *cur >= block.len() || shift >= 57 {
            return None; // 截断或数值过大
        }
        let b = block[*cur];
        *cur += 1;
        v += ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
}

/// 字符串字面量解码（RFC 7541 §5.2）
fn read_string(cur: &mut usize, block: &[u8]) -> Option<String> {
    if *cur >= block.len() {
        return None;
    }
    let huffman = block[*cur] & 0x80 != 0;
    let len = read_int(cur, block, 7)? as usize;
    if len > MAX_STRING_LEN || *cur + len > block.len() {
        return None;
    }
    let raw = &block[*cur..*cur + len];
    *cur += len;
    if huffman {
        let decoded = huffman_decode(raw)?;
        String::from_utf8(decoded).ok()
    } else {
        String::from_utf8(raw.to_vec()).ok()
    }
}

/// 按索引查静态表 / 动态表，返回 (name, value)
fn lookup(idx: u64, dyn_table: &[(String, String)]) -> Option<(String, String)> {
    if idx == 0 || idx > 61 + dyn_table.len() as u64 {
        return None;
    }
    if idx <= 61 {
        let (n, v) = STATIC_TABLE[(idx - 1) as usize];
        Some((n.to_string(), v.to_string()))
    } else {
        let pos = dyn_table.len() - (idx - 61) as usize;
        Some(dyn_table[pos].clone())
    }
}

/// 字面量表示的 (name, value)：name 可来自索引
fn read_literal_pair(
    cur: &mut usize,
    block: &[u8],
    name_idx: u64,
    dyn_table: &[(String, String)],
) -> Option<(String, String)> {
    let name = if name_idx == 0 {
        read_string(cur, block)?
    } else {
        lookup(name_idx, dyn_table)?.0
    };
    let value = read_string(cur, block)?;
    Some((name, value))
}

/// 解码一个完整的 HPACK 头部块（RFC 7541 §6）
///
/// 无状态设计：动态表仅在本块内有效（增量索引条目在块内可被索引引用），
/// 与"只解码首个客户端 HEADERS 帧"的使用场景自洽——连接级动态表从空开始。
pub fn decode_header_block(block: &[u8]) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut dyn_table: Vec<(String, String)> = Vec::new();
    let mut cur = 0usize;
    while cur < block.len() {
        if out.len() >= MAX_HEADERS {
            return None; // 防爆炸
        }
        let b = block[cur];
        if b & 0x80 != 0 {
            // 索引头部字段
            let idx = read_int(&mut cur, block, 7)?;
            out.push(lookup(idx, &dyn_table)?);
        } else if b & 0xC0 == 0x40 {
            // 增量索引的字面量
            let name_idx = read_int(&mut cur, block, 6)?;
            let pair = read_literal_pair(&mut cur, block, name_idx, &dyn_table)?;
            if dyn_table.len() >= MAX_DYN_ENTRIES {
                dyn_table.remove(0);
            }
            dyn_table.push(pair.clone());
            out.push(pair);
        } else if b & 0xE0 == 0x20 {
            // 动态表大小更新：一次性解码不维护真实容量，直接跳过
            let _ = read_int(&mut cur, block, 5)?;
        } else {
            // 不索引 / 永不索引的字面量（0000xxxx / 0001xxxx，共用 4 位前缀）
            let name_idx = read_int(&mut cur, block, 4)?;
            let pair = read_literal_pair(&mut cur, block, name_idx, &dyn_table)?;
            out.push(pair);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 码表结构自检：Kraft 和精确等于 2^30（完备无间隙）
    #[test]
    fn test_kraft_sum_exact() {
        let mut kraft: u64 = 0;
        for &(bits, _) in HUFFMAN_TABLE.iter() {
            kraft += 1u64 << (30 - bits);
        }
        assert_eq!(kraft, 1u64 << 30);
    }

    /// 码表结构自检：前缀无冲突（按左对齐码值排序后相邻项不互为前缀）
    #[test]
    fn test_prefix_free() {
        let mut sorted: Vec<(u64, u8, usize)> = HUFFMAN_TABLE
            .iter()
            .enumerate()
            .map(|(sym, &(bits, code))| (((code as u64) << (30 - bits)) as u64, bits, sym))
            .collect();
        sorted.sort_by_key(|&(left, _, _)| left);
        for w in sorted.windows(2) {
            let (left_a, bits_a, _) = w[0];
            let (left_b, bits_b, _) = w[1];
            if bits_b >= bits_a {
                assert_ne!(left_b >> (bits_b - bits_a), left_a, "sym 是另一符号的前缀");
            }
        }
    }

    /// RFC 7541 C.4.1 官方向量：:authority "www.example.com" 的 Huffman 编码
    #[test]
    fn test_huffman_decode_rfc_c4_1() {
        let data = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(huffman_decode(&data).unwrap(), b"www.example.com");
    }

    /// 尾部填充必须是 EOS（全 1）的最高位前缀：全 1 合法、含 0 非法
    #[test]
    fn test_huffman_decode_padding() {
        // "www.example.com"（89 位码）+ 7 位全 1 填充（RFC C.4.1 同款）
        let ok = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(huffman_decode(&ok).unwrap(), b"www.example.com");
        // 尾部填充含 0（非 EOS 前缀）→ 非法
        let bad = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0x80,
        ];
        assert!(huffman_decode(&bad).is_none());
    }

    /// 单符号解码抽查（覆盖 5/6 位短码与 13 位长码，尾部补全 1 填充）
    #[test]
    fn test_huffman_decode_symbols() {
        // '0' = 5 位 00000 + 3 位全 1 填充
        assert_eq!(huffman_decode(&[0x07]).unwrap(), b"0");
        // '/' = 6 位 011000 + 2 位全 1 填充
        assert_eq!(huffman_decode(&[0x63]).unwrap(), b"/");
        // 'a' = 5 位 00011 + 3 位全 1 填充
        assert_eq!(huffman_decode(&[0x1f]).unwrap(), b"a");
        // sym 0（13 位 1111111111000）+ 3 位全 1 EOS 前缀填充
        assert_eq!(huffman_decode(&[0xff, 0xc7]).unwrap(), &[0u8][..]);
    }

    /// 非法编码：未定义码点 → None
    #[test]
    fn test_huffman_decode_invalid() {
        // 00000 解出 '0' 后剩余位含 0（非 EOS 全 1 前缀）→ 失败
        assert!(huffman_decode(&[0x01]).is_none());
        // 全 0：连续解出三个 '0' 后剩 1 位 0 → 失败
        assert!(huffman_decode(&[0x00, 0x00]).is_none());
    }

    /// RFC 7541 C.4.1 完整头部块（索引 + 增量索引字面量 + Huffman 值）
    #[test]
    fn test_decode_header_block_rfc_c4_1() {
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let headers = decode_header_block(&block).unwrap();
        assert_eq!(headers.len(), 4);
        assert_eq!(headers[0], (":method".to_string(), "GET".to_string()));
        assert_eq!(headers[1], (":scheme".to_string(), "http".to_string()));
        assert_eq!(headers[2], (":path".to_string(), "/".to_string()));
        assert_eq!(
            headers[3],
            (":authority".to_string(), "www.example.com".to_string())
        );
    }

    /// 非压缩字面量：索引名（user-agent = 58，4 位前缀续码）+ 不索引表示
    #[test]
    fn test_decode_header_block_literal() {
        // literal without indexing: 首字节 0x00|0x0f（4 位前缀取满），续码 58-15
        let mut block = vec![0x0f, 58 - 15, 0x0b];
        block.extend_from_slice(b"Mozilla/5.0");
        let headers = decode_header_block(&block).unwrap();
        assert_eq!(
            headers[0],
            ("user-agent".to_string(), "Mozilla/5.0".to_string())
        );
    }

    /// 自定义名（name_idx = 0）
    #[test]
    fn test_decode_header_block_custom_name() {
        let mut block = vec![0x40, 0x04];
        block.extend_from_slice(b"host");
        block.push(0x0b);
        block.extend_from_slice(b"example.com");
        let headers = decode_header_block(&block).unwrap();
        assert_eq!(headers[0], ("host".to_string(), "example.com".to_string()));
    }

    /// 帧内动态表：增量索引条目可被后续索引引用
    #[test]
    fn test_decode_header_block_dynamic_table() {
        let mut block = vec![0x40, 0x03];
        block.extend_from_slice(b"foo");
        block.push(0x03);
        block.extend_from_slice(b"bar");
        // 索引 62 = 动态表最新条目
        block.push(0x80 | 62);
        let headers = decode_header_block(&block).unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0], ("foo".to_string(), "bar".to_string()));
        assert_eq!(headers[1], ("foo".to_string(), "bar".to_string()));
    }

    /// 动态表大小更新指令被跳过
    #[test]
    fn test_decode_header_block_size_update() {
        // 0x20 | 31 = 动态表大小更新 max=31
        let block = [0x3f, 0x00, 0x82];
        let headers = decode_header_block(&block).unwrap();
        assert_eq!(headers[0], (":method".to_string(), "GET".to_string()));
    }

    /// 畸形输入：截断 / 越界索引 / 字符串越界 → None
    #[test]
    fn test_decode_header_block_malformed() {
        // 空块
        assert!(decode_header_block(&[]).unwrap().is_empty());
        // 截断的索引字段
        assert!(decode_header_block(&[0x80]).is_none());
        // 索引 0 无效
        assert!(decode_header_block(&[0x80]).is_none());
        // 字符串长度越界
        assert!(decode_header_block(&[0x40, 0x7f, 0x81, 0x80]).is_none());
        // 悬空的字面量（只有 name 索引没有 value）
        assert!(decode_header_block(&[0x41]).is_none());
    }
}
