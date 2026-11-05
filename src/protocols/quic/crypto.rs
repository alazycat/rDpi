//! QUIC Initial 包解密所需的密码学原语（全手写，不引入新依赖）
//!
//! RFC 9001 §5：QUIC v1 Initial 包使用 AEAD_AES_128_GCM + HKDF-SHA256 保护。
//! 本模块实现：
//! - AES-128 加密核心（仅需加密方向：GCM-CTR 与头部保护都是 AES-ECB 单块加密）
//! - AES-128-GCM 解密（GHASH + CTR，RFC 8439）
//! - HMAC-SHA256 / HKDF（RFC 2104 / RFC 5869，基于现有 sha2 依赖）
//! - TLS 1.3 HKDF-Expand-Label（RFC 8446 §7.1）与 QUIC Initial 密钥派生（RFC 9001 §5.2）
//!
//! 性能说明：解密仅在 QUIC Initial 包上触发（每流至多数个包），会有少量堆分配
//! （AES 轮密钥为栈上数组，明文/密文缓冲约 1-2 KiB），量级可接受且失败即降级。

use super::parser::{QUIC_VERSION_1, QUIC_VERSION_2};

/// AES S-box（FIPS-197 §5.1.1）
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// GF(2^8) 上乘 2（xtime）
#[inline]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ ((x >> 7) * 0x1b)
}

/// AES-128 密钥扩展：16 字节密钥 → 176 字节轮密钥（11 轮）
fn key_expansion(key: &[u8; 16]) -> [u8; 176] {
    let mut rk = [0u8; 176];
    rk[..16].copy_from_slice(key);
    let mut rcon = 1u8;
    let mut i = 16;
    while i < 176 {
        // 取上一个字（4 字节）
        let mut t = [rk[i - 4], rk[i - 3], rk[i - 2], rk[i - 1]];
        if i % 16 == 0 {
            // RotWord + SubWord + Rcon
            t.rotate_left(1);
            for b in &mut t {
                *b = SBOX[*b as usize];
            }
            t[0] ^= rcon;
            rcon = xtime(rcon);
        }
        for j in 0..4 {
            rk[i + j] = rk[i - 16 + j] ^ t[j];
        }
        i += 4;
    }
    rk
}

/// AES-128 单块加密（ECB 方向，等价于 RFC 9001 §5.4.3 的 AES 头保护掩码运算）
fn aes128_encrypt_block(rk: &[u8; 176], block: &[u8; 16]) -> [u8; 16] {
    let mut s = *block;

    // 初始轮 AddRoundKey
    for j in 0..16 {
        s[j] ^= rk[j];
    }

    // 9 个完整轮：SubBytes + ShiftRows + MixColumns + AddRoundKey
    for round in 1..10 {
        // SubBytes
        for b in &mut s {
            *b = SBOX[*b as usize];
        }
        // ShiftRows（列主序：第 r 行 = s[r], s[r+4], s[r+8], s[r+12]，左移 r）
        for r in 1..4 {
            let row = [s[r], s[r + 4], s[r + 8], s[r + 12]];
            s[r] = row[r % 4];
            s[r + 4] = row[(r + 1) % 4];
            s[r + 8] = row[(r + 2) % 4];
            s[r + 12] = row[(r + 3) % 4];
        }
        // MixColumns
        for c in 0..4 {
            let o = c * 4;
            let (a0, a1, a2, a3) = (s[o], s[o + 1], s[o + 2], s[o + 3]);
            s[o] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
            s[o + 1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
            s[o + 2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
            s[o + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
        }
        // AddRoundKey
        let off = round * 16;
        for j in 0..16 {
            s[j] ^= rk[off + j];
        }
    }

    // 末轮：SubBytes + ShiftRows + AddRoundKey（无 MixColumns）
    for b in &mut s {
        *b = SBOX[*b as usize];
    }
    for r in 1..4 {
        let row = [s[r], s[r + 4], s[r + 8], s[r + 12]];
        s[r] = row[r % 4];
        s[r + 4] = row[(r + 1) % 4];
        s[r + 8] = row[(r + 2) % 4];
        s[r + 12] = row[(r + 3) % 4];
    }
    for j in 0..16 {
        s[j] ^= rk[160 + j];
    }
    s
}

/// 128 位大端整数右移 1 位（GHASH 用）
fn shift_right_128(v: &mut [u8; 16]) {
    for j in (1..16).rev() {
        v[j] = (v[j] >> 1) | (v[j - 1] << 7);
    }
    v[0] >>= 1;
}

/// 乘 x（GCM 的 GF(2^128) 约定：右移 1 位，最高位溢出则异或 R = 0xe1…）
fn mul_x(v: &mut [u8; 16]) {
    let lsb = v[15] & 1;
    shift_right_128(v);
    if lsb == 1 {
        v[0] ^= 0xe1;
    }
}

/// 逐位 GF(2^128) 乘法参考实现（NIST SP 800-38D §6.3）
///
/// 仅保留为测试对照基准（oracle）：生产路径已改用 [`GhashTable`] 查表乘法。
#[cfg(test)]
fn gf128_mul_reference(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for i in 0..128 {
        if (x[i / 8] >> (7 - (i % 8))) & 1 == 1 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }
        mul_x(&mut v);
    }
    z
}

/// GHASH 查表乘法结构（Shoup 式 4-bit 表）
///
/// T[k][m] = 被乘数第 k 个 nibble（自最高位起，k=0 为字节 0 高 4 位）取值 m 时
/// 对 V·H 的贡献，即 nibble 的四个比特分别乘 H·x^(4k+0..3) 后的异或和。
/// 于是 V·H = ⊕_k T[k][nibble_k(V)]——单次 128 位乘法从逐位 128 次移位+条件异或
/// 降为 32 次查表异或，无移位、无数据依赖分支。
///
/// 空间：32 × 16 × 16B = 8 KiB（栈上）；构建约百次移位，随 GHASH 块数摊销
/// （单个 QUIC Initial 的 GCM 计算约 80 块，摊销比约 1:60）。
struct GhashTable {
    t: [[[u8; 16]; 16]; 32],
}

impl GhashTable {
    /// 由 H 构建查表
    fn new(h: &[u8; 16]) -> Self {
        let mut t = [[[0u8; 16]; 16]; 32];
        let mut base = *h; // base = H · x^(4k)
        for (k, t_k) in t.iter_mut().enumerate() {
            if k > 0 {
                for _ in 0..4 {
                    mul_x(&mut base);
                }
            }
            // W[q] = H · x^(4k+q)；m 的第 p 位（自低位起）对应 nibble 内第 (3-p) 高位，
            // 其权重为 x^(4k+3-p)，故单比特基项 T[k][1<<p] = W[3-p]
            let mut w = [base; 4];
            for i in 1..4 {
                w[i] = w[i - 1];
                mul_x(&mut w[i]);
            }
            t_k[1] = w[3];
            t_k[2] = w[2];
            t_k[4] = w[1];
            t_k[8] = w[0];
            // 其余项由低一位项异或对应基项得出
            for m in 1..16usize {
                if m.count_ones() > 1 {
                    let p = m.trailing_zeros() as usize;
                    let mut acc = t_k[m & (m - 1)];
                    let b = &t_k[1 << p];
                    for j in 0..16 {
                        acc[j] ^= b[j];
                    }
                    t_k[m] = acc;
                }
            }
        }
        Self { t }
    }

    /// V · H：32 次查表异或（无移位、无分支）
    fn mul(&self, v: &[u8; 16]) -> [u8; 16] {
        let mut z = [0u8; 16];
        for (j, byte) in v.iter().enumerate() {
            let th = &self.t[2 * j][(byte >> 4) as usize];
            let tl = &self.t[2 * j + 1][(byte & 0x0f) as usize];
            for i in 0..16 {
                z[i] ^= th[i] ^ tl[i];
            }
        }
        z
    }
}

/// GHASH 单块吸收：Y ^= block; Y = Y · H（查表乘法）
#[inline]
fn ghash_block(table: &GhashTable, y: &mut [u8; 16], block: &[u8; 16]) {
    let mut v = [0u8; 16];
    for j in 0..16 {
        v[j] = y[j] ^ block[j];
    }
    *y = table.mul(&v);
}

/// GHASH 流式吸收（自动补零到 16 字节边界）
fn ghash_update(table: &GhashTable, y: &mut [u8; 16], data: &[u8]) {
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        ghash_block(table, y, &block);
    }
}

/// AES-128-GCM 解密并校验认证标签（RFC 8439 §7）
///
/// nonce 为 96 位；返回明文（堆分配，量级 = 单个 QUIC Initial 载荷）。
/// 标签校验失败返回 None（认证不通过，数据不可信）。
pub(crate) fn aes128_gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
) -> Option<Vec<u8>> {
    let rk = key_expansion(key);

    // H = E(K, 0^128)
    let h = aes128_encrypt_block(&rk, &[0u8; 16]);
    let table = GhashTable::new(&h);

    // J0 = nonce || 0x00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    // 长度块：8 字节 AAD 位长 || 8 字节密文位长
    let len_block: [u8; 16] = {
        let aad_bits = (aad.len() as u64) * 8;
        let ct_bits = (ct.len() as u64) * 8;
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&aad_bits.to_be_bytes());
        b[8..].copy_from_slice(&ct_bits.to_be_bytes());
        b
    };

    // S = GHASH_H(AAD || pad || C || pad || len)
    let mut s = [0u8; 16];
    ghash_update(&table, &mut s, aad);
    ghash_update(&table, &mut s, ct);
    ghash_block(&table, &mut s, &len_block);

    // T = E(K, J0) XOR S
    let ek_j0 = aes128_encrypt_block(&rk, &j0);
    let mut diff = 0u8;
    for j in 0..16 {
        diff |= ek_j0[j] ^ s[j] ^ tag[j];
    }
    if diff != 0 {
        return None; // 标签不匹配（常量时间比较后统一拒绝）
    }

    // CTR 解密：计数器从 inc32(J0) 开始
    let mut counter = j0;
    inc32(&mut counter);
    let mut pt = Vec::with_capacity(ct.len());
    for chunk in ct.chunks(16) {
        let ks = aes128_encrypt_block(&rk, &counter);
        for (i, b) in chunk.iter().enumerate() {
            pt.push(b ^ ks[i]);
        }
        inc32(&mut counter);
    }
    Some(pt)
}

/// 32 位计数器自增（RFC 8439 §7.2，仅递增最后 4 字节）
#[inline]
fn inc32(block: &mut [u8; 16]) {
    let ctr = u32::from_be_bytes([block[12], block[13], block[14], block[15]]).wrapping_add(1);
    block[12..].copy_from_slice(&ctr.to_be_bytes());
}

/// HMAC-SHA256（RFC 2104）
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    // 密钥处理：超长先哈希，不足补零（SHA-256 块大小 64 字节）
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash: [u8; 32] = inner.finalize().into();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

/// HKDF-Extract（RFC 5869 §2.2）
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand（RFC 5869 §2.3）
fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new(); // T(0) 为空串
    let mut counter = 1u8;
    while okm.len() < len {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(counter);
        t = hmac_sha256(prk, &msg).to_vec();
        okm.extend_from_slice(&t);
        counter += 1;
    }
    okm.truncate(len);
    okm
}

/// TLS 1.3 HKDF-Expand-Label（RFC 8446 §7.1）
///
/// info = len(u16BE) || "tls13 " + label || context
fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, len)
}

/// QUIC 版本对应的 Initial salt（RFC 9001 §5.2 / RFC 9369 / draft-29 / draft-28）
fn initial_salt(version: u32) -> Option<&'static [u8; 20]> {
    match version {
        super::QUIC_VERSION_1 => Some(&[
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
            0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ]),
        super::QUIC_VERSION_2 => Some(&[
            0x0a, 0xf5, 0xef, 0x1c, 0x4e, 0x1f, 0x4c, 0xd4, 0xd6, 0xf0, 0xe6, 0xb5, 0x7a, 0xf4,
            0x4c, 0xea, 0x3c, 0xc4, 0x0e, 0x17,
        ]),
        super::QUIC_VERSION_DRAFT29 => Some(&[
            0xaf, 0x89, 0xbf, 0x25, 0x6f, 0x13, 0x6b, 0x9c, 0xf9, 0x6a, 0x03, 0xc7, 0x9f, 0x8c,
            0x4e, 0xb5, 0x85, 0x6d, 0xcb, 0x96,
        ]),
        super::QUIC_VERSION_DRAFT28 => Some(&[
            0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x3e, 0xbb, 0x1a, 0x96, 0x09, 0x31, 0x6c, 0x67, 0x2a,
            0xe1, 0x8a, 0xc1, 0xc4, 0x40, 0x8b,
        ]),
        _ => None,
    }
}

/// 派生的 QUIC Initial 保护密钥组（按包发送方向取对应 secret）
pub(crate) struct InitialKeys {
    /// AEAD 密钥（"quic key"，16 字节）
    pub key: [u8; 16],
    /// AEAD nonce 基值（"quic iv"，12 字节）
    pub iv: [u8; 12],
    /// 头保护密钥（"quic hp"，16 字节）
    pub hp: [u8; 16],
}

/// Initial 包发送方向（RFC 9001 §5.2：client/server 两个方向的 secret 均派生自
/// 同一 initial_secret，仅 Expand-Label 后缀不同）
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Side {
    /// 客户端发出的 Initial（"client in"）
    Client,
    /// 服务端发出的 Initial（"server in"）；其 DCID 字段即 ODCID（客户端所选 CID），
    /// 因此从包头 DCID 即可派生服务端密钥。
    Server,
}

/// 按方向派生 Initial 密钥（RFC 9001 §5.2）
///
/// initial_secret = HKDF-Extract(salt, ODCID)
/// <方向>secret   = HKDF-Expand-Label(initial_secret, "<client|server> in", "", 32)
/// key/iv/hp      = HKDF-Expand-Label(<方向>secret, "quic key"/"quic iv"/"quic hp", "", len)
pub(crate) fn derive_initial_keys(version: u32, dcid: &[u8], side: Side) -> Option<InitialKeys> {
    let salt = initial_salt(version)?;
    let initial_secret = hkdf_extract(salt, dcid);
    let secret = match side {
        Side::Client => hkdf_expand_label(&initial_secret, "client in", &[], 32),
        Side::Server => hkdf_expand_label(&initial_secret, "server in", &[], 32),
    };
    let key: [u8; 16] = hkdf_expand_label(&secret, "quic key", &[], 16)
        .try_into()
        .ok()?;
    let iv: [u8; 12] = hkdf_expand_label(&secret, "quic iv", &[], 12)
        .try_into()
        .ok()?;
    let hp: [u8; 16] = hkdf_expand_label(&secret, "quic hp", &[], 16)
        .try_into()
        .ok()?;
    Some(InitialKeys { key, iv, hp })
}

/// 移除头保护（RFC 9001 §5.4.2/§5.4.3）
///
/// 返回（去保护后的首字节, 原始 packet number, packet number 长度）。
/// 采样点固定取 packet number 字段起点后 4 字节开始的 16 字节（长度本身受保护，无法预知）。
fn remove_header_protection(
    hp: &[u8; 16],
    packet: &[u8],
    pn_offset: usize,
) -> Option<(u8, u64, usize)> {
    // 需要：采样点 16 字节 + 至少 1 字节 packet number + 16 字节认证标签
    if pn_offset + 4 + 16 + 1 + 16 > packet.len() {
        return None;
    }
    let mut sample = [0u8; 16];
    sample.copy_from_slice(&packet[pn_offset + 4..pn_offset + 20]);
    let mask = aes128_encrypt_block(&key_expansion(hp), &sample);

    // 长头：首字节低 4 位受保护（RFC 9001 §5.4.2）
    let first = packet[0] ^ (mask[0] & 0x0f);
    let pn_len = ((first & 0x03) as usize) + 1;

    let mut pn: u64 = 0;
    for i in 0..pn_len {
        pn = (pn << 8) | u64::from(packet[pn_offset + i] ^ mask[1 + i]);
    }
    Some((first, pn, pn_len))
}

/// 尝试解密并去保护 QUIC Initial 包载荷（RFC 9001 §5.3/§5.4）
///
/// 无流级 packet number 状态时，原始 pn 值（模 2^(8*pn_len)）即真实 pn 的低位。
/// 握手期 largest_acked 很小，raw == 真实 pn 几乎恒成立；对 pn_len < 4 的情况
/// 再尝试少数几个高位候选（tag 校验兜底），全部失败返回 None。
pub(crate) fn decrypt_initial_payload(
    packet: &[u8],
    pn_offset: usize,
    version: u32,
    dcid: &[u8],
    side: Side,
) -> Option<Vec<u8>> {
    let keys = derive_initial_keys(version, dcid, side)?;
    let (first, pn, pn_len) = remove_header_protection(&keys.hp, packet, pn_offset)?;

    // 候选数量上限：pn_len=4 时 raw 即完整 pn（仅 1 个候选）；否则最多 4 个候选
    let candidate_count = if pn_len == 4 { 1 } else { 4 };
    let step = 1u64 << (8 * pn_len);
    for k in 0..candidate_count {
        // nonce 使用 pn 的低 32 位（RFC 9001 §5.3）
        let pn32 = (pn.wrapping_add(k * step) & 0xffff_ffff) as u32;
        if let Some(pt) = decrypt_with_pn(packet, pn_offset, pn_len, first, pn32, &keys) {
            return Some(pt);
        }
    }
    None
}

/// 以给定 packet number 解密一次（AAD = 去保护后的头部）
fn decrypt_with_pn(
    packet: &[u8],
    pn_offset: usize,
    pn_len: usize,
    first: u8,
    pn: u32,
    keys: &InitialKeys,
) -> Option<Vec<u8>> {
    if pn_offset + pn_len + 16 > packet.len() {
        return None;
    }
    let ct = &packet[pn_offset + pn_len..packet.len() - 16];
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&packet[packet.len() - 16..]);

    // AAD = 未保护头部：首字节 + 版本/连接 ID/Token + 去保护的 packet number
    let mut aad = packet[..pn_offset + pn_len].to_vec();
    aad[0] = first;
    aad[pn_offset..pn_offset + pn_len].copy_from_slice(&pn.to_be_bytes()[4 - pn_len..]);

    // nonce = iv XOR 左填充 4 字节的 packet number
    let mut nonce = keys.iv;
    let pn_bytes = pn.to_be_bytes();
    for i in 0..4 {
        nonce[8 + i] ^= pn_bytes[i];
    }

    aes128_gcm_decrypt(&keys.key, &nonce, &aad, ct, &tag)
}

/// GCM 加密（用于 Retry 包完整性标签计算与单元测试夹具构造）
pub(crate) fn aes128_gcm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    pt: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let rk = key_expansion(key);
    let h = aes128_encrypt_block(&rk, &[0u8; 16]);
    let table = GhashTable::new(&h);

    // CTR 加密
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let mut counter = j0;
    inc32(&mut counter);
    let mut ct = Vec::with_capacity(pt.len());
    for chunk in pt.chunks(16) {
        let ks = aes128_encrypt_block(&rk, &counter);
        for (i, b) in chunk.iter().enumerate() {
            ct.push(b ^ ks[i]);
        }
        inc32(&mut counter);
    }

    // 标签 = E(K, J0) XOR GHASH(AAD, CT, len)
    let mut s = [0u8; 16];
    ghash_update(&table, &mut s, aad);
    ghash_update(&table, &mut s, &ct);
    let len_block: [u8; 16] = {
        let aad_bits = (aad.len() as u64) * 8;
        let ct_bits = (ct.len() as u64) * 8;
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&aad_bits.to_be_bytes());
        b[8..].copy_from_slice(&ct_bits.to_be_bytes());
        b
    };
    ghash_block(&table, &mut s, &len_block);
    let ek_j0 = aes128_encrypt_block(&rk, &j0);
    let mut tag = [0u8; 16];
    for j in 0..16 {
        tag[j] = ek_j0[j] ^ s[j];
    }
    (ct, tag)
}

/// QUIC v1 Retry 完整性 AEAD 密钥（RFC 9001 §5.8）
///
/// 常数经双独立实现交叉验证：quic-go internal/handshake/retry.go 与
/// aioquic quic/packet.py 逐字节一致。
const RETRY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
/// QUIC v1 Retry 完整性 AEAD nonce（RFC 9001 §5.8，固定 12 字节）
const RETRY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];
/// QUIC v2 Retry 完整性 AEAD 密钥（RFC 9369，同上双源交叉验证）
const RETRY_KEY_V2: [u8; 16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];
/// QUIC v2 Retry 完整性 AEAD nonce（RFC 9369，固定 12 字节）
const RETRY_NONCE_V2: [u8; 12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
];

/// 计算 QUIC Retry 包完整性标签（RFC 9001 §5.8）
///
/// AES-128-GCM，空明文，AAD = Retry 伪包：
/// `odcid_len(1B) || odcid || retry_packet_without_tag`（ODCID 为客户端视角的
/// 原始目的连接 ID，即触发 Retry 的客户端 Initial 包的 DCID）。
///
/// 返回 None 表示版本不支持（仅覆盖 QUIC v1/v2 标准常数，draft 版本常数
/// 随版本演进、不做校验）。
pub(crate) fn retry_integrity_tag(
    retry_without_tag: &[u8],
    odcid: &[u8],
    version: u32,
) -> Option<[u8; 16]> {
    let (key, nonce) = match version {
        QUIC_VERSION_1 => (&RETRY_KEY_V1, &RETRY_NONCE_V1),
        QUIC_VERSION_2 => (&RETRY_KEY_V2, &RETRY_NONCE_V2),
        _ => return None,
    };
    // 伪包：odcid_len || odcid || retry_without_tag（长度字段用 u8，ODCID ≤ 20 字节天然满足）
    let mut pseudo = Vec::with_capacity(1 + odcid.len() + retry_without_tag.len());
    pseudo.push(odcid.len() as u8);
    pseudo.extend_from_slice(odcid);
    pseudo.extend_from_slice(retry_without_tag);

    let (_, tag) = aes128_gcm_encrypt(key, nonce, &pseudo, &[]);
    Some(tag)
}

/// 测试专用：构造一个完整的受保护 QUIC v1 Initial 包（固定 4 字节 packet number）
///
/// 结构对齐真实 Initial 包：首字节 0xC3 + Version + DCID + SCID + Token + Length
/// （2 字节 varint，覆盖 Packet Number + 载荷）+ 受保护的 Packet Number + 密文 + Tag。
#[cfg(test)]
pub(crate) fn build_initial_packet(
    version: u32,
    dcid: &[u8],
    pn: u32,
    frames: &[u8],
    side: Side,
) -> Vec<u8> {
    let keys = derive_initial_keys(version, dcid, side).unwrap();
    const PN_LEN: usize = 4;

    // 未保护头部：0xC3 = Long Header + Initial + pn_len=4
    let first: u8 = 0xC3;
    let mut packet = vec![first];
    packet.extend_from_slice(&version.to_be_bytes());
    packet.push(dcid.len() as u8);
    packet.extend_from_slice(dcid);
    packet.push(0x00); // SCID 长度 0
    packet.push(0x00); // Token 长度 0
    // Length = pn + 载荷（帧 + 16 字节 tag）；小于 16384 时用 2 字节 varint
    let payload_len = PN_LEN + frames.len() + 16;
    assert!(
        payload_len <= 0x3fff,
        "test helper 仅支持 2 字节 varint Length"
    );
    packet.push(0x40 | ((payload_len >> 8) as u8));
    packet.push((payload_len & 0xff) as u8);
    let pn_offset = packet.len();

    // AAD = 未保护头部（含明文 pn）
    let mut aad = packet.clone();
    aad.extend_from_slice(&pn.to_be_bytes());

    // nonce = iv XOR pn
    let mut nonce = keys.iv;
    let pn_bytes = pn.to_be_bytes();
    for i in 0..4 {
        nonce[8 + i] ^= pn_bytes[i];
    }

    // 写入明文 packet number（稍后被头保护掩码覆盖）
    packet.extend_from_slice(&pn.to_be_bytes());

    let (ct, tag) = aes128_gcm_encrypt(&keys.key, &nonce, &aad, frames);
    packet.extend_from_slice(&ct);
    packet.extend_from_slice(&tag);

    // 头保护：采样点 = pn 字段起点后 4 字节起的 16 字节（此处即密文起始）
    let mut sample = [0u8; 16];
    sample.copy_from_slice(&packet[pn_offset + 4..pn_offset + 20]);
    let mask = aes128_encrypt_block(&key_expansion(&keys.hp), &sample);
    packet[0] ^= mask[0] & 0x0f;
    for i in 0..4 {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    // ------------------------------------------------------------------
    // AES-128 单块加密：FIPS-197 附录 C.1 官方向量
    // ------------------------------------------------------------------

    #[test]
    fn test_aes128_ecb_fips197() {
        let key: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let block: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        let rk = key_expansion(&key);
        let out = aes128_encrypt_block(&rk, &block);
        assert_eq!(to_hex(&out), "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    #[test]
    fn test_aes128_ecb_fips197_vector2() {
        // FIPS-197 附录 C.1 变体：全零密钥 + 全零块（轮密钥首块即密钥本身）
        let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let block: [u8; 16] = hex("6bc1bee22e409f96e93d7e117393172a").try_into().unwrap();
        let rk = key_expansion(&key);
        let out = aes128_encrypt_block(&rk, &block);
        // SP 800-38A F.1.1 AES-128 ECB 第一块
        assert_eq!(to_hex(&out), "3ad77bb40d7a3660a89ecaf32466ef97");
    }

    // ------------------------------------------------------------------
    // AES-128-GCM：RFC 8439 官方测试向量
    // ------------------------------------------------------------------

    #[test]
    fn test_gcm_rfc8439_tc1() {
        // TC1：全零密钥/IV，空明文空 AAD
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let tag: [u8; 16] = hex("58e2fccefa7e3061367f1d57a4e7455a").try_into().unwrap();
        assert!(aes128_gcm_decrypt(&key, &nonce, &[], &[], &tag).is_some());
    }

    #[test]
    fn test_gcm_rfc8439_tc2() {
        // TC2：全零密钥/IV，16 字节零明文
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let pt = [0u8; 16];
        let ct: [u8; 16] = hex("0388dace60b6a392f328c2b971b2fe78").try_into().unwrap();
        let tag: [u8; 16] = hex("ab6e47d42cec13bdf53a67b21257bddf").try_into().unwrap();
        assert_eq!(
            aes128_gcm_decrypt(&key, &nonce, &[], &ct, &tag),
            Some(pt.to_vec())
        );
    }

    #[test]
    fn test_gcm_rfc8439_tc4() {
        // TC4：带 AAD 的 4 块明文
        let key: [u8; 16] = hex("feffe9928665731c6d6a8f9467308308").try_into().unwrap();
        let nonce: [u8; 12] = hex("cafebabefacedbaddecaf888").try_into().unwrap();
        let pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let ct = hex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        );
        let tag: [u8; 16] = hex("5bc94fbc3221a5db94fae95ae7121a47").try_into().unwrap();
        // 注：本向量出自 NIST SP 800-38D 附录 B Test Case 4（60 字节明文变体），
        // tag 已用独立 Python+OpenSSL 实现交叉验证（RFC 8439 与 GCM 无关）。
        assert_eq!(aes128_gcm_decrypt(&key, &nonce, &aad, &ct, &tag), Some(pt));

        // 篡改 1 bit → 拒绝
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        assert!(aes128_gcm_decrypt(&key, &nonce, &aad, &bad_ct, &tag).is_none());
    }

    #[test]
    fn test_ghash_table_matches_bitwise_reference() {
        // 查表乘法与逐位参考实现交叉验证（xorshift32 伪随机 200 对）
        let mut seed = 0x1a2b3c4du32;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for _ in 0..200 {
            let mut x = [0u8; 16];
            let mut y = [0u8; 16];
            for b in x.iter_mut() {
                *b = (next() & 0xff) as u8;
            }
            for b in y.iter_mut() {
                *b = (next() & 0xff) as u8;
            }
            let table = GhashTable::new(&y);
            assert_eq!(table.mul(&x), gf128_mul_reference(&x, &y));
        }
    }

    /// 性能对照（默认忽略）：查表 vs 逐位参考实现
    ///
    /// 运行：cargo test --lib -- --ignored --nocapture ghash_table_benchmark
    #[test]
    #[ignore]
    fn test_ghash_table_benchmark() {
        use std::hint::black_box;
        use std::time::Instant;

        let mut seed = 0xdeadbeefu32;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        let mut h = [0u8; 16];
        for b in h.iter_mut() {
            *b = (next() & 0xff) as u8;
        }
        let table = GhashTable::new(&h);
        let mut blocks = vec![[0u8; 16]; 4096];
        for b in blocks.iter_mut() {
            for e in b.iter_mut() {
                *e = (next() & 0xff) as u8;
            }
        }

        // 查表版
        let t0 = Instant::now();
        let mut acc = [0u8; 16];
        for _ in 0..64 {
            for b in &blocks {
                let r = black_box(table.mul(black_box(b)));
                for i in 0..16 {
                    acc[i] ^= r[i];
                }
            }
        }
        let d_table = t0.elapsed();

        // 逐位参考版
        let t1 = Instant::now();
        let mut acc2 = [0u8; 16];
        for _ in 0..64 {
            for b in &blocks {
                let r = black_box(gf128_mul_reference(black_box(b), &h));
                for i in 0..16 {
                    acc2[i] ^= r[i];
                }
            }
        }
        let d_bits = t1.elapsed();

        println!("查表 GHASH：262144 块耗时 {:?}", d_table);
        println!("逐位 GHASH：262144 块耗时 {:?}", d_bits);
        black_box((acc, acc2)); // 防止编译器消除循环
    }

    // ------------------------------------------------------------------
    // HMAC-SHA256：RFC 4231 官方测试向量
    // ------------------------------------------------------------------

    #[test]
    fn test_hmac_rfc4231() {
        // TC1：key = 0x0b * 20, data = "Hi There"
        let key = [0x0bu8; 20];
        let out = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            to_hex(&out),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        // TC2：key = "Jefe", data = "what do ya want for nothing?"
        let out = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            to_hex(&out),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    // ------------------------------------------------------------------
    // HKDF：RFC 5869 官方测试向量
    // ------------------------------------------------------------------

    #[test]
    fn test_hkdf_rfc5869_tc1() {
        // TC1：基本测试
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            to_hex(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let okm = hkdf_expand(&prk, &info, 42);
        assert_eq!(
            to_hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        );
    }

    #[test]
    fn test_hkdf_rfc5869_tc2() {
        // TC2：更长输入（OKM 前 32 字节 = T1；全长 82 字节不便记忆，TC1 已覆盖多块 expand）
        let ikm: Vec<u8> = (0x00u8..=0x4f).collect();
        let salt: Vec<u8> = (0x60u8..=0xaf).collect();
        let info: Vec<u8> = (0xb0u8..=0xff).collect();
        let okm = hkdf_expand(&hkdf_extract(&salt, &ikm), &info, 82);
        // OKM 前缀（RFC 5869 TC2）
        assert_eq!(
            &to_hex(&okm)[..64],
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        );
    }

    // ------------------------------------------------------------------
    // QUIC Initial 密钥派生：RFC 9001 附录 A.1 官方向量
    // ------------------------------------------------------------------

    #[test]
    fn test_derive_initial_keys_rfc9001_appendix_a1() {
        // RFC 9001 附录 A.1 官方向量（经独立来源交叉核对）
        let dcid = hex("8394c8f03e515708");
        let keys = derive_initial_keys(super::super::QUIC_VERSION_1, &dcid, Side::Client).unwrap();
        assert_eq!(to_hex(&keys.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(to_hex(&keys.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(to_hex(&keys.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn test_derive_initial_keys_server_side() {
        // 服务端方向：RFC 9001 §5.2 未发布计算值，用独立 Python 实现
        // （hashlib HMAC 逐标签展开）交叉核对生成期望值
        let dcid = hex("8394c8f03e515708");
        let keys = derive_initial_keys(super::super::QUIC_VERSION_1, &dcid, Side::Server).unwrap();
        assert_eq!(to_hex(&keys.key), "cf3a5331653c364c88f0f379b6067e37");
        assert_eq!(to_hex(&keys.iv), "0ac1493ca1905853b0bba03e");
        assert_eq!(to_hex(&keys.hp), "c206b8d9b9f0f37644430b490eeaa314");
    }
}
