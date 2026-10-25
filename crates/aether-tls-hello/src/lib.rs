//! 手工构造 TLS 1.3 ClientHello。
//!
//! 存在理由：`opencode.ai` 免费层按 **TLS 客户端指纹**放行。rustls / OpenSSL /
//! BoringSSL 都发不出目标那套 ClientHello（cipher 列表里含 CBC 套件、扩展集合与
//! 顺序固定），而 Go 的 utls 能。这个 crate 用纯 Rust 手写字节，等价于 utls 的
//! `HelloCustom`：调用方给随机段，其余字段按模板原样输出。
//!
//! 约束与事实来源（2026-10-25 实测）：
//! - 目标 JA3 = `1523504b38f0fae0d881d4b6554aac1b`（能拿到 200 的那条 hello）
//! - 17 个 cipher suite，顺序敏感，**含 CBC 套件**（0x002f/0x0035/0xc009 等）
//! - 13 个扩展，顺序：0,23,65281,10,11,35,16,5,13,18,51,45,43
//! - supported_groups = 4588(X25519MLKEM768), 29, 23, 24
//! - ALPN 只有 `http/1.1`（没有 h2），无 GREASE
//!
//! 本模块只负责「造字节」和「算 JA3」，不做握手：握手状态机是后续步骤，这样
//! 指纹这一层可以离线验证，不消耗上游额度。

/// 目标 JA3 指纹（opencode 官方客户端 / 免费层认可的那条）。
pub const TARGET_JA3: &str = "1523504b38f0fae0d881d4b6554aac1b";

/// 目标 cipher suite 列表，顺序不可改。
pub const CIPHER_SUITES: [u16; 17] = [
    0x1301, 0x1302, 0x1303, // TLS 1.3
    0xc02b, 0xc02f, 0xc02c, 0xc030, // ECDHE-ECDSA/RSA AES-GCM
    0xcca9, 0xcca8, // ECDHE CHACHA20
    0xc009, 0xc013, 0xc00a, 0xc014, // ECDHE-* AES-CBC
    0x009c, 0x009d, // AES-GCM（静态 RSA）
    0x002f, 0x0035, // AES-CBC（静态 RSA）
];

/// 目标扩展顺序，顺序不可改。
pub const EXTENSION_ORDER: [u16; 13] = [
    0,     // server_name
    23,    // extended_master_secret
    65281, // renegotiation_info
    10,    // supported_groups
    11,    // ec_point_formats
    35,    // session_ticket
    16,    // ALPN
    5,     // status_request
    13,    // signature_algorithms
    18,    // signed_certificate_timestamp
    51,    // key_share
    45,    // psk_key_exchange_modes
    43,    // supported_versions
];

/// supported_groups，顺序不可改；4588 是 X25519MLKEM768 的编号。
pub const SUPPORTED_GROUPS: [u16; 4] = [4588, 29, 23, 24];

/// signature_algorithms，顺序不可改。
pub const SIGNATURE_ALGORITHMS: [u16; 11] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807, 0x0603, 0x0201,
];

/// 构造一条 ClientHello 所需的「每次都要变」的部分。
///
/// 公钥材料由调用方给：本模块不碰密码学，M2 里用 `ml-kem` + `x25519-dalek` 生成，
/// 单元测试里用固定字节即可（JA3 只取决于结构与顺序，与公钥内容无关）。
pub struct HelloInputs<'a> {
    pub server_name: &'a str,
    /// 32 字节 client random
    pub random: [u8; 32],
    /// 32 字节 legacy_session_id（目标客户端固定 32 字节）
    pub session_id: [u8; 32],
    /// group 4588 的 key_share 数据：ML-KEM-768 封装公钥(1184) || X25519 公钥(32)
    pub mlkem_share: &'a [u8],
    /// group 29 的 key_share 数据：X25519 公钥(32)
    pub x25519_share: &'a [u8],
}

/// 生成完整的 TLS record：`16 03 01 len` + handshake(ClientHello)。
pub fn build_client_hello(input: &HelloInputs<'_>) -> Vec<u8> {
    let mut body = Vec::with_capacity(1600);
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&input.random);
    body.push(32);
    body.extend_from_slice(&input.session_id);

    // cipher_suites（TLS 1.3 与 TLS 1.2 混在同一个列表里，顺序即指纹）
    body.extend_from_slice(&((CIPHER_SUITES.len() * 2) as u16).to_be_bytes());
    for suite in CIPHER_SUITES {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    body.extend_from_slice(&[0x01, 0x00]); // compression: null

    let mut exts = Vec::with_capacity(1200);
    // 0 server_name
    {
        let host = input.server_name.as_bytes();
        let mut list = Vec::with_capacity(host.len() + 3);
        list.push(0); // host_name
        list.extend_from_slice(&(host.len() as u16).to_be_bytes());
        list.extend_from_slice(host);
        push_ext(&mut exts, 0, &{
            let mut v = Vec::with_capacity(list.len() + 2);
            v.extend_from_slice(&(list.len() as u16).to_be_bytes());
            v.extend_from_slice(&list);
            v
        });
    }
    // 23 extended_master_secret（空体）
    push_ext(&mut exts, 23, &[]);
    // 65281 renegotiation_info（renegotiated_connection 空 = 0x00）
    push_ext(&mut exts, 65281, &[0x00]);
    // 10 supported_groups
    {
        let mut v = Vec::with_capacity(SUPPORTED_GROUPS.len() * 2 + 2);
        v.extend_from_slice(&((SUPPORTED_GROUPS.len() * 2) as u16).to_be_bytes());
        for g in SUPPORTED_GROUPS {
            v.extend_from_slice(&g.to_be_bytes());
        }
        push_ext(&mut exts, 10, &v);
    }
    // 11 ec_point_formats（仅 uncompressed）
    push_ext(&mut exts, 11, &[0x01, 0x00]);
    // 35 session_ticket（空体）
    push_ext(&mut exts, 35, &[]);
    // 16 ALPN（只有 http/1.1）
    push_ext(&mut exts, 16, &{
        let p = b"http/1.1";
        let mut v = Vec::with_capacity(p.len() + 3);
        v.extend_from_slice(&((p.len() + 1) as u16).to_be_bytes());
        v.push(p.len() as u8);
        v.extend_from_slice(p);
        v
    });
    // 5 status_request（ocsp, 空 responder 列表, 空扩展）
    push_ext(&mut exts, 5, &[0x01, 0x00, 0x00, 0x00, 0x00]);
    // 13 signature_algorithms
    {
        let mut v = Vec::with_capacity(SIGNATURE_ALGORITHMS.len() * 2 + 2);
        v.extend_from_slice(&((SIGNATURE_ALGORITHMS.len() * 2) as u16).to_be_bytes());
        for s in SIGNATURE_ALGORITHMS {
            v.extend_from_slice(&s.to_be_bytes());
        }
        push_ext(&mut exts, 13, &v);
    }
    // 18 signed_certificate_timestamp（空体）
    push_ext(&mut exts, 18, &[]);
    // 51 key_share（4588 + 29 两份）
    {
        let mut entries =
            Vec::with_capacity(input.mlkem_share.len() + input.x25519_share.len() + 8);
        for (group, data) in [(4588u16, input.mlkem_share), (29u16, input.x25519_share)] {
            entries.extend_from_slice(&group.to_be_bytes());
            entries.extend_from_slice(&(data.len() as u16).to_be_bytes());
            entries.extend_from_slice(data);
        }
        let mut v = Vec::with_capacity(entries.len() + 2);
        v.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        v.extend_from_slice(&entries);
        push_ext(&mut exts, 51, &v);
    }
    // 45 psk_key_exchange_modes（psk_dhe_ke）
    push_ext(&mut exts, 45, &[0x01, 0x01]);
    // 43 supported_versions（1.3, 1.2）
    push_ext(&mut exts, 43, &[0x04, 0x03, 0x04, 0x03, 0x03]);

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(0x01); // client_hello
    handshake.extend_from_slice(&u24(body.len()));
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(0x16); // handshake
    record.extend_from_slice(&[0x03, 0x01]); // record version = TLS 1.0（与官方一致）
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// 从一条 record（含 5 字节头）里算出 JA3。
///
/// 只实现 JA3 需要的四项：版本、cipher 列表、扩展类型列表（跳过 GREASE）、
/// supported_groups、ec_point_formats。
pub fn ja3_of(record: &[u8]) -> Option<String> {
    if record.len() < 9 || record[0] != 0x16 {
        return None;
    }
    let hs = 5;
    let mut i = hs + 4; // 跳过 handshake type + 长度
    let legacy_version = u16::from_be_bytes([record[i], record[i + 1]]);
    i += 2;
    i += 32; // random
    let sid_len = record[i] as usize;
    i += 1 + sid_len;
    let cs_len = u16::from_be_bytes([record[i], record[i + 1]]) as usize;
    i += 2;
    let suites: Vec<u16> = (0..cs_len / 2)
        .map(|k| u16::from_be_bytes([record[i + k * 2], record[i + k * 2 + 1]]))
        .collect();
    i += cs_len;
    let comp_len = record[i] as usize;
    i += 1 + comp_len;
    if i + 2 > record.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([record[i], record[i + 1]]) as usize;
    i += 2;
    let ext_end = (i + ext_total).min(record.len());

    let mut ext_types: Vec<u16> = Vec::new();
    let mut groups: Vec<u16> = Vec::new();
    let mut point_formats: Vec<u8> = Vec::new();
    while i + 4 <= ext_end {
        let ty = u16::from_be_bytes([record[i], record[i + 1]]);
        let len = u16::from_be_bytes([record[i + 2], record[i + 3]]) as usize;
        let body = &record[i + 4..(i + 4 + len).min(ext_end)];
        i += 4 + len;
        if is_grease(ty) {
            continue;
        }
        ext_types.push(ty);
        match ty {
            10 if body.len() >= 2 => {
                let n = u16::from_be_bytes([body[0], body[1]]) as usize;
                groups = (0..n / 2)
                    .filter_map(|k| body.get(2 + k * 2..4 + k * 2))
                    .map(|s| u16::from_be_bytes([s[0], s[1]]))
                    .filter(|g| !is_grease(*g))
                    .collect();
            }
            11 if !body.is_empty() => {
                let n = body[0] as usize;
                point_formats = body[1..(1 + n).min(body.len())].to_vec();
            }
            _ => {}
        }
    }

    let join = |v: &[u16]| {
        v.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    Some(format!(
        "{},{},{},{},{}",
        legacy_version,
        join(&suites),
        join(&ext_types),
        join(&groups),
        point_formats
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join("-")
    ))
}

fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) as u8 == (v & 0xff) as u8
}

fn push_ext(out: &mut Vec<u8>, ty: u16, body: &[u8]) {
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

fn u24(n: usize) -> [u8; 3] {
    [(n >> 16) as u8, (n >> 8) as u8, n as u8]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mlkem = vec![0x11u8; 1216];
        let x25519 = vec![0x22u8; 32];
        build_client_hello(&HelloInputs {
            server_name: "opencode.ai",
            random: [0x33; 32],
            session_id: [0x44; 32],
            mlkem_share: &mlkem,
            x25519_share: &x25519,
        })
    }

    #[test]
    fn ja3_matches_the_shape_the_upstream_accepts() {
        use md5::{Digest, Md5};
        let hello = sample();
        let ja3 = ja3_of(&hello).expect("parse");
        let digest = Md5::digest(ja3.as_bytes());
        let hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(hex, TARGET_JA3, "JA3 不一致，原文: {ja3}");
    }

    #[test]
    fn extension_order_is_pinned() {
        let hello = sample();
        let ja3 = ja3_of(&hello).unwrap();
        let exts = ja3.split(',').nth(2).unwrap();
        let want = EXTENSION_ORDER
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");
        assert_eq!(exts, want);
    }

    #[test]
    fn cipher_list_is_pinned_including_the_cbc_suites() {
        let hello = sample();
        let ja3 = ja3_of(&hello).unwrap();
        let ciphers = ja3.split(',').nth(1).unwrap();
        let want = CIPHER_SUITES
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");
        assert_eq!(ciphers, want);
        assert!(ciphers.contains("47"), "必须保留 0x002f(AES128-SHA)");
    }

    #[test]
    fn record_header_and_handshake_lengths_are_consistent() {
        let hello = sample();
        assert_eq!(hello[0], 0x16);
        assert_eq!(&hello[1..3], &[0x03, 0x01]);
        let rec_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(rec_len, hello.len() - 5);
        assert_eq!(hello[5], 0x01);
        let hs_len = u24_decode(&hello[6..9]);
        assert_eq!(hs_len, rec_len - 4);
    }

    fn u24_decode(b: &[u8]) -> usize {
        ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
    }
}
