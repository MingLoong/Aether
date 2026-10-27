// 手工构造 TLS 1.3 ClientHello。
//
// 存在理由：`opencode.ai` 免费层按 **TLS 客户端指纹**放行。rustls / OpenSSL /
// BoringSSL 都发不出目标那套 ClientHello（cipher 列表里含 CBC 套件、扩展集合与
// 顺序固定），而 Go 的 utls 能。这个 crate 用纯 Rust 手写字节，等价于 utls 的

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

use std::io::{self, Read, Write};
use std::net::TcpStream;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

/// 与 `host:port` 建立一条 TLS 1.3 连接（完整握手 + 证书校验）。
pub fn connect(host: &str, port: u16) -> Result<TlsStream, String> {
    let sock = TcpStream::connect((host, port)).map_err(|e| format!("connect: {e}"))?;
    connect_over(sock, host)
}

/// 在**已经建立好的 TCP 流**上完成 TLS 1.3 握手。
///
/// 用于「TCP 走别的通道（例如 SOCKS5 出口）、TLS 仍在本地做」的场景：
/// 握手字节与 `connect` 完全一致，客户端指纹不受传输路径影响。
pub fn connect_over(mut sock: TcpStream, host: &str) -> Result<TlsStream, String> {
    let mut rng = rand::rngs::OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    let ek_bytes = ek.as_bytes();
    let (_ct, _ss) = ek
        .encapsulate(&mut rng)
        .map_err(|_| "ml-kem encapsulate 失败".to_string())?;

    let x_secret = StaticSecret::random_from_rng(rng);
    let x_public = PublicKey::from(&x_secret);

    let mut share_4588 = Vec::with_capacity(1216);
    share_4588.extend_from_slice(ek_bytes.as_slice());
    share_4588.extend_from_slice(x_public.as_bytes());

    let mut random = [0u8; 32];
    let mut session_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut random);
    rand::RngCore::fill_bytes(&mut rng, &mut session_id);

    let hello = build_client_hello(&HelloInputs {
        server_name: host,
        random,
        session_id,
        mlkem_share: &share_4588,
        x25519_share: x_public.as_bytes(),
    });

    sock.set_read_timeout(Some(std::time::Duration::from_secs(120)))
        .ok();
    sock.write_all(&hello).map_err(|e| format!("write: {e}"))?;

    let (hs_type, sh_body) = read_handshake(&mut sock)?;
    if hs_type != 2 {
        return Err(format!("期望 ServerHello(2)，收到 {hs_type}"));
    }
    let sh = parse_server_hello(&sh_body)?;

    let group = sh.kex_group.ok_or("ServerHello 没有 key_share")?;
    let (ss_mlkem, ss_x): (Option<Vec<u8>>, Vec<u8>) = match group {
        4588 => {
            if sh.kex_share.len() != 1120 {
                return Err(format!("4588 的 share 长度 {} != 1120", sh.kex_share.len()));
            }
            let server_pub = PublicKey::from(<[u8; 32]>::try_from(&sh.kex_share[1088..]).unwrap());
            let ss = x_secret.diffie_hellman(&server_pub).as_bytes().to_vec();
            let arr = ml_kem::Ciphertext::<MlKem768>::try_from(&sh.kex_share[..1088])
                .map_err(|_| "ciphertext 长度不对".to_string())?;
            let mk = dk
                .decapsulate(&arr)
                .map_err(|_| "ml-kem decapsulate 失败".to_string())?;
            (Some(mk.as_slice().to_vec()), ss)
        }
        29 => {
            if sh.kex_share.len() != 32 {
                return Err(format!("29 的 share 长度 {} != 32", sh.kex_share.len()));
            }
            let server_pub = PublicKey::from(<[u8; 32]>::try_from(&sh.kex_share[..]).unwrap());
            let ss = x_secret.diffie_hellman(&server_pub).as_bytes().to_vec();
            (None, ss)
        }
        other => return Err(format!("不支持的 group {other}")),
    };

    let mut transcript = Sha256::new();
    transcript.update(&hello[5..]);
    transcript.update(server_hello_message(&sh_body));
    let th_sh = transcript.clone().finalize().to_vec();

    let mut candidates: Vec<Vec<u8>> = Vec::new();
    if let Some(mk) = ss_mlkem.as_ref() {
        let mut a = Vec::with_capacity(64);
        a.extend_from_slice(mk);
        a.extend_from_slice(&ss_x);
        candidates.push(a);
        let mut b = Vec::with_capacity(64);
        b.extend_from_slice(&ss_x);
        b.extend_from_slice(mk);
        candidates.push(b);
    } else {
        candidates.push(ss_x.clone());
    }

    let first_payload = loop {
        let (ct, payload) = read_record(&mut sock)?;
        if ct == 0x14 {
            continue;
        }
        if ct != 0x17 {
            return Err(format!("期望加密记录(0x17)，收到 0x{ct:02x}"));
        }
        break payload;
    };

    let mut hs_secret = Vec::new();
    let mut s_hs = Vec::new();
    let mut c_hs = Vec::new();
    let mut first_plain: Option<Vec<u8>> = None;
    for cand in candidates.iter() {
        let (hs, _) = handshake_secret(cand);
        let s = derive_secret(&hs, b"s hs traffic", &th_sh);
        let mut probe = RecordCipher::new(&s);
        if let Ok(pt) = probe.decrypt(&first_payload) {
            c_hs = derive_secret(&hs, b"c hs traffic", &th_sh);
            hs_secret = hs;
            s_hs = s;
            first_plain = Some(pt);
            break;
        }
    }
    let first_plain = first_plain.ok_or("服务端握手记录解密失败（两种拼接顺序都不对）")?;

    let mut s_hs_reader = RecordCipher::new_at(&s_hs, 1);
    let mut c_hs_writer = RecordCipher::new(&c_hs);

    let mut hs_buf: Vec<u8> = first_plain;
    let mut cert_chain: Vec<Vec<u8>> = Vec::new();
    let mut cert_verify: (u16, Vec<u8>) = (0, Vec::new());
    let mut th_before_cv: Option<Vec<u8>> = None;
    let mut server_finished_ok = false;
    while !server_finished_ok {
        let complete = hs_buf.len() >= 4 && {
            let len =
                ((hs_buf[1] as usize) << 16) | ((hs_buf[2] as usize) << 8) | hs_buf[3] as usize;
            hs_buf.len() >= 4 + len
        };
        if !complete {
            let (ct, payload) = read_record(&mut sock)?;
            if ct == 0x14 {
                continue;
            }
            if ct != 0x17 {
                return Err(format!("期望加密记录(0x17)，收到 0x{ct:02x}"));
            }
            let plain = s_hs_reader
                .decrypt(&payload)
                .map_err(|_| "服务端握手记录解密失败".to_string())?;
            hs_buf.extend_from_slice(&plain);
            continue;
        }
        let ty = hs_buf[0];
        let len = ((hs_buf[1] as usize) << 16) | ((hs_buf[2] as usize) << 8) | hs_buf[3] as usize;
        let msg: Vec<u8> = hs_buf.drain(..4 + len).collect();
        let body = &msg[4..];
        match ty {
            11 => cert_chain = parse_certificate(body)?,
            15 => {
                th_before_cv = Some(transcript.clone().finalize().to_vec());
                cert_verify = parse_certificate_verify(body)?;
            }
            20 => {
                let fin_key = hkdf_expand_label(&s_hs, b"finished", b"", 32);
                let expect = hmac_sha256(&fin_key, &transcript.clone().finalize());
                if expect.as_slice() != body {
                    return Err("服务端 Finished 校验失败".into());
                }
                server_finished_ok = true;
            }
            _ => {}
        }
        transcript.update(&msg);
    }

    verify_peer(host, &cert_chain, cert_verify, th_before_cv)?;

    let th_cf = transcript.clone().finalize().to_vec();
    let client_fin_key = hkdf_expand_label(&c_hs, b"finished", b"", 32);
    let client_verify = hmac_sha256(&client_fin_key, &th_cf);
    let mut flight = handshake_msg(20, &client_verify);
    let rec = c_hs_writer.encrypt(&mut flight, 0x16);
    sock.write_all(&rec)
        .map_err(|e| format!("write finished: {e}"))?;

    let th_app = transcript.clone().finalize().to_vec();
    let (master, _) = master_secret(&hs_secret);
    let c_ap = derive_secret(&master, b"c ap traffic", &th_app);
    let s_ap = derive_secret(&master, b"s ap traffic", &th_app);

    Ok(TlsStream {
        sock,
        reader: RecordCipher::new(&s_ap),
        writer: RecordCipher::new(&c_ap),
        plain: Vec::new(),
        eof: false,
    })
}

/// 一条已完成握手的 TLS 1.3 连接。`Read`/`Write` 直接收发应用数据。
pub struct TlsStream {
    sock: TcpStream,
    reader: RecordCipher,
    writer: RecordCipher,
    plain: Vec<u8>,
    eof: bool,
}

impl TlsStream {
    /// 发 close_notify 并断开 TCP。
    pub fn shutdown(&mut self) {
        let mut alert = Vec::new();
        let rec = self.writer.encrypt(&mut alert, 0x15);
        let _ = self.sock.write_all(&rec);
        let _ = self.sock.shutdown(std::net::Shutdown::Both);
    }

    fn fill(&mut self) -> io::Result<()> {
        loop {
            let (ct, body) = match read_record(&mut self.sock) {
                Ok(v) => v,
                Err(_) => {
                    self.eof = true;
                    return Ok(());
                }
            };
            if ct == 0x15 {
                self.eof = true;
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "服务器发来 alert",
                ));
            }
            if ct != 0x17 {
                continue;
            }
            let mut pt = self
                .reader
                .decrypt(&body)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "应用数据解密失败"))?;
            let inner = match pt.pop() {
                Some(t) => t,
                None => continue,
            };
            match inner {
                0x17 => {
                    if !pt.is_empty() {
                        self.plain = pt;
                        return Ok(());
                    }
                }
                0x15 => {
                    self.eof = true;
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "服务器发来 alert",
                    ));
                }
                _ => continue,
            }
        }
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.plain.is_empty() {
            if self.eof {
                return Ok(0);
            }
            self.fill()?;
            if self.plain.is_empty() {
                return Ok(0);
            }
        }
        let n = buf.len().min(self.plain.len());
        buf[..n].copy_from_slice(&self.plain[..n]);
        self.plain.drain(..n);
        Ok(n)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut off = 0usize;
        while off < buf.len() {
            let end = (off + 16000).min(buf.len());
            let mut chunk = buf[off..end].to_vec();
            let rec = self.writer.encrypt(&mut chunk, 0x17);
            self.sock.write_all(&rec)?;
            off = end;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

fn read_record(s: &mut TcpStream) -> Result<(u8, Vec<u8>), String> {
    let mut head = [0u8; 5];
    s.read_exact(&mut head)
        .map_err(|e| format!("read head: {e}"))?;
    let len = u16::from_be_bytes([head[3], head[4]]) as usize;
    let mut body = vec![0u8; len];
    s.read_exact(&mut body)
        .map_err(|e| format!("read body: {e}"))?;
    Ok((head[0], body))
}

fn read_handshake(s: &mut TcpStream) -> Result<(u8, Vec<u8>), String> {
    let (ct, body) = read_record(s)?;
    if ct != 0x16 || body.len() < 4 {
        return Err(format!("期望明文 handshake，收到 ct=0x{ct:02x}"));
    }
    let ty = body[0];
    let len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    Ok((ty, body[4..4 + len].to_vec()))
}

fn handshake_msg(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(body.len() + 4);
    v.push(ty);
    v.extend_from_slice(&[
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ]);
    v.extend_from_slice(body);
    v
}

fn server_hello_message(body: &[u8]) -> Vec<u8> {
    handshake_msg(2, body)
}

struct ServerHello {
    version: u16,
    cipher: u16,
    kex_group: Option<u16>,
    kex_share: Vec<u8>,
}

fn parse_server_hello(b: &[u8]) -> Result<ServerHello, String> {
    let version = u16::from_be_bytes([b[0], b[1]]);
    let mut i = 2 + 32;
    let sid = b[i] as usize;
    i += 1 + sid;
    let cipher = u16::from_be_bytes([b[i], b[i + 1]]);
    i += 2;
    i += 1; // compression
    let ext_len = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
    i += 2;
    let end = i + ext_len;
    let mut kex_group = None;
    let mut kex_share = Vec::new();
    while i + 4 <= end {
        let ty = u16::from_be_bytes([b[i], b[i + 1]]);
        let len = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
        let body = &b[i + 4..i + 4 + len];
        if ty == 51 && body.len() >= 4 {
            kex_group = Some(u16::from_be_bytes([body[0], body[1]]));
            let sl = u16::from_be_bytes([body[2], body[3]]) as usize;
            kex_share = body[4..4 + sl].to_vec();
        }
        i += 4 + len;
    }
    Ok(ServerHello {
        version,
        cipher,
        kex_group,
        kex_share,
    })
}

// ---------------- 密钥编排 ----------------

fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(label.len() + context.len() + 8);
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((label.len() + 6) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    // secret 已经是 PRK（Extract 的产物），必须用 from_prk；
    // 用 Hkdf::new 会再 extract 一次，密钥全错（这就是之前解不开的原因）。
    let hk = Hkdf::<Sha256>::from_prk(secret).expect("prk");
    let mut out = vec![0u8; len];
    hk.expand(&info, &mut out).expect("hkdf expand");
    out
}

fn derive_secret(secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    hkdf_expand_label(secret, label, transcript_hash, 32)
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    // TLS 1.3 的 Extract 就是 HMAC(salt, ikm)，直接算，别绕 Hkdf。
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("hmac key");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

fn empty_hash() -> Vec<u8> {
    Sha256::digest([]).to_vec()
}

fn handshake_secret(shared: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let zeros = [0u8; 32];
    let early = hkdf_extract(&zeros, &zeros);
    let derived = derive_secret(&early, b"derived", &empty_hash());
    let hs = hkdf_extract(&derived, shared);
    (hs, derived)
}

fn master_secret(hs_secret: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let zeros = [0u8; 32];
    let derived = derive_secret(hs_secret, b"derived", &empty_hash());
    let master = hkdf_extract(&derived, &zeros);
    (master, derived)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

struct RecordCipher {
    cipher: Aes128Gcm,
    iv: [u8; 12],
    seq: u64,
}

impl RecordCipher {
    fn new_at(traffic_secret: &[u8], seq: u64) -> Self {
        let mut c = Self::new(traffic_secret);
        c.seq = seq;
        c
    }

    fn new(traffic_secret: &[u8]) -> Self {
        let key = hkdf_expand_label(traffic_secret, b"key", b"", 16);
        let iv = hkdf_expand_label(traffic_secret, b"iv", b"", 12);
        Self {
            cipher: Aes128Gcm::new_from_slice(&key).expect("aes key"),
            iv: iv.try_into().expect("iv len"),
            seq: 0,
        }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let seq = self.seq.to_be_bytes();
        for (i, b) in seq.iter().enumerate() {
            n[4 + i] ^= b;
        }
        n
    }

    /// `plain` 末尾会补上内层内容类型字节；入参是「内容 + 类型」。
    fn encrypt(&mut self, content: &mut Vec<u8>, inner_type: u8) -> Vec<u8> {
        content.push(inner_type);
        // AAD 就是记录头，长度字段必须是**密文长度**（明文 + 16 字节 tag）。
        // 之前这里写死 0x0000，服务端一验 AEAD 就报 decode_error。
        let ct_len = (content.len() + 16) as u16;
        let mut aad = [0x17u8, 0x03, 0x03, 0x00, 0x00];
        aad[3..5].copy_from_slice(&ct_len.to_be_bytes());
        let nonce = self.nonce();
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: content,
                    aad: &aad,
                },
            )
            .expect("encrypt");
        self.seq += 1;
        let mut rec = Vec::with_capacity(ct.len() + 5);
        rec.push(0x17);
        rec.extend_from_slice(&[0x03, 0x03]);
        rec.extend_from_slice(&(ct.len() as u16).to_be_bytes());
        rec.extend_from_slice(&ct);
        rec
    }

    fn decrypt(&mut self, ct: &[u8]) -> Result<Vec<u8>, ()> {
        if ct.len() < 17 {
            return Err(());
        }
        let mut aad = [0x17u8, 0x03, 0x03, 0x00, 0x00];
        aad[3..5].copy_from_slice(&(ct.len() as u16).to_be_bytes());
        let nonce = self.nonce();
        let pt = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload { msg: ct, aad: &aad },
            )
            .map_err(|_| ())?;
        self.seq += 1;
        Ok(pt)
    }
}

/// 官方客户端的 ID 算法：current = (毫秒 << 12 | 1) 取低 48 位；
/// session 用补码（降序），request 用原值（升序）；12 位 hex + 14 位随机尾。
fn oc_id(prefix: &str, descending: bool) -> String {
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let current = (ms << 12 | 1) & 0xffff_ffff_ffff;
    let v = if descending {
        !current & 0xffff_ffff_ffff
    } else {
        current
    };
    let mut out = format!("{prefix}{v:012x}");
    let mut seed = ms ^ (current.rotate_left(17));
    for _ in 0..14 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push(CHARS[(seed >> 33) as usize % 62] as char);
    }
    out
}

fn parse_certificate(body: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    // TLS 1.3 Certificate: context(1) + listlen(3) + [ certlen(3) + cert + extlen(2) + ext ]
    if body.len() < 4 {
        return Err("Certificate 太短".into());
    }
    let ctx_len = body[0] as usize;
    let mut i = 1 + ctx_len;
    let list_len =
        ((body[i] as usize) << 16) | ((body[i + 1] as usize) << 8) | body[i + 2] as usize;
    i += 3;
    let end = i + list_len;
    let mut out = Vec::new();
    while i + 3 <= end {
        let len = ((body[i] as usize) << 16) | ((body[i + 1] as usize) << 8) | body[i + 2] as usize;
        i += 3;
        if i + len > end {
            return Err("证书长度越界".into());
        }
        out.push(body[i..i + len].to_vec());
        i += len;
        if i + 2 > end {
            break;
        }
        let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2 + ext_len;
    }
    Ok(out)
}

fn parse_certificate_verify(body: &[u8]) -> Result<(u16, Vec<u8>), String> {
    if body.len() < 4 {
        return Err("CertificateVerify 太短".into());
    }
    let scheme = u16::from_be_bytes([body[0], body[1]]);
    let len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if 4 + len > body.len() {
        return Err("签名长度越界".into());
    }
    Ok((scheme, body[4..4 + len].to_vec()))
}

fn verify_peer(
    host: &str,
    chain: &[Vec<u8>],
    (scheme, sig): (u16, Vec<u8>),
    th_before_cv: Option<Vec<u8>>,
) -> Result<(), String> {
    use rustls_pki_types::{CertificateDer, ServerName, SignatureVerificationAlgorithm, UnixTime};

    if chain.is_empty() {
        return Err("服务端没给证书".into());
    }
    let leaf = CertificateDer::from(chain[0].clone());
    let intermediates: Vec<CertificateDer<'static>> = chain[1..]
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect();
    // webpki-roots 直接给的就是 pki-types 的 TrustAnchor，不需要再转换。
    let anchors: &[rustls_pki_types::TrustAnchor<'static>] = webpki_roots::TLS_SERVER_ROOTS;

    let cert = webpki::EndEntityCert::try_from(&leaf).map_err(|e| format!("解析叶子证书: {e}"))?;
    cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        anchors,
        &intermediates,
        UnixTime::now(),
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(|e| format!("证书链校验失败: {e}"))?;

    let name = ServerName::try_from(host.to_string()).map_err(|_| "非法主机名".to_string())?;
    cert.verify_is_valid_for_subject_name(&name)
        .map_err(|e| format!("主机名不匹配: {e}"))?;

    // 直接在这里选算法，避免 `Option<&'static dyn Trait>` 那条路径
    // （rustc 1.95 在 resolver lowering 阶段会 ICE）。
    let alg: &dyn SignatureVerificationAlgorithm = match scheme {
        0x0403 => webpki::ring::ECDSA_P256_SHA256,
        0x0503 => webpki::ring::ECDSA_P384_SHA384,
        0x0804 => webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        0x0805 => webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        0x0806 => webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        0x0401 => webpki::ring::RSA_PKCS1_2048_8192_SHA256,
        0x0501 => webpki::ring::RSA_PKCS1_2048_8192_SHA384,
        0x0601 => webpki::ring::RSA_PKCS1_2048_8192_SHA512,
        0x0807 => webpki::ring::ED25519,
        other => return Err(format!("不支持的签名算法 0x{other:04x}")),
    };

    let th = th_before_cv.ok_or("缺少 Certificate 之后的 transcript")?;
    let mut msg = vec![0x20u8; 64];
    msg.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    msg.push(0);
    msg.extend_from_slice(&th);
    cert.verify_signature(alg, &msg, &sig)
        .map_err(|e| format!("CertificateVerify 验签失败: {e}"))?;
    Ok(())
}
