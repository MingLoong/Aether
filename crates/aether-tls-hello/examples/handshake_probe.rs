//! M2 探针：用 `aether_tls_hello` 造出的 ClientHello 完成一次 TLS 1.3 握手，
//! 然后发一个 HTTP/1.1 请求，把响应行打出来。
//!
//! 目的：证明「我们自己发的这条 hello 能被真实服务器接受，且后续握手能走通」。
//! 这不是生产实现 —— 证书链没有校验（PoC 阶段），只验证协议正确性。
//!
//! 运行：
//!     cargo run -p aether-tls-hello --example handshake_probe -- opencode.ai 443
//!
//! 预期输出里有 `HTTP/1.1 <status>`：200（模型列表）/401/403/429 都说明
//! TLS 层与 HTTP 层都通了，差异只在上游策略。

use std::io::{Read, Write};
use std::net::TcpStream;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use aether_tls_hello::{build_client_hello, HelloInputs};

type HmacSha256 = Hmac<Sha256>;

fn main() {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "opencode.ai".into());
    let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(443);
    let path = args.next().unwrap_or_else(|| "/inference/v1/models".into());
    let body = args.next();

    match run(&host, port, &path, body.as_deref()) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("FAILED: {e}");
            std::process::exit(1);
        }
    }
}

fn run(host: &str, port: u16, path: &str, body_file: Option<&str>) -> Result<(), String> {
    // ---- 1. 生成 key_share 材料 ----
    let mut rng = rand::rngs::OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    let ek_bytes = ek.as_bytes();
    let (_ct, mlkem_ss) = ek
        .encapsulate(&mut rng)
        .map_err(|_| "ml-kem encapsulate 失败".to_string())?;
    let _ = dk; // 服务端回 ct 后才需要，先留引用

    let x_secret = StaticSecret::random_from_rng(rng);
    let x_public = PublicKey::from(&x_secret);

    // group 4588 的 client_share = ML-KEM ek(1184) || X25519 pk(32)
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

    // ---- 2. 发送 ClientHello ----
    let mut stream = TcpStream::connect((host, port)).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .ok();
    stream
        .write_all(&hello)
        .map_err(|e| format!("write: {e}"))?;

    // ---- 3. 读 ServerHello ----
    let (hs_type, sh_body) = read_handshake(&mut stream)?;
    if hs_type != 2 {
        return Err(format!("期望 ServerHello(2)，收到 {hs_type}"));
    }
    let sh = parse_server_hello(&sh_body)?;
    println!(
        "ServerHello: cipher=0x{:04x} version=0x{:04x} kex_group={:?} share_len={}",
        sh.cipher,
        sh.version,
        sh.kex_group,
        sh.kex_share.len()
    );
    let group = sh.kex_group.ok_or("ServerHello 没有 key_share")?;
    let (ss_mlkem, ss_x): (Option<Vec<u8>>, Vec<u8>) = match group {
        4588 => {
            if sh.kex_share.len() != 1120 {
                return Err(format!("4588 的 share 长度 {} ≠ 1120", sh.kex_share.len()));
            }
            let server_x = &sh.kex_share[1088..];
            let server_pub = PublicKey::from(<[u8; 32]>::try_from(server_x).unwrap());
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
                return Err(format!("29 的 share 长度 {} ≠ 32", sh.kex_share.len()));
            }
            let server_pub = PublicKey::from(<[u8; 32]>::try_from(&sh.kex_share[..]).unwrap());
            let ss = x_secret.diffie_hellman(&server_pub).as_bytes().to_vec();
            (None, ss)
        }
        other => return Err(format!("不支持的 group {other}")),
    };

    // ---- 4'. 共享密钥候选（4588 = ML-KEM‖X25519 或反向；29 = 纯 X25519）----
    let _ = mlkem_ss;

    // ---- 5. TLS 1.3 key schedule ----
    let mut transcript = Sha256::new();
    // 握手 transcript 只包含 handshake 消息（type+len+body），不含 5 字节 record 头
    transcript.update(&hello[5..]);
    transcript.update(server_hello_message(&sh_body));

    let th_sh = transcript.clone().finalize().to_vec();

    // 共享密钥的拼接顺序（ML-KEM||X25519 vs X25519||ML-KEM）各实现有过分歧。
    // 与其猜，不如拿第一条加密记录做试验：谁能解开就用谁。
    let mut candidates: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(mk) = ss_mlkem.as_ref() {
        let mut a = Vec::with_capacity(64);
        a.extend_from_slice(mk);
        a.extend_from_slice(&ss_x);
        candidates.push(("ML-KEM||X25519".into(), a));
        let mut b = Vec::with_capacity(64);
        b.extend_from_slice(&ss_x);
        b.extend_from_slice(mk);
        candidates.push(("X25519||ML-KEM".into(), b));
    } else {
        candidates.push(("X25519".into(), ss_x.clone()));
    }

    // 跳过 change_cipher_spec，读第一条加密记录（不消耗解密器状态）
    let first_payload = loop {
        let (ctt, payload) = read_record(&mut stream)?;
        if ctt == 0x14 {
            continue;
        }
        if ctt != 0x17 {
            return Err(format!("期望加密记录(0x17)，收到 0x{ctt:02x}"));
        }
        break payload;
    };

    let mut hs_secret = Vec::new();
    let mut s_hs = Vec::new();
    let mut c_hs = Vec::new();
    let mut first_plain: Option<Vec<u8>> = None;
    for (name, cand) in candidates.iter() {
        let (hs, _) = handshake_secret(cand);
        let s = derive_secret(&hs, b"s hs traffic", &th_sh);
        let mut probe = RecordCipher::new(&s);
        if let Ok(pt) = probe.decrypt(&first_payload) {
            println!("共享密钥顺序: {name}");
            c_hs = derive_secret(&hs, b"c hs traffic", &th_sh);
            hs_secret = hs;
            s_hs = s;
            first_plain = Some(pt);
            break;
        }
    }
    let first_plain = first_plain.ok_or("服务端握手记录解密失败（两种拼接顺序都不对）")?;

    // 第一条加密记录已经被试探解密消耗掉 seq=0，续读必须从 seq=1 开始，
    // 否则「握手消息被拆成多条记录」时会错位一条。
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
            let (content_type, payload) = read_record(&mut stream)?;
            if content_type == 0x14 {
                continue; // change_cipher_spec
            }
            if content_type != 0x17 {
                return Err(format!("期望加密记录(0x17)，收到 0x{content_type:02x}"));
            }
            let plain = s_hs_reader
                .decrypt(&payload)
                .map_err(|_| "服务端握手记录解密失败".to_string())?;
            hs_buf.extend_from_slice(&plain);
        }

        loop {
            if hs_buf.len() < 4 {
                break;
            }
            let ty = hs_buf[0];
            let len =
                ((hs_buf[1] as usize) << 16) | ((hs_buf[2] as usize) << 8) | hs_buf[3] as usize;
            if hs_buf.len() < 4 + len {
                break;
            }
            let msg: Vec<u8> = hs_buf.drain(..4 + len).collect();
            let body = &msg[4..];
            match ty {
                8 => println!("  EncryptedExtensions"),
                11 => {
                    cert_chain = parse_certificate(body)?;
                    println!("  Certificate（{} 张）", cert_chain.len());
                }
                15 => {
                    th_before_cv = Some(transcript.clone().finalize().to_vec());
                    cert_verify = parse_certificate_verify(body)?;
                    println!("  CertificateVerify（scheme=0x{:04x}）", cert_verify.0);
                }
                20 => {
                    let fin_key = hkdf_expand_label(&s_hs, b"finished", b"", 32);
                    let expect = hmac_sha256(&fin_key, &transcript.clone().finalize());
                    server_finished_ok = expect.as_slice() == body;
                    println!(
                        "  Finished（校验{}）",
                        if server_finished_ok {
                            "通过"
                        } else {
                            "失败"
                        }
                    );
                    transcript.update(&msg);
                }
                other => println!("  未知 handshake {other}"),
            }
            if ty != 20 {
                transcript.update(&msg);
            }
        }
    }

    // ---- 6.5 证书链 + CertificateVerify 验签（安全底线）----
    verify_peer(host, &cert_chain, cert_verify, th_before_cv)?;
    println!("  证书校验：通过（链 + 主机名 + 签名）");

    // ---- 7. 客户端 Finished ----
    let th_cf = transcript.clone().finalize().to_vec();
    let client_fin_key = hkdf_expand_label(&c_hs, b"finished", b"", 32);
    let client_verify = hmac_sha256(&client_fin_key, &th_cf);
    let mut flight = handshake_msg(20, &client_verify);
    let rec = c_hs_writer.encrypt(&mut flight, 0x16);
    stream
        .write_all(&rec)
        .map_err(|e| format!("write finished: {e}"))?;
    // 注意：**不要**把客户端 Finished 加进 transcript 再算应用密钥。
    // RFC 8446 里应用流量密钥的 transcript 只到服务端 Finished 为止；
    // 之前把这条加进去，导致 app 密钥全错、服务端一回应就解不开。

    // ---- 8. 应用数据密钥 + HTTP 请求 ----
    let th_app = transcript.clone().finalize().to_vec();
    let (master, _) = master_secret(&hs_secret);
    let c_ap = derive_secret(&master, b"c ap traffic", &th_app);
    let s_ap = derive_secret(&master, b"s ap traffic", &th_app);
    let mut c_ap_writer = RecordCipher::new(&c_ap);
    let mut s_ap_reader = RecordCipher::new(&s_ap);

    let req = match body_file {
        Some(f) => {
            let body = std::fs::read(f).map_err(|e| format!("读 body 失败: {e}"))?;
            let sid = oc_id("ses_", true);
            let rid = oc_id("msg_", false);
            let head = format!(
                "POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer public\r\nContent-Type: application/json\r\nAccept: */*\r\nUser-Agent: opencode/1.19.4 ai-sdk/provider-utils/4.0.23 runtime/bun/1.4.4\r\nx-opencode-client: cli\r\nx-opencode-project: global\r\nx-opencode-session: {sid}\r\nx-opencode-session-id: {sid}\r\nx-opencode-request: {rid}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            println!("POST body {} 字节", body.len());
            [head.into_bytes(), body].concat()
        }
        None => format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer public\r\nAccept: */*\r\nUser-Agent: opencode/1.19.4\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
    };
    // TLS 1.3 单条记录明文上限 2^14 = 16384 字节。官方 body 32601 字节，
    // 一次性塞进一条记录会被对端按 decode_error 直接断开 —— 必须分片。
    let payload = req;
    let mut off = 0usize;
    while off < payload.len() {
        let end = (off + 16000).min(payload.len());
        let mut chunk = payload[off..end].to_vec();
        let rec = c_ap_writer.encrypt(&mut chunk, 0x17);
        stream
            .write_all(&rec)
            .map_err(|e| format!("write req: {e}"))?;
        off = end;
    }

    let mut out = Vec::new();
    for _ in 0..8 {
        let (ct, body) = match read_record(&mut stream) {
            Ok(v) => v,
            Err(e) => {
                println!("读记录失败: {e}");
                break;
            }
        };
        if ct == 0x15 {
            println!("服务器发来 alert: {:?}", body);
            break;
        }
        if ct != 0x17 {
            println!("非加密记录 ct=0x{ct:02x} len={}", body.len());
            continue;
        }
        match s_ap_reader.decrypt(&body) {
            Ok(mut plain) => {
                if let Some(&ty) = plain.last() {
                    plain.pop();
                    if ty == 0x17 {
                        out.extend_from_slice(&plain);
                        if out.windows(4).any(|w| w == b"\r\n\r\n") && out.len() > 200 {
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                println!(
                    "应用数据解密失败（记录 {} 字节），用握手密钥试探：",
                    body.len()
                );
                let mut hint = String::from("未知");
                for seq in 0..8u64 {
                    let mut c = RecordCipher::new_at(&s_hs, seq);
                    if let Ok(mut pt) = c.decrypt(&body) {
                        if let Some(t) = pt.pop() {
                            hint = format!("inner_type=0x{t:02x} payload={:?}", pt);
                        }
                        break;
                    }
                }
                println!("  {hint}（59=access_denied 51=decrypt_error 47=illegal_parameter 40=handshake_failure）");
                break;
            }
        }
    }
    let text = String::from_utf8_lossy(&out);
    let first_line = text.lines().next().unwrap_or("(空响应)");
    println!("\nHTTP: {first_line}");
    Ok(())
}

// ---------------- TLS 记录层 ----------------

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
