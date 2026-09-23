//! OpenCode session id and client-version helpers.
//!
//! Session ids follow the official OpenCode client shape:
//! `ses_` + 12 lowercase hex digits + 14 `[A-Za-z0-9]` digits.  The upstream
//! free-tier fingerprint check rejects ids that do not match this shape with
//! `403 FreeTierError`.

use std::sync::atomic::{AtomicU64, Ordering};

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

const ALNUM_CHARS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Generates an official-shape OpenCode session id.
pub fn new_session_id() -> String {
    let mut bytes = [0u8; 26];
    fill_random(&mut bytes);
    // First 12 bytes must be lowercase hex digits.
    for byte in &mut bytes[..12] {
        *byte = b"0123456789abcdef"[(*byte as usize) % 16];
    }
    // Remaining 14 bytes must be `[A-Za-z0-9]`.
    for byte in &mut bytes[12..] {
        *byte = ALNUM_CHARS[*byte as usize % ALNUM_CHARS.len()];
    }
    format!("ses_{}", String::from_utf8_lossy(&bytes))
}

fn fill_random(bytes: &mut [u8]) {
    // Prefer OS CSPRNG.  Fall back to a time/counter mix when unavailable.
    let mut filled = false;
    #[cfg(feature = "std")]
    {
        use std::io::Read;
        if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
            filled = file.read_exact(bytes).is_ok();
        }
    }
    if !filled {
        let counter = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut seed = now ^ (counter.wrapping_mul(0x9e3779b97f4a7c15));
        let mut state = seed;
        for byte in bytes.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state & 0xff) as u8;
            seed = seed.wrapping_add(0x9e3779b97f4a7c15);
            state ^= seed;
        }
    }
}

/// Compares two dotted-decimal client versions.
///
/// Returns a negative value when `left < right`, zero when equal, and a
/// positive value when `left > right`.  Non-numeric components are treated
/// as zero, so `1.17.0` and `1.17` compare equal.
pub fn compare_client_version(left: &str, right: &str) -> i32 {
    let left_parts = version_parts(left);
    let right_parts = version_parts(right);
    for index in 0..3 {
        let left_value = left_parts[index];
        let right_value = right_parts[index];
        if left_value < right_value {
            return -1;
        }
        if left_value > right_value {
            return 1;
        }
    }
    0
}

fn version_parts(version: &str) -> [u32; 3] {
    let mut parts = [0u32; 3];
    for (index, part) in version.split('.').take(3).enumerate() {
        parts[index] = part
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .unwrap_or(0);
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions() {
        assert_eq!(compare_client_version("1.17.0", "1.17.0"), 0);
        assert_eq!(compare_client_version("1.17.0", "1.16.9"), 1);
        assert_eq!(compare_client_version("1.16.9", "1.17.0"), -1);
        assert_eq!(compare_client_version("1.17", "1.17.0"), 0);
        assert_eq!(compare_client_version("2.0.0", "1.99.99"), 1);
        assert_eq!(compare_client_version("", "0.0.0"), 0);
    }

    #[test]
    fn session_ids_are_different_and_shape_valid() {
        let a = new_session_id();
        let b = new_session_id();
        assert_ne!(a, b);
        for id in [&a, &b] {
            assert!(id.starts_with("ses_"));
            assert_eq!(id.len(), 30);
            let rest = &id[4..];
            assert!(rest.chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }
}
