//! JA4 TLS Client Fingerprinting (FoxIO Standard)
//! Implementation adhering to FoxIO JA4 specification
//! Author(s): Ac AngelaMos, CarterPerez-dev

use crate::ja3::is_grease;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja4Fingerprint {
    pub raw: String,
    pub hash: String,
    pub part_a: String,
    pub part_b: String,
    pub part_c: String,
}

pub fn format_tls_version(ver: u16) -> &'static str {
    match ver {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

pub fn format_alpn(alpn: Option<&str>) -> String {
    match alpn {
        Some(s) if !s.is_empty() => {
            let first = s.chars().next().unwrap();
            let last = s.chars().last().unwrap();
            format!("{}{}", first, last)
        }
        _ => "00".to_string(),
    }
}

pub fn generate_ja4(
    is_quic: bool,
    tls_version: u16,
    has_sni: bool,
    ciphers: &[u16],
    extensions: &[u16],
    alpn: Option<&str>,
) -> Ja4Fingerprint {
    let proto = if is_quic { 'q' } else { 't' };
    let ver_str = format_tls_version(tls_version);
    let sni_char = if has_sni { 'd' } else { 'i' };

    // Filter GREASE
    let filtered_ciphers: Vec<u16> = ciphers.iter().copied().filter(|&c| !is_grease(c)).collect();

    // Filter GREASE, SNI (0x0000), and ALPN (0x0010) for JA4 extension count
    let filtered_exts: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|&e| !is_grease(e) && e != 0x0000 && e != 0x0010)
        .collect();

    let num_ciphers = std::cmp::min(filtered_ciphers.len(), 99);
    let num_exts = std::cmp::min(filtered_exts.len(), 99);
    let alpn_chars = format_alpn(alpn);

    // Part A: [t|q][version][d|i][ciphers_2_digits][exts_2_digits][alpn_2_chars]
    let part_a = format!(
        "{}{}{}{:02}{:02}{}",
        proto, ver_str, sni_char, num_ciphers, num_exts, alpn_chars
    );

    // Part B: Sorted ciphers in 4-hex lowercase, sha256 truncated to 12 chars
    let mut hex_ciphers: Vec<String> = filtered_ciphers
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect();
    hex_ciphers.sort();
    let b_joined = hex_ciphers.join("");
    let part_b = if b_joined.is_empty() {
        "000000000000".to_string()
    } else {
        let mut hasher = Sha256::new();
        hasher.update(b_joined.as_bytes());
        let res = hex::encode(hasher.finalize());
        res[..12].to_string()
    };

    // Part C: Sorted extensions in 4-hex lowercase, sha256 truncated to 12 chars
    let mut hex_exts: Vec<String> = filtered_exts
        .iter()
        .map(|e| format!("{:04x}", e))
        .collect();
    hex_exts.sort();
    let c_joined = hex_exts.join("");
    let part_c = if c_joined.is_empty() {
        "000000000000".to_string()
    } else {
        let mut hasher = Sha256::new();
        hasher.update(c_joined.as_bytes());
        let res = hex::encode(hasher.finalize());
        res[..12].to_string()
    };

    let hash = format!("{}_{}_{}", part_a, part_b, part_c);
    let raw = format!("{}_{}_{}", part_a, b_joined, c_joined);

    Ja4Fingerprint {
        raw,
        hash,
        part_a,
        part_b,
        part_c,
    }
}

pub fn generate_ja4s(
    tls_version: u16,
    cipher: u16,
    extensions: &[u16],
    alpn: Option<&str>,
) -> String {
    let ver_str = format_tls_version(tls_version);
    let filtered_exts: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|&e| !is_grease(e) && e != 0x0000 && e != 0x0010)
        .collect();

    let num_exts = std::cmp::min(filtered_exts.len(), 99);
    let alpn_chars = format_alpn(alpn);
    let part_a = format!("t{}{:02}{}", ver_str, num_exts, alpn_chars);
    let cipher_hex = format!("{:04x}", cipher);

    let mut hex_exts: Vec<String> = filtered_exts.iter().map(|e| format!("{:04x}", e)).collect();
    hex_exts.sort();
    let c_joined = hex_exts.join("");
    let part_c = if c_joined.is_empty() {
        "000000000000".to_string()
    } else {
        let mut hasher = Sha256::new();
        hasher.update(c_joined.as_bytes());
        let res = hex::encode(hasher.finalize());
        res[..12].to_string()
    };

    format!("{}_{}_{}", part_a, cipher_hex, part_c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ja4_structure() {
        let fp = generate_ja4(
            false,
            0x0304,
            true,
            &[0x1301, 0x1302, 0x1303, 0x0a0a],
            &[0x0000, 0x0017, 0x000d, 0x0010, 0x1a1a],
            Some("h2"),
        );

        assert_eq!(&fp.part_a[0..1], "t");
        assert_eq!(&fp.part_a[1..3], "13");
        assert_eq!(&fp.part_a[3..4], "d");
        assert_eq!(&fp.part_a[4..6], "03"); // 3 ciphers without GREASE
        assert_eq!(&fp.part_a[6..8], "02"); // 2 exts without GREASE, SNI, ALPN
        assert_eq!(&fp.part_a[8..10], "h2");
        assert_eq!(fp.part_b.len(), 12);
        assert_eq!(fp.part_c.len(), 12);
    }
}
