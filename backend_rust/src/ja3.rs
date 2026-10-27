//! JA3 TLS Fingerprinting standard implementation
//! Author(s): receptacle-pot

use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};

/// Check if a 16-bit integer is an RFC 8701 GREASE value
pub fn is_grease(val: u16) -> bool {
    let high = (val >> 8) as u8;
    let low = (val & 0xff) as u8;
    high == low && (high & 0x0f) == 0x0a
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja3Fingerprint {
    pub raw: String,
    pub hash: String,
    pub tls_version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

pub fn generate_ja3(
    tls_version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    supported_groups: &[u16],
    ec_point_formats: &[u8],
) -> Ja3Fingerprint {
    // 1. Filter GREASE values from ciphers, extensions, and groups
    let filtered_ciphers: Vec<u16> = ciphers.iter().copied().filter(|&c| !is_grease(c)).collect();
    let filtered_exts: Vec<u16> = extensions.iter().copied().filter(|&e| !is_grease(e)).collect();
    let filtered_groups: Vec<u16> = supported_groups.iter().copied().filter(|&g| !is_grease(g)).collect();

    // 2. Format components as decimal separated by '-'
    let ciphers_str = filtered_ciphers
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let exts_str = filtered_exts
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let groups_str = filtered_groups
        .iter()
        .map(|g| g.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let ec_str = ec_point_formats
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join("-");

    // 3. Construct canonical comma-separated representation
    let raw = format!(
        "{},{},{},{},{}",
        tls_version, ciphers_str, exts_str, groups_str, ec_str
    );

    // 4. Compute MD5
    let mut hasher = Md5::new();
    hasher.update(raw.as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    Ja3Fingerprint {
        raw,
        hash,
        tls_version,
        ciphers: filtered_ciphers,
        extensions: filtered_exts,
        supported_groups: filtered_groups,
        ec_point_formats: ec_point_formats.to_vec(),
    }
}

pub fn generate_ja3s(tls_version: u16, cipher: u16, extensions: &[u16]) -> (String, String) {
    let filtered_exts: Vec<u16> = extensions.iter().copied().filter(|&e| !is_grease(e)).collect();
    let exts_str = filtered_exts
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let raw = format!("{},{},{}", tls_version, cipher, exts_str);
    let mut hasher = Md5::new();
    hasher.update(raw.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    (raw, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0x5a5a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0000));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn test_ja3_generation() {
        let fp = generate_ja3(
            771,
            &[0x1301, 0x1302, 0x0a0a, 0xc02b],
            &[0x0000, 0x0017, 0x1a1a, 0x000d],
            &[0x001d, 0x0017],
            &[0],
        );
        assert!(!fp.raw.contains("2570")); // 0x0a0a
        assert_eq!(fp.ciphers, vec![0x1301, 0x1302, 0xc02b]);
        assert_eq!(fp.hash.len(), 32);
    }
}
