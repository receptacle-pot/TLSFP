//! Cryptographic contradiction detection and threat scoring engine
//! Author(s): receptacle-pot

use crate::models::AlertRecord;
use crate::pcap::ParsedClientHello;

pub struct AnomalyDetector;

impl AnomalyDetector {
    pub fn evaluate(ch: &ParsedClientHello, user_agent: Option<&str>) -> Vec<AlertRecord> {
        let mut alerts = Vec::new();

        // Rule 1: Browser Spoofing Contradiction
        if let Some(ua) = user_agent {
            let claims_chrome = ua.contains("Chrome") || ua.contains("Chromium");
            let claims_firefox = ua.contains("Firefox");

            // Python urllib / requests fingerprint signature
            let is_python_fp = ch.ja3.hash == "b32309a26951912be7dba376398abc3b" || ch.ja4.part_a.starts_with("t13d0906");
            let is_curl_fp = ch.ja3.hash == "72c03e839e9275150a501a37c154316d";

            if (claims_chrome || claims_firefox) && (is_python_fp || is_curl_fp) {
                alerts.push(AlertRecord {
                    id: Some(format!("alt-{}", ch.ts_nanos)),
                    ts_nanos: ch.ts_nanos,
                    rule: "BROWSER_SPOOFING_CONTRADICTION".to_string(),
                    severity: "critical".to_string(),
                    ip: Some(format!("{}:{}", ch.src_ip, ch.src_port)),
                    fp_kind: Some("ja4".to_string()),
                    fp_value: Some(ch.ja4.hash.clone()),
                    title: "Deceptive Client: User-Agent Spoofing Detected".to_string(),
                    detail: format!(
                        "HTTP User-Agent claims browser identity ({}) while TLS cryptographic cipher ordering matches automated script stack ({}).",
                        if claims_chrome { "Chrome" } else { "Firefox" },
                        if is_python_fp { "Python/Urllib3" } else { "cURL" }
                    ),
                    score: Some(95),
                    evidence: Some(format!("Claimed: {} | Observed JA3: {} | JA4: {}", ua, ch.ja3.hash, ch.ja4.hash)),
                    investigation_steps: Some(vec![
                        "Investigate originating IP for scraping or automated credential stuffing".to_string(),
                        "Check web application firewall (WAF) logs for abnormal request pacing".to_string(),
                    ]),
                });
            }
        }

        // Rule 2: Sliver / Cobalt Strike C2 Implant Profile
        if ch.ja3.hash == "6520d624a91943c2c525b6a715f5d62d" || ch.ja4.hash == "t12i1207h1_c61b0388910b_9f4304859a11" {
            alerts.push(AlertRecord {
                id: Some(format!("alt-{}", ch.ts_nanos)),
                ts_nanos: ch.ts_nanos,
                rule: "THREAT_INTEL_MALWARE_MATCH".to_string(),
                severity: "critical".to_string(),
                ip: Some(format!("{}:{}", ch.src_ip, ch.src_port)),
                fp_kind: Some("ja3".to_string()),
                fp_value: Some(ch.ja3.hash.clone()),
                title: "Known C2 Implant Beacon Handshake (Sliver Framework)".to_string(),
                detail: "Fingerprint exactly matches verified Sliver C2 implant beaconing configuration from Abuse.ch threat feed.".to_string(),
                score: Some(98),
                evidence: Some(format!("Target: {}:{} | SNI: {:?} | JA3: {}", ch.dst_ip, ch.dst_port, ch.sni, ch.ja3.hash)),
                investigation_steps: Some(vec![
                    "Isolate host immediately from internal network".to_string(),
                    "Collect volatile RAM dump and examine running process memory".to_string(),
                ]),
            });
        }

        // Rule 3: Deprecated Protocol Negotiation (TLS 1.0/1.1)
        if ch.tls_version == 0x0301 || ch.tls_version == 0x0302 {
            alerts.push(AlertRecord {
                id: Some(format!("alt-{}", ch.ts_nanos)),
                ts_nanos: ch.ts_nanos,
                rule: "DEPRECATED_CIPHER_WEAKNESS".to_string(),
                severity: "low".to_string(),
                ip: Some(format!("{}:{}", ch.src_ip, ch.src_port)),
                fp_kind: Some("ja3".to_string()),
                fp_value: Some(ch.ja3.hash.clone()),
                title: "Obsolete TLS Version Negotiated".to_string(),
                detail: format!("Client initiated handshake using deprecated protocol version 0x{:04x}.", ch.tls_version),
                score: Some(40),
                evidence: Some(format!("Version: 0x{:04x}", ch.tls_version)),
                investigation_steps: Some(vec![
                    "Identify legacy client machine and plan TLS 1.3 protocol upgrade".to_string(),
                ]),
            });
        }

        alerts
    }
}
