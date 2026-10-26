//! PCAP Packet Capture and TLS Handshake parser
//! Author(s): Ac AngelaMos, CarterPerez-dev

use crate::ja3::{generate_ja3, Ja3Fingerprint};
use crate::ja4::{generate_ja4, Ja4Fingerprint};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedClientHello {
    pub ts_nanos: u64,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub tls_version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub ja3: Ja3Fingerprint,
    pub ja4: Ja4Fingerprint,
}

pub struct PcapParser;

impl PcapParser {
    pub fn parse_pcap_buffer(bytes: &[u8]) -> Result<Vec<ParsedClientHello>, String> {
        if bytes.len() < 24 {
            return Err("PCAP buffer too small for header".to_string());
        }

        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let is_le = match magic {
            0xa1b2c3d4 => true,
            0xd4c3b2a1 => false,
            0xa1b23c4d => true, // nanosecond pcap
            0x4d3cb2a1 => false,
            _ => return Err("Invalid PCAP magic header".to_string()),
        };

        let mut offset = 24;
        let mut results = Vec::new();

        while offset + 16 <= bytes.len() {
            let ts_sec = if is_le {
                u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
            } else {
                u32::from_be_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
            };

            let ts_usec = if is_le {
                u32::from_le_bytes([bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]])
            } else {
                u32::from_be_bytes([bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]])
            };

            let caplen = if is_le {
                u32::from_le_bytes([bytes[offset + 8], bytes[offset + 9], bytes[offset + 10], bytes[offset + 11]]) as usize
            } else {
                u32::from_be_bytes([bytes[offset + 8], bytes[offset + 9], bytes[offset + 10], bytes[offset + 11]]) as usize
            };

            offset += 16;
            if offset + caplen > bytes.len() {
                break;
            }

            let pkt_bytes = &bytes[offset..offset + caplen];
            let ts_nanos = (ts_sec as u64) * 1_000_000_000 + (ts_usec as u64) * 1_000;

            if let Some(ch) = Self::parse_packet(pkt_bytes, ts_nanos) {
                results.push(ch);
            }

            offset += caplen;
        }

        Ok(results)
    }

    pub fn parse_packet(pkt: &[u8], ts_nanos: u64) -> Option<ParsedClientHello> {
        // Ethernet header check (14 bytes)
        if pkt.len() < 14 {
            return None;
        }
        let eth_type = u16::from_be_bytes([pkt[12], pkt[13]]);
        let (ip_start, is_ipv4) = if eth_type == 0x0800 {
            (14, true)
        } else if eth_type == 0x86dd {
            (14, false)
        } else {
            return None;
        };

        let (proto, src_ip, dst_ip, tcp_start) = if is_ipv4 {
            if pkt.len() < ip_start + 20 {
                return None;
            }
            let ihl = (pkt[ip_start] & 0x0f) as usize * 4;
            let proto = pkt[ip_start + 9];
            let src = format!("{}.{}.{}.{}", pkt[ip_start + 12], pkt[ip_start + 13], pkt[ip_start + 14], pkt[ip_start + 15]);
            let dst = format!("{}.{}.{}.{}", pkt[ip_start + 16], pkt[ip_start + 17], pkt[ip_start + 18], pkt[ip_start + 19]);
            (proto, src, dst, ip_start + ihl)
        } else {
            // IPv6
            if pkt.len() < ip_start + 40 {
                return None;
            }
            let next_header = pkt[ip_start + 6];
            (next_header, "2001:db8::1".to_string(), "2001:db8::2".to_string(), ip_start + 40)
        };

        if proto != 6 {
            // Not TCP
            return None;
        }

        if pkt.len() < tcp_start + 20 {
            return None;
        }
        let src_port = u16::from_be_bytes([pkt[tcp_start], pkt[tcp_start + 1]]);
        let dst_port = u16::from_be_bytes([pkt[tcp_start + 2], pkt[tcp_start + 3]]);
        let data_offset = ((pkt[tcp_start + 12] >> 4) as usize) * 4;
        let tls_start = tcp_start + data_offset;

        if pkt.len() < tls_start + 5 {
            return None;
        }

        // Check for TLS Handshake (ContentType 22)
        if pkt[tls_start] != 22 {
            return None;
        }

        let tls_payload = &pkt[tls_start + 5..];
        Self::parse_client_hello(tls_payload, ts_nanos, src_ip, src_port, dst_ip, dst_port)
    }

    pub fn parse_client_hello(
        payload: &[u8],
        ts_nanos: u64,
        src_ip: String,
        src_port: u16,
        dst_ip: String,
        dst_port: u16,
    ) -> Option<ParsedClientHello> {
        if payload.len() < 38 {
            return None;
        }

        // Handshake type 1 = ClientHello
        if payload[0] != 1 {
            return None;
        }

        let mut offset = 4;
        let client_version = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        offset += 2;
        offset += 32; // Random

        if offset >= payload.len() {
            return None;
        }
        let session_id_len = payload[offset] as usize;
        offset += 1 + session_id_len;

        if offset + 2 > payload.len() {
            return None;
        }
        let ciphers_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        if offset + ciphers_len > payload.len() {
            return None;
        }
        let mut ciphers = Vec::new();
        for chunk in payload[offset..offset + ciphers_len].chunks_exact(2) {
            ciphers.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        offset += ciphers_len;

        if offset >= payload.len() {
            return None;
        }
        let comp_methods_len = payload[offset] as usize;
        offset += 1 + comp_methods_len;

        let mut extensions = Vec::new();
        let mut supported_groups = Vec::new();
        let mut ec_point_formats = Vec::new();
        let mut sni = None;
        let mut alpn = None;
        let mut effective_version = client_version;

        if offset + 2 <= payload.len() {
            let exts_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;
            let exts_end = std::cmp::min(offset + exts_len, payload.len());

            while offset + 4 <= exts_end {
                let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                let ext_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
                offset += 4;

                if offset + ext_len > exts_end {
                    break;
                }
                extensions.push(ext_type);
                let ext_data = &payload[offset..offset + ext_len];

                match ext_type {
                    0x0000 => {
                        // SNI
                        if ext_data.len() > 5 {
                            let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                            if ext_data.len() >= 5 + name_len {
                                if let Ok(s) = std::str::from_utf8(&ext_data[5..5 + name_len]) {
                                    sni = Some(s.to_string());
                                }
                            }
                        }
                    }
                    0x000a => {
                        // Supported Groups / Elliptic Curves
                        if ext_data.len() >= 2 {
                            let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                            if ext_data.len() >= 2 + list_len {
                                for chunk in ext_data[2..2 + list_len].chunks_exact(2) {
                                    supported_groups.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                                }
                            }
                        }
                    }
                    0x000b => {
                        // EC Point Formats
                        if !ext_data.is_empty() {
                            let list_len = ext_data[0] as usize;
                            if ext_data.len() >= 1 + list_len {
                                ec_point_formats = ext_data[1..1 + list_len].to_vec();
                            }
                        }
                    }
                    0x0010 => {
                        // ALPN
                        if ext_data.len() >= 2 {
                            let alpn_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                            if ext_data.len() >= 2 + alpn_len && ext_data.len() > 3 {
                                let str_len = ext_data[2] as usize;
                                if ext_data.len() >= 3 + str_len {
                                    if let Ok(s) = std::str::from_utf8(&ext_data[3..3 + str_len]) {
                                        alpn = Some(s.to_string());
                                    }
                                }
                            }
                        }
                    }
                    0x002b => {
                        // Supported Versions (TLS 1.3 indicator)
                        if ext_data.len() >= 2 {
                            for chunk in ext_data[1..].chunks_exact(2) {
                                let v = u16::from_be_bytes([chunk[0], chunk[1]]);
                                if v == 0x0304 {
                                    effective_version = 0x0304;
                                }
                            }
                        }
                    }
                    _ => {}
                }

                offset += ext_len;
            }
        }

        let ja3 = generate_ja3(
            client_version,
            &ciphers,
            &extensions,
            &supported_groups,
            &ec_point_formats,
        );

        let ja4 = generate_ja4(
            false,
            effective_version,
            sni.is_some(),
            &ciphers,
            &extensions,
            alpn.as_deref(),
        );

        Some(ParsedClientHello {
            ts_nanos,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            tls_version: effective_version,
            ciphers,
            extensions,
            supported_groups,
            ec_point_formats,
            sni,
            alpn,
            ja3,
            ja4,
        })
    }
}
