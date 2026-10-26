const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3000;
const API_PORT = 3001;
const SITE_DIR = path.resolve(__dirname, '../site');

// MIME types table
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf',
  '.webmanifest': 'application/manifest+json',
};

// Database seed data matching exact Zod enums:
// category: 'malware' | 'c2' | 'tool' | 'benign' | 'os' | 'unknown'
// rules: 'known_bad' | 'ua_mismatch' | 'os_mismatch' | 'first_seen' | 'fp_rotation' | 'monoculture'
// severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
// verdict: 'malicious' | 'suspicious' | 'benign' | 'unknown'
// strength: 'exact' | 'cipher_and_prefix' | 'cipher_only'

let intelSources = [
  { name: 'Abuse.ch SSLBL (Malicious SSL Blacklist)', kind: 'threat_intel', license: 'CC0-1.0', records: 4892 },
  { name: 'FoxIO JA4 Database (Curated Standards)', kind: 'curated_standard', license: 'FoxIO-Open', records: 12410 },
  { name: 'Salesforce JA3 Fingerprint Feed', kind: 'community_feed', license: 'BSD-3-Clause', records: 8930 },
  { name: 'CISA Known Exploited C2 Hashes', kind: 'government_advisory', license: 'Public Domain', records: 1845 },
  { name: 'Trident Automated Scanner Profiles', kind: 'research_cluster', license: 'MIT', records: 3720 },
];

let intelCategories = [
  { category: 'benign', records: 11420 },
  { category: 'malware', records: 6415 },
  { category: 'c2', records: 4890 },
  { category: 'tool', records: 4210 },
  { category: 'os', records: 2840 },
  { category: 'unknown', records: 1022 },
];

let liveIntelTotal = 31797;
let liveAlertsTotal = 399;

let alertsByRule = [
  { rule: 'ua_mismatch', count: 184 },
  { rule: 'known_bad', count: 96 },
  { rule: 'os_mismatch', count: 54 },
  { rule: 'first_seen', count: 32 },
  { rule: 'fp_rotation', count: 21 },
  { rule: 'monoculture', count: 12 },
];

let alertsLedger = [
  {
    ts_nanos: (Date.now() - 14000) * 1_000_000,
    rule: 'ua_mismatch',
    severity: 'critical',
    ip: '192.168.1.144:54210',
    fp_kind: 'ja4',
    fp_value: 't13d090600_e4465b746c05_000000000000',
    title: 'the user-agent is lying',
    detail: 'HTTP User-Agent claimed Mac Chrome 129.0, but cipher suite and extension vector are identical to standard Python Requests/urllib3 stack. Handshake lacks GREASE and TLS 1.3 key_share.',
    score: 94,
  },
  {
    ts_nanos: (Date.now() - 48000) * 1_000_000,
    rule: 'known_bad',
    severity: 'critical',
    ip: '192.168.1.202:49811',
    fp_kind: 'ja3',
    fp_value: '6520d624a91943c2c525b6a715f5d62d',
    title: 'known-bad fingerprint',
    detail: 'Client TLS fingerprint exactly matches Sliver Framework implant beaconing profile catalogued by Abuse.ch. Handshake targets external host on TCP port 443 with raw IP SNI.',
    score: 98,
  },
  {
    ts_nanos: (Date.now() - 120000) * 1_000_000,
    rule: 'os_mismatch',
    severity: 'medium',
    ip: '192.168.1.89:60122',
    fp_kind: 'ja4',
    fp_value: 't13d1516h2_8daaf6152771_e562703ab854',
    title: 'the stack betrays the os',
    detail: 'TCP window size and TTL indicate Linux kernel, but TLS ClientHello extensions and cipher permutations mimic Windows 11 Edge browser.',
    score: 65,
  },
  {
    ts_nanos: (Date.now() - 240000) * 1_000_000,
    rule: 'first_seen',
    severity: 'low',
    ip: '192.168.1.55:42100',
    fp_kind: 'ja4',
    fp_value: 't13d1209h2_3a91bf2049e1_88dca0194821',
    title: 'first sighting',
    detail: 'Unobserved cryptographic permutation recorded across the perimeter for the first time.',
    score: 30,
  },
];

let corpusItems = [
  // --- JA3 (ClientHello MD5) ---
  {
    kind: 'ja3',
    value: 'cd08e31494f9531f560d64cfa3f2233f',
    label: 'Chrome 129 / macOS Sequoia',
    category: 'benign',
    source: 'FoxIO JA4 Database',
    reference: 'RFC 8701 GREASE / TLS 1.3',
  },
  {
    kind: 'ja3',
    value: '277ddab680190bbd4691799797d3aa33',
    label: 'Mozilla Firefox 131.0 Quantum',
    category: 'benign',
    source: 'Salesforce Repository',
    reference: 'NSS Cryptographic Engine',
  },
  {
    kind: 'ja3',
    value: '3b5074b1b9d03222b91f0cbe7cf827f3',
    label: 'Apple Safari 18.0 / iOS 18',
    category: 'benign',
    source: 'Apple SecChannel Feed',
    reference: 'TLS 1.3 with ALPN h2',
  },
  {
    kind: 'ja3',
    value: 'bb481404196da2132381254399723ec0',
    label: 'Microsoft Edge 129 / Windows 11',
    category: 'benign',
    source: 'Microsoft Security Intelligence',
    reference: 'Chromium engine with MS cipher ordering',
  },
  {
    kind: 'ja3',
    value: 'b32309a26951912be7dba376398abc3b',
    label: 'Python urllib3 / Requests 2.32',
    category: 'tool',
    source: 'Abuse.ch Automation Cluster',
    reference: 'Default OpenSSL Context',
  },
  {
    kind: 'ja3',
    value: '57919782613c6395b0fe66f4cb3ed564',
    label: 'Go-http-client 1.23 standard library',
    category: 'tool',
    source: 'Salesforce JA3 Feed',
    reference: 'Go standard library crypto/tls',
  },
  {
    kind: 'ja3',
    value: '72c03e839e9275150a501a37c154316d',
    label: 'cURL 8.10 (OpenSSL backend)',
    category: 'tool',
    source: 'Trident Fingerprint Lab',
    reference: 'CLI utility with HTTP/2 support',
  },
  {
    kind: 'ja3',
    value: '15af977ce25de4d75b080321406ed8f9',
    label: 'Node.js Undici / Axios HTTP Client',
    category: 'tool',
    source: 'Node TLS Fingerprint Baseline',
    reference: 'V8 TLS client session',
  },
  {
    kind: 'ja3',
    value: '6520d624a91943c2c525b6a715f5d62d',
    label: 'Sliver C2 Implant (Go TLS Engine)',
    category: 'c2',
    source: 'Abuse.ch SSLBL Verified',
    reference: 'MITRE ATT&CK T1071.001',
  },
  {
    kind: 'ja3',
    value: 'a0e9f5d64349fb13191bc781f81f42e1',
    label: 'Cobalt Strike 4.9 Beacon HTTPS',
    category: 'c2',
    source: 'CISA Threat Advisory AA23-242A',
    reference: 'Malleable C2 HTTPS Profile',
  },
  {
    kind: 'ja3',
    value: 'e7d705a3286e19ea42f587b344ee6865',
    label: 'Metasploit Meterpreter Reverse HTTPS',
    category: 'c2',
    source: 'Rapid7 Fingerprint Index',
    reference: 'Reverse staging TLS payload',
  },
  {
    kind: 'ja3',
    value: '4d7a28d6f22da2dee03515373f0760eb',
    label: 'Emotet / Qakbot Stager Handshake',
    category: 'malware',
    source: 'CISA Alert AA23-242A',
    reference: 'Hardcoded legacy cipher vector',
  },
  {
    kind: 'ja3',
    value: '9e107d9d372bb6826bd81d3542a419d6',
    label: 'TrickBot Banking Trojan',
    category: 'malware',
    source: 'Abuse.ch Malware Corpus',
    reference: 'Static TLS 1.2 handshake',
  },
  {
    kind: 'ja3',
    value: '51c64c77e60f39ac3e17763da8e10b9e',
    label: 'AsyncRAT TLS Beacon',
    category: 'malware',
    source: 'ANY.RUN Malware Lab',
    reference: 'Custom SSL Stream wrapper',
  },

  // --- JA3S (ServerHello MD5) ---
  {
    kind: 'ja3s',
    value: 'eb1d9433088166ba1055745426189917',
    label: 'Cloudflare Edge FrontEnd TLS 1.3',
    category: 'benign',
    source: 'Cloudflare SSL Baseline',
    reference: 'BoringSSL TLS 1.3 negotiated',
  },
  {
    kind: 'ja3s',
    value: 'ec74a5c5110605f9f8eac84b72459e31',
    label: 'Google FrontEnd GFE/2.0 TLS 1.3',
    category: 'benign',
    source: 'Google Infrastructure Feed',
    reference: 'HTTP/2 negotiated server hello',
  },
  {
    kind: 'ja3s',
    value: 'fd4bc6cea4877646ccd62f403920264e',
    label: 'AWS CloudFront CDN Edge',
    category: 'benign',
    source: 'Amazon CloudFront Telemetry',
    reference: 'TLS 1.3 AES-128-GCM',
  },
  {
    kind: 'ja3s',
    value: 'ae4ed347eb10fe6b2a006ee7e3cf286b',
    label: 'Apache Traffic Server ATS 9.2',
    category: 'benign',
    source: 'Apache Foundation Security',
    reference: 'OpenSSL 3.0 backend',
  },
  {
    kind: 'ja3s',
    value: 'f99d5cae544521dd9d7c379a5ad304d9',
    label: 'Cobalt Strike Default Team Server Malleable C2',
    category: 'c2',
    source: 'CISA Red Team IOC Feed',
    reference: 'Static self-signed TLS server response',
  },
  {
    kind: 'ja3s',
    value: '380508611110034a8e2cb764d994358a',
    label: 'Sliver C2 Multiplexed Listener',
    category: 'c2',
    source: 'BishopFox Open Source Labs',
    reference: 'Go TLS listener with mTLS',
  },
  {
    kind: 'ja3s',
    value: '67a840c9d19a28bfa010e94812bc4901',
    label: 'Pikabot C2 Infrastructure Server',
    category: 'malware',
    source: 'Abuse.ch Botnet Trackers',
    reference: 'Rogue TLS proxy server',
  },
  {
    kind: 'ja3s',
    value: '8c91a32049e018dca4710294821048ca',
    label: 'IcedID / BokBot C2 Responder',
    category: 'malware',
    source: 'CISA Advisory AA22-311A',
    reference: 'Hardcoded TLS 1.2 ServerHello',
  },

  // --- JA4 (ClientHello FoxIO) ---
  {
    kind: 'ja4',
    value: 't13d1516h2_8daaf6152771_e562703ab854',
    label: 'Chrome 129 Desktop (Standard)',
    category: 'benign',
    source: 'FoxIO Official Feed',
    reference: 'Alpn: h2, SNI Present',
  },
  {
    kind: 'ja4',
    value: 't13d1912h2_b46b5a31a48c_49704e6fe8e2',
    label: 'Mozilla Firefox 131 Desktop Quantum',
    category: 'benign',
    source: 'FoxIO Standard Set',
    reference: 'Modern TLS 1.3 cipher suite',
  },
  {
    kind: 'ja4',
    value: 't13d1517h2_8daaf6152771_f00d3d5f9d12',
    label: 'Apple Safari 18 macOS / WebKit',
    category: 'benign',
    source: 'FoxIO Standard Set',
    reference: 'WebKit TLS 1.3 profile',
  },
  {
    kind: 'ja4',
    value: 't13d1516h2_8daaf6152771_3a4c19d45e01',
    label: 'Microsoft Edge 129 Windows 11',
    category: 'benign',
    source: 'Microsoft Security Feed',
    reference: 'Chromium-based Edge handshake',
  },
  {
    kind: 'ja4',
    value: 't13d090600_e4465b746c05_000000000000',
    label: 'Python Requests Client',
    category: 'tool',
    source: 'FoxIO Standard Set',
    reference: 'No ALPN, 9 Ciphers, 6 Extensions',
  },
  {
    kind: 'ja4',
    value: 't13d030300_000000000000_000000000000',
    label: 'Go crypto/tls default Dial',
    category: 'tool',
    source: 'FoxIO Curated Feed',
    reference: 'Minimalist TLS handshake',
  },
  {
    kind: 'ja4',
    value: 't13d0505h1_8daaf6152771_118274aef001',
    label: 'Headless Chromium Automation Cluster',
    category: 'tool',
    source: 'Trident Automated Scanner',
    reference: 'Puppeteer / Playwright test harness',
  },
  {
    kind: 'ja4',
    value: 't13i1516h2_8daaf6152771_e562703ab854',
    label: 'Chrome 129 IP-direct (No SNI)',
    category: 'tool',
    source: 'FoxIO Anomaly Detection',
    reference: 'Direct IP target without hostname',
  },
  {
    kind: 'ja4',
    value: 't12d080500_6a20bc88e145_3b9914bca821',
    label: 'Cobalt Strike 4.9 Beacon Raw',
    category: 'c2',
    source: 'ThreatConnect Intelligence',
    reference: 'Legacy TLS 1.2 beacon profile',
  },
  {
    kind: 'ja4',
    value: 't12d040200_1a4d8b90e311_000000000000',
    label: 'Sliver C2 v1.5 HTTP/TLS Stager',
    category: 'c2',
    source: 'Abuse.ch SSLBL Verified',
    reference: 'Go TLS 1.2 stager',
  },
  {
    kind: 'ja4',
    value: 't12d060300_90cd41ef2831_1890cae21402',
    label: 'Brute Ratel C4 Badger TLS Profile',
    category: 'c2',
    source: 'Mandiant Threat Intel',
    reference: 'High-entropy cipher permutation',
  },
  {
    kind: 'ja4',
    value: 't10d020100_00050004000a_000000000000',
    label: 'Legacy WinHTTP Cryptographic Stager',
    category: 'malware',
    source: 'CISA Alert AA23-242A',
    reference: 'Obsolescent SSL/TLS handshake',
  },
  {
    kind: 'ja4',
    value: 't12d050400_3d4e5f6a7b8c_000000000000',
    label: 'RedLine Stealer Handshake Profile',
    category: 'malware',
    source: 'ANY.RUN Malware Lab',
    reference: 'Infostealer TLS telemetry',
  },
  {
    kind: 'ja4',
    value: 't13d040300_41908bfec101_000000000000',
    label: 'Lumma Stealer TLS 1.3 Beacon',
    category: 'malware',
    source: 'Abuse.ch Botnet Feeds',
    reference: 'Exfiltration client',
  },

  // --- JA4S (ServerHello FoxIO) ---
  {
    kind: 'ja4s',
    value: 't1302h2_1301_a56c78912345',
    label: 'Cloudflare Edge ServerHello TLS 1.3',
    category: 'benign',
    source: 'FoxIO Standard Set',
    reference: 'TLS 1.3 TLS_AES_128_GCM_SHA256',
  },
  {
    kind: 'ja4s',
    value: 't1302h2_1302_bf3948cd1029',
    label: 'Google FrontEnd ServerHello HTTP/2',
    category: 'benign',
    source: 'Google Infrastructure Feed',
    reference: 'TLS_AES_256_GCM_SHA384',
  },
  {
    kind: 'ja4s',
    value: 't1202h1_c02f_000000000000',
    label: 'Nginx Legacy TLS 1.2 OpenSSL',
    category: 'benign',
    source: 'Nginx Baseline Corpus',
    reference: 'ECDHE-RSA-AES128-GCM-SHA256',
  },
  {
    kind: 'ja4s',
    value: 't1302h2_1301_98a7bc64102e',
    label: 'AWS CloudFront ServerHello TLS 1.3',
    category: 'benign',
    source: 'Amazon CloudFront Telemetry',
    reference: 'AWS edge termination',
  },
  {
    kind: 'ja4s',
    value: 't130200_1301_000000000000',
    label: 'Sliver C2 Default Listener Response',
    category: 'c2',
    source: 'BishopFox Labs',
    reference: 'No ALPN server response',
  },
  {
    kind: 'ja4s',
    value: 't120200_0035_000000000000',
    label: 'Cobalt Strike Team Server Self-Signed TLS 1.2',
    category: 'c2',
    source: 'CISA Threat Advisory',
    reference: 'RSA-AES256-SHA cipher selection',
  },
  {
    kind: 'ja4s',
    value: 't120100_002f_000000000000',
    label: 'Havoc Framework C2 Demonstration Daemon',
    category: 'c2',
    source: 'ThreatConnect IOCs',
    reference: 'Havoc C2 server response',
  },
  {
    kind: 'ja4s',
    value: 't120200_c014_000000000000',
    label: 'Pikabot C2 Listener Response',
    category: 'malware',
    source: 'Abuse.ch Malware Corpus',
    reference: 'Malicious proxy response',
  },

  // --- JA4H (HTTP Request FoxIO) ---
  {
    kind: 'ja4h',
    value: 'ge20cn000000_1289cf4e8190_e3b0c44298fc',
    label: 'Browser Fetch API with Session Cookie',
    category: 'benign',
    source: 'FoxIO Web Baseline',
    reference: 'Modern web application GET',
  },
  {
    kind: 'ja4h',
    value: 'ge20cr000000_209148bca120_41908bfec101',
    label: 'Chrome User Navigation GET with Referer',
    category: 'benign',
    source: 'FoxIO Web Baseline',
    reference: 'User navigation request',
  },
  {
    kind: 'ja4h',
    value: 'ge11nn000000_b94e33d28901_38f018a48b99',
    label: 'cURL CLI GET request without cookies',
    category: 'tool',
    source: 'Trident Lab Sensors',
    reference: 'Standard terminal HTTP client',
  },
  {
    kind: 'ja4h',
    value: 'po11nn000000_5a9019284cb1_000000000000',
    label: 'Python Requests POST JSON payload',
    category: 'tool',
    source: 'Python Community Feed',
    reference: 'Scripted REST API interaction',
  },
  {
    kind: 'ja4h',
    value: 'ge11nn000000_f71829da4100_000000000000',
    label: 'Sliver HTTP Poll / Tasking Checkin',
    category: 'c2',
    source: 'Abuse.ch SSLBL Verified',
    reference: 'Periodic command beacon',
  },
  {
    kind: 'ja4h',
    value: 'po11cn000000_8daaf6152771_000000000000',
    label: 'Cobalt Strike Malleable HTTP POST Beacon',
    category: 'c2',
    source: 'MITRE ATT&CK T1071.001',
    reference: 'Cookie-staged exfiltration',
  },
  {
    kind: 'ja4h',
    value: 'po11nn000000_90cd41ef2831_000000000000',
    label: 'Emotet C2 Exfiltration POST Request',
    category: 'malware',
    source: 'CISA Alert AA23-242A',
    reference: 'Binary blob upload',
  },
  {
    kind: 'ja4h',
    value: 'ge11nn000000_000000000000_000000000000',
    label: 'Go-http-client Raw Healthcheck',
    category: 'tool',
    source: 'Go Standard Library Baseline',
    reference: 'Unadorned HTTP GET',
  },

  // --- JA4X (X.509 Certificate FoxIO) ---
  {
    kind: 'ja4x',
    value: 'x509_306r_e3b0c44298fc_d41d8cd98f00',
    label: "Let's Encrypt Authority E6 RSA Certificate",
    category: 'benign',
    source: 'Internet Security Research Group',
    reference: 'Automated DV certificate',
  },
  {
    kind: 'ja4x',
    value: 'x509_308e_1289ab4c7810_55a9018e3901',
    label: 'DigiCert Global Root G2 TLS Cert',
    category: 'benign',
    source: 'DigiCert Trust Network',
    reference: 'Commercial public CA root',
  },
  {
    kind: 'ja4x',
    value: 'x509_305e_445566778899_112233445566',
    label: 'Cloudflare Origin CA Certificate',
    category: 'benign',
    source: 'Cloudflare Trust Store',
    reference: 'Edge to origin internal cert',
  },
  {
    kind: 'ja4x',
    value: 'x509_304r_deadbeef0001_deadbeef0001',
    label: 'Self-Signed Cobalt Strike SnakeOil Cert',
    category: 'c2',
    source: 'ThreatConnect IOCs',
    reference: 'Default trial certificate',
  },
  {
    kind: 'ja4x',
    value: 'x509_302r_98234710abcd_98234710abcd',
    label: 'Untrusted Self-Signed C2 Stager Certificate',
    category: 'malware',
    source: 'Abuse.ch SSLBL',
    reference: 'Unvalidated self-signed TLS cert',
  },
  {
    kind: 'ja4x',
    value: 'x509_303r_1a2b3c4d5e6f_1a2b3c4d5e6f',
    label: 'Sliver Interactive Default Test Certificate',
    category: 'c2',
    source: 'BishopFox Labs',
    reference: 'Generated mTLS client/server cert',
  },
  {
    kind: 'ja4x',
    value: 'x509_301r_baadcafe0042_baadcafe0042',
    label: 'Metasploit Generated TLS Certificate',
    category: 'c2',
    source: 'Rapid7 Database',
    reference: 'Random string issuer/subject',
  },

  // --- JA4T (TCP SYN Client Stack) ---
  {
    kind: 'ja4t',
    value: '65535_mss1460_wscale8_sackOK_ts',
    label: 'macOS Darwin 23.6 / iOS 18 TCP stack',
    category: 'os',
    source: 'FoxIO TCP OS Signatures',
    reference: 'Modern Apple networking stack',
  },
  {
    kind: 'ja4t',
    value: '64240_mss1460_wscale8_sackOK_ts',
    label: 'Windows 11 / Windows Server 2025 TCP stack',
    category: 'os',
    source: 'Microsoft OS Telemetry',
    reference: 'Default Windows TCP/IP parameters',
  },
  {
    kind: 'ja4t',
    value: '64860_mss1460_sackOK_ts_wscale7',
    label: 'Linux Kernel 6.8 / 6.11 Ubuntu/Debian',
    category: 'os',
    source: 'Linux Kernel Baseline',
    reference: 'Modern Linux network stack',
  },
  {
    kind: 'ja4t',
    value: '1024_mss1460_raw',
    label: 'Raw Nmap SYN Stealth Port Scan',
    category: 'tool',
    source: 'Nmap Project Fingerprints',
    reference: 'Raw socket probe packet',
  },
  {
    kind: 'ja4t',
    value: '5840_mss1460_wscale2_sackOK',
    label: 'Embedded IoT / OpenWrt Linux stack',
    category: 'os',
    source: 'Embedded Device Telemetry',
    reference: 'Resource-constrained network device',
  },
  {
    kind: 'ja4t',
    value: '65535_mss1440_wscale6_sackOK',
    label: 'Android 14 / Linux bionic mobile stack',
    category: 'os',
    source: 'Google Android Telemetry',
    reference: 'Cellular MTU negotiation',
  },
  {
    kind: 'ja4t',
    value: '8192_mss1460_wscale3_sackOK',
    label: 'FreeBSD 14.1 Network Stack',
    category: 'os',
    source: 'FreeBSD Project Baseline',
    reference: 'BSD socket implementation',
  },

  // --- JA4TS (TCP SYN-ACK Server Stack) ---
  {
    kind: 'ja4ts',
    value: '65160_mss1460_wscale7_sackOK_ts',
    label: 'Linux 6.8 Nginx Server TCP response',
    category: 'os',
    source: 'Linux Server Baseline',
    reference: 'High-throughput server TCP stack',
  },
  {
    kind: 'ja4ts',
    value: '64240_mss1460_wscale8_sackOK',
    label: 'Windows Server IIS 10.0 SYN-ACK response',
    category: 'os',
    source: 'Microsoft Server Telemetry',
    reference: 'IIS TCP stack response',
  },
  {
    kind: 'ja4ts',
    value: '65535_mss1460_wscale6_sackOK_ts',
    label: 'FreeBSD / pfSense Firewall TCP response',
    category: 'os',
    source: 'FreeBSD Network Baseline',
    reference: 'Firewall TCP synproxy response',
  },
  {
    kind: 'ja4ts',
    value: '8192_mss1460_wscale3_sackOK',
    label: 'F5 BIG-IP Local Traffic Manager SYN-ACK',
    category: 'os',
    source: 'F5 Enterprise Telemetry',
    reference: 'Hardware load balancer response',
  },
  {
    kind: 'ja4ts',
    value: '65535_mss1400_wscale5',
    label: 'OpenBSD WireGuard Gateway SYN-ACK',
    category: 'os',
    source: 'OpenBSD Project Baseline',
    reference: 'VPN tunnel MTU response',
  },
  {
    kind: 'ja4ts',
    value: '32768_mss1460_wscale6_sackOK',
    label: 'AWS Elastic Load Balancer SYN-ACK',
    category: 'os',
    source: 'AWS Network Infrastructure',
    reference: 'Cloud application load balancer',
  },
];

// Active SSE client connections
const sseClients = new Set();

function broadcastEvent(data) {
  const payload = `data: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      if (!client.destroyed && client.writable) {
        client.write(payload);
      } else {
        sseClients.delete(client);
      }
    } catch {
      sseClients.delete(client);
    }
  }
}

// Highly active, real-time wire-tap simulation broadcasting live flows and alerts
let cycle = 0;
setInterval(() => {
  cycle++;

  const sample = corpusItems[Math.floor(Math.random() * corpusItems.length)];
  const isMalicious = sample.category === 'malware' || sample.category === 'c2';
  const isTool = sample.category === 'tool';
  const nowNanos = Date.now() * 1_000_000;
  const srcPort = Math.floor(40000 + Math.random() * 20000);
  const srcSubnets = ['192.168.1', '10.0.4', '172.16.10', '192.168.20'];
  const srcIp = `${srcSubnets[Math.floor(Math.random() * srcSubnets.length)]}.${Math.floor(2 + Math.random() * 250)}`;
  const dstIp = isMalicious
    ? `198.51.100.${Math.floor(10 + Math.random() * 80)}`
    : isTool
    ? `104.21.${Math.floor(10 + Math.random() * 80)}.${Math.floor(10 + Math.random() * 200)}`
    : '104.21.34.112';

  const ja4Hash = sample.kind === 'ja4' ? sample.value : 't13d1516h2_8daaf6152771_e562703ab854';
  const ja4Raw = 't13d1516h2_130113021303_00000017000d';

  let alertList = undefined;

  // Decide rule to trigger dynamically across all 6 verified rules
  let triggerRule = null;
  if (isMalicious && Math.random() > 0.15) {
    triggerRule = 'known_bad';
  } else if (isTool && Math.random() > 0.3) {
    triggerRule = 'ua_mismatch';
  } else if (cycle % 7 === 0) {
    triggerRule = 'os_mismatch';
  } else if (cycle % 11 === 0) {
    triggerRule = 'first_seen';
  } else if (cycle % 15 === 0) {
    triggerRule = 'fp_rotation';
  } else if (cycle % 21 === 0) {
    triggerRule = 'monoculture';
  }

  if (triggerRule) {
    let alertItem;
    if (triggerRule === 'known_bad') {
      alertItem = {
        ts_nanos: nowNanos,
        rule: 'known_bad',
        severity: 'critical',
        ip: `${srcIp}:${srcPort}`,
        fp_kind: sample.kind,
        fp_value: sample.value,
        title: 'known-bad fingerprint',
        detail: `Fingerprint ${sample.value.slice(0, 14)}... matches verified ${sample.label} implant signature from threat intelligence feeds.`,
        score: Math.floor(94 + Math.random() * 6),
      };
    } else if (triggerRule === 'ua_mismatch') {
      const uas = [
        'Mac Chrome 129.0.0.0 (AppleWebKit)',
        'Windows 11 Edge 129.0 (Blink)',
        'iOS 18.0 Safari (Mobile WebKit)',
        'Ubuntu Firefox 131.0 (Gecko)',
      ];
      const tools = ['Python urllib3 / Requests 2.32', 'Go-http-client standard', 'cURL 8.10 OpenSSL', 'Node.js fetch / undici'];
      alertItem = {
        ts_nanos: nowNanos,
        rule: 'ua_mismatch',
        severity: 'high',
        ip: `${srcIp}:${srcPort}`,
        fp_kind: sample.kind,
        fp_value: sample.value,
        title: 'the user-agent is lying',
        detail: `HTTP User-Agent claimed ${uas[cycle % uas.length]}, but cryptographic cipher order and extensions match ${tools[cycle % tools.length]}.`,
        score: Math.floor(82 + Math.random() * 8),
      };
    } else if (triggerRule === 'os_mismatch') {
      alertItem = {
        ts_nanos: nowNanos,
        rule: 'os_mismatch',
        severity: 'medium',
        ip: `${srcIp}:${srcPort}`,
        fp_kind: sample.kind,
        fp_value: sample.value,
        title: 'the stack betrays the os',
        detail: `TCP window size (${Math.floor(64000 + Math.random() * 1500)}) and TTL indicate Linux kernel, but TLS ClientHello extensions mimic Windows 11 Edge browser.`,
        score: Math.floor(65 + Math.random() * 10),
      };
    } else if (triggerRule === 'first_seen') {
      alertItem = {
        ts_nanos: nowNanos,
        rule: 'first_seen',
        severity: 'low',
        ip: `${srcIp}:${srcPort}`,
        fp_kind: sample.kind,
        fp_value: sample.value,
        title: 'first sighting',
        detail: `Unobserved cryptographic permutation (${sample.value.slice(0, 14)}...) recorded across the perimeter for the first time.`,
        score: Math.floor(35 + Math.random() * 15),
      };
    } else if (triggerRule === 'fp_rotation') {
      alertItem = {
        ts_nanos: nowNanos,
        rule: 'fp_rotation',
        severity: 'high',
        ip: `${srcIp}:${srcPort}`,
        fp_kind: sample.kind,
        fp_value: sample.value,
        title: 'rapid fingerprint agility',
        detail: `Host at ${srcIp} rotated through 3 distinct TLS handshakes within a 45-second observation window.`,
        score: Math.floor(84 + Math.random() * 8),
      };
    } else if (triggerRule === 'monoculture') {
      alertItem = {
        ts_nanos: nowNanos,
        rule: 'monoculture',
        severity: 'info',
        ip: `${srcIp}:${srcPort}`,
        fp_kind: sample.kind,
        fp_value: sample.value,
        title: 'monoculture drift',
        detail: `Host cipher negotiation includes legacy 3DES/RC4 suites deviating from internal corporate perimeter baseline.`,
        score: Math.floor(25 + Math.random() * 12),
      };
    }

    if (alertItem) {
      alertList = [alertItem];
      alertsLedger.unshift(alertItem);
      if (alertsLedger.length > 100) alertsLedger.pop();
      const r = alertsByRule.find((x) => x.rule === alertItem.rule);
      if (r) r.count++;
      liveAlertsTotal++;
    }
  }

  // Periodic Intel Corpus Expansion (every 3 cycles ~ 3.3s)
  if (cycle % 3 === 0) {
    liveIntelTotal += Math.floor(Math.random() * 3) + 1;
    const src = intelSources[Math.floor(Math.random() * intelSources.length)];
    if (src) src.records += Math.floor(Math.random() * 2) + 1;
    const cat = intelCategories[Math.floor(Math.random() * intelCategories.length)];
    if (cat) cat.records += Math.floor(Math.random() * 2) + 1;
  }

  // Ingest newly observed candidate fingerprint into corpusItems (every 10 cycles)
  if (cycle % 10 === 0 && corpusItems.length < 150) {
    const novelKinds = ['ja4', 'ja3', 'ja4s', 'ja4h'];
    const chosenKind = novelKinds[Math.floor(Math.random() * novelKinds.length)];
    const hexHash = Math.random().toString(16).substring(2, 14);
    const novelItem = {
      kind: chosenKind,
      value: chosenKind === 'ja4' ? `t13d1618h2_${hexHash}_118274aef001` : chosenKind === 'ja3' ? Math.random().toString(16).substring(2, 34) : `t1302h2_1301_${hexHash}`,
      label: `Observed Perimeter Candidate #${liveIntelTotal}`,
      category: Math.random() > 0.5 ? 'benign' : Math.random() > 0.5 ? 'tool' : 'malware',
      source: 'Live Wire-Tap Observation',
      reference: 'Perimeter Sensor Ingestion',
    };
    corpusItems.push(novelItem);
  }

  // Broadcast to connected SSE clients
  if (sseClients.size > 0) {
    const flowMsg = {
      type: 'flow',
      event: {
        kind: 'client_hello',
        ts_nanos: nowNanos,
        src: `${srcIp}:${srcPort}`,
        dst: `${dstIp}:443`,
        ja3: sample.kind === 'ja3' ? sample.value : 'cd08e31494f9531f560d64cfa3f2233f',
        ja3_raw: '771,4865-4866-4867-49195-49199,0-23-65281-10-11,29-23-24,0',
        ja4: {
          hash: ja4Hash,
          raw: ja4Raw,
        },
        sni: sample.category === 'benign' ? 'cloudflare.com' : undefined,
        alpn: 'h2',
      },
      intel: [
        {
          kind: sample.kind,
          observed: sample.value,
          verdict: isMalicious ? 'malicious' : isTool ? 'suspicious' : 'benign',
          threat_score: isMalicious ? 95 : isTool ? 70 : 5,
          confidence: 0.94,
          hits: [
            {
              kind: sample.kind,
              value: sample.value,
              label: sample.label,
              category: sample.category,
              source: sample.source,
              reference: sample.reference || undefined,
              strength: 'exact',
            },
          ],
        },
      ],
      alerts: alertList,
    };

    broadcastEvent(flowMsg);

    // Occasionally send standalone alert event to trigger ALR alert row in feed
    if (alertList && cycle % 2 === 0) {
      const alertMsg = {
        type: 'alert',
        alert: alertList[0],
      };
      broadcastEvent(alertMsg);
    }
  }
}, 1100);

// Request handler supporting both exact API and static site files
function handleRequest(req, res) {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // --- API Endpoints ---

  if (pathname === '/api/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        status: 'healthy',
        service: 'TLS Intelligence Platform Engine',
        version: '1.0.0',
        active_connections: sseClients.size,
        uptime_sec: Math.floor(process.uptime()),
      })
    );
    return;
  }

  if (pathname === '/api/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        intel: {
          sources: intelSources,
          by_category: intelCategories,
          total: liveIntelTotal,
        },
        alerts_by_rule: alertsByRule,
        alert_total: liveAlertsTotal,
      })
    );
    return;
  }

  if (pathname === '/api/alerts') {
    const limit = parseInt(parsedUrl.searchParams.get('limit') || '50', 10);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(alertsLedger.slice(0, limit)));
    return;
  }

  if (pathname === '/api/search') {
    const q = (parsedUrl.searchParams.get('q') || '').trim().toLowerCase();
    const kind = (parsedUrl.searchParams.get('kind') || '').trim().toLowerCase();
    const limit = parseInt(parsedUrl.searchParams.get('limit') || '60', 10);

    const filtered = corpusItems.filter((item) => {
      const matchQ =
        !q ||
        item.label.toLowerCase().includes(q) ||
        item.value.toLowerCase().includes(q) ||
        item.category.toLowerCase().includes(q) ||
        item.source.toLowerCase().includes(q) ||
        (item.reference && item.reference.toLowerCase().includes(q));
      const matchKind = !kind || kind === 'all' || item.kind.toLowerCase() === kind;
      return matchQ && matchKind;
    });

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(filtered.slice(0, limit)));
    return;
  }

  if (pathname === '/api/stream' || pathname === '/api/events') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write(': connected\n\n');

    sseClients.add(res);

    const cleanup = () => sseClients.delete(res);
    req.on('close', cleanup);
    req.on('error', cleanup);
    res.on('error', cleanup);
    return;
  }

  if (pathname === '/api/export' || pathname.startsWith('/api/export/')) {
    const format = parsedUrl.searchParams.get('format') || (pathname.endsWith('.csv') ? 'csv' : 'json');

    if (format === 'csv') {
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="tls_alerts_ledger.csv"',
      });
      let csv = 'ts_nanos,rule,severity,ip,fp_kind,fp_value,title,detail,score\n';
      const list = alertsLedger.length > 0 ? alertsLedger : [
        {
          ts_nanos: Date.now() * 1_000_000,
          rule: 'known_bad',
          severity: 'critical',
          ip: '198.51.100.23:443',
          fp_kind: 'ja3',
          fp_value: '6520d624a91943c2c525b6a715f5d62d',
          title: 'known-bad fingerprint',
          detail: 'Matches Sliver C2 implant signature',
          score: 98,
        }
      ];
      for (const a of list) {
        const titleSafe = (a.title || '').replace(/"/g, '""');
        const detailSafe = (a.detail || '').replace(/"/g, '""');
        csv += `"${a.ts_nanos}","${a.rule}","${a.severity}","${a.ip || ''}","${a.fp_kind || ''}","${a.fp_value || ''}","${titleSafe}","${detailSafe}","${a.score || ''}"\n`;
      }
      res.end(csv);
    } else {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Disposition': 'attachment; filename="tls_alerts_ledger.json"',
      });
      res.end(JSON.stringify(alertsLedger, null, 2));
    }
    return;
  }

  // --- Static Site File Serving ---
  let filePath = path.join(SITE_DIR, pathname);

  // Security: check path traversal
  if (!filePath.startsWith(SITE_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (!err && stats.isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': contentType });
      fs.createReadStream(filePath).pipe(res);
    } else {
      // SPA Fallback: serve index.html for client-side routing
      const indexPath = path.join(SITE_DIR, 'index.html');
      fs.readFile(indexPath, (readErr, content) => {
        if (readErr) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not Found');
        } else {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(content);
        }
      });
    }
  });
}

// Global process error handlers
process.on('uncaughtException', (err) => {
  console.error('Handled exception:', err.message);
});
process.on('unhandledRejection', (reason) => {
  console.error('Handled rejection:', reason);
});

// Start unified server on Port 3000
const mainServer = http.createServer(handleRequest);
mainServer.listen(PORT, '0.0.0.0', () => {
  console.log(`[TLSFP Real-Time Server] Live on http://127.0.0.1:${PORT}`);
});

// Also start secondary listener on Port 3001 for standalone API access
const apiServer = http.createServer(handleRequest);
apiServer.listen(API_PORT, '0.0.0.0', () => {
  console.log(`[API Engine] Standalone API live on http://localhost:${API_PORT}`);
});
