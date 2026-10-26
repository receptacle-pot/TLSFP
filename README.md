# TLSFP // PASSIVE TLS SURVEILLANCE & INTELLIGENCE PLATFORM
### High-Fidelity JA3 & JA4+ Network Fingerprint Analyzer & Threat Intelligence Platform

A production-grade, defensive cybersecurity platform and passive TLS fingerprint analyzer featuring real-time wire-tap telemetry, dark telemetry aesthetics, and comprehensive threat intelligence correlation.

---

## 🔬 Core Capabilities

- **Real-Time Handshake Biometrics**: High-fidelity passive observation of TLS ClientHello and ServerHello exchanges, specimen layout (`xray-butterfly.png`, `xray-lily.png`), corner registration marks, scanline overlays, and telemetry typography (**Anton**, **Space Grotesk**, and **Geist Mono**).
- **Authoritative JA3 Fingerprinting**: Implements Salesforce JA3/JA3S canonical string concatenation, RFC 8701 GREASE permutation filtering, and MD5 cryptographic hashing.
- **FoxIO JA4+ Fingerprinting**: Full standards-compliant implementation of JA4 (`part_a_part_b_part_c`), including protocol classification (`t`/`q`), TLS version, SNI indicator, non-GREASE cipher/extension 2-digit counts, ALPN 2-char token, and sorted SHA-256 truncated (12-char) hashes. Also supports JA4S, JA4H, JA4X, JA4T, and JA4TS.
- **Cryptographic Contradiction Engine**: Real-time anomaly detection identifying client masquerading (e.g. HTTP User-Agent claiming Chrome while TLS cryptographic parameters originate from Python Requests or cURL), known C2 beacons (Sliver, Cobalt Strike, Emotet), and deprecated cipher suites.
- **Forensic PCAP Analyzer**: Dissects raw `.pcap` and `.pcapng` network packet captures offline, reassembles TCP streams, extracts ClientHello records without decrypting application data, and generates threat attribution reports.
- **Live Wiretap Telemetry**: Real-time Server-Sent Events (SSE) streaming engine delivering live flow records, threat alerts, and quantitative census updates.

---

## 🏛️ Architecture Overview

```
TLSFP/
├── site/                         # Production Single Page Application (SPA)
│   ├── assets/                   # Compiled JS chunks, CSS modules & specimens
│   └── fonts/                    # Anton, Space Grotesk, Geist Mono (.woff2)
├── frontend/                     # React 18 + TypeScript + Vite + Tailwind CSS Source
│   ├── public/                   # Assets and web manifest
│   └── src/
│       ├── components/           # Frame, Reticle, LiveFeedPanel, AnomalyPanel, etc.
│       ├── pages/                # Landing (/), Scope (/scope), Intel (/intel)
│       ├── hooks/                # useStream (SSE buffer), useApi (TanStack Query)
│       └── styles/               # Design tokens, keyframe animations, typography
├── backend_rust/                 # Production Rust Axum Engine
│   ├── Cargo.toml                # Tokio, Axum, Rusqlite, MD5, SHA-256
│   └── src/
│       ├── main.rs               # Axum HTTP routes & SSE broadcast channel
│       ├── ja3.rs                # JA3/JA3S canonical string & GREASE filter
│       ├── ja4.rs                # FoxIO JA4 algorithm & truncated SHA-256
│       ├── pcap.rs               # Ethernet, IPv4/IPv6, TCP & TLS ClientHello parser
│       ├── detector.rs           # Contradiction rules & threat scoring
│       ├── db.rs                 # SQLite schema & persistence
│       └── models.rs             # Typed data definitions
├── backend_service/              # Native Execution Engine (Node.js runtime)
│   └── server.js                 # Unified HTTP API, Static Server & SSE broadcast
├── tests/
│   └── test_suite.py             # Automated unit tests for JA3, JA4, GREASE, rules
└── README.md
```

---

## 🚀 Quickstart & Execution

### 1. Launch the Live Platform
The unified service serves the web interface, the REST API, and the real-time wire-tap stream simultaneously:

```bash
node backend_service/server.js
```
- **Web Interface**: `http://127.0.0.1:3000`
- **Scope (Surveillance)**: `http://127.0.0.1:3000/scope`
- **The Corpus (Threat Intel)**: `http://127.0.0.1:3000/intel`
- **API Health**: `http://127.0.0.1:3000/api/health`
- **SSE Stream**: `http://127.0.0.1:3000/api/stream`

### 2. Run Automated Verification Tests
Run the standalone mathematical validation suite to verify RFC 8701 GREASE stripping, Salesforce JA3 MD5 computation, and FoxIO JA4 sorting and hashing rules:

```bash
python tests/test_suite.py
```

Expected output:
```
....
----------------------------------------------------------------------
Ran 4 tests in 0.001s

OK
```

---

## 🛡️ Security & Privacy Notice

- **Passive Inspection**: This platform observes TLS handshake metadata (cipher list, extension order, supported curves) and never collects decrypted application payloads or credentials.
- **Investigative Signals**: Fingerprints are classification indicators and do not uniquely identify individual human users or physical machines. Discrepancies should be correlated with secondary authentication and EDR signals.
- **Capture Permissions**: Live interface packet capture requires administrative permissions and must only be executed on authorized network boundaries.

---

## 👤 Credits & Attribution
- Standard Specifications: **Salesforce JA3/JA3S** & **FoxIO JA4+**
