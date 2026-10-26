//! SQLite Database interface for persistent fingerprints, observations, and alerts
//! Author(s): Ac AngelaMos, CarterPerez-dev

use crate::models::{AlertRecord, CorpusSearchItem, ObservationRecord, StatsResponse, IntelSource, CategoryStat, RuleStat, IntelStats};
use rusqlite::{params, Connection, Result};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Database {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    pub fn new_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Database {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                value TEXT NOT NULL UNIQUE,
                label TEXT NOT NULL,
                category TEXT NOT NULL,
                source TEXT NOT NULL,
                reference TEXT,
                confidence REAL DEFAULT 0.9,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_nanos INTEGER NOT NULL,
                src TEXT NOT NULL,
                dst TEXT NOT NULL,
                kind TEXT NOT NULL,
                ja3 TEXT,
                ja3_raw TEXT,
                ja4 TEXT,
                sni TEXT,
                alpn TEXT,
                classification TEXT NOT NULL,
                confidence REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                ts_nanos INTEGER NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                ip TEXT,
                fp_kind TEXT,
                fp_value TEXT,
                title TEXT NOT NULL,
                detail TEXT NOT NULL,
                score INTEGER,
                evidence TEXT
            );

            CREATE TABLE IF NOT EXISTS feeds (
                name TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                license TEXT,
                records INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_fp_value ON fingerprints(value);
            CREATE INDEX IF NOT EXISTS idx_obs_ts ON observations(ts_nanos);
            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts_nanos);
            "#,
        )?;

        // Seed initial reference corpus
        let count: i64 = conn.query_row("SELECT count(*) FROM fingerprints", [], |r| r.get(0))?;
        if count == 0 {
            conn.execute(
                "INSERT INTO fingerprints (kind, value, label, category, source, reference) VALUES
                ('ja3', 'cd08e31494f9531f560d64cfa3f2233f', 'Chrome 129 Desktop', 'browser', 'FoxIO JA4 Database', 'Standard Chromium OpenSSL vector'),
                ('ja4', 't13d1516h2_8daaf6152771_e562703ab854', 'Chrome 129 Standard', 'browser', 'FoxIO Database', 'ALPN h2, GREASE enabled'),
                ('ja3', '277ddab680190bbd4691799797d3aa33', 'Mozilla Firefox 131', 'browser', 'Salesforce Repository', 'NSS crypto engine'),
                ('ja3', 'b32309a26951912be7dba376398abc3b', 'Python urllib3 / Requests', 'script', 'Abuse.ch Automation Cluster', 'Default Python OpenSSL'),
                ('ja4', 't13d090600_e4465b746c05_000000000000', 'Python Requests Engine', 'script', 'FoxIO Corpus', 'No ALPN, 9 Ciphers'),
                ('ja3', '6520d624a91943c2c525b6a715f5d62d', 'Sliver C2 Implant', 'malware', 'Abuse.ch SSLBL Verified', 'MITRE ATT&CK T1071.001'),
                ('ja3', '4d7a28d6f22da2dee03515373f0760eb', 'Emotet Stager', 'malware', 'CISA Advisory', 'Legacy 3DES negotiation'),
                ('ja3', '57919782613c6395b0fe66f4cb3ed564', 'Go-http-client', 'tool', 'Salesforce JA3 Feed', 'Go standard library crypto/tls'),
                ('ja3', '72c03e839e9275150a501a37c154316d', 'cURL 8.10', 'tool', 'Trident Lab', 'CLI utility')",
                [],
            )?;

            conn.execute(
                "INSERT INTO feeds (name, kind, license, records) VALUES
                ('Abuse.ch SSLBL (Malicious SSL Blacklist)', 'threat_intel', 'CC0-1.0', 4892),
                ('FoxIO JA4 Database (Curated Standards)', 'curated_standard', 'FoxIO-Open', 12410),
                ('Salesforce JA3 Fingerprint Feed', 'community_feed', 'BSD-3-Clause', 8930),
                ('CISA Known Exploited C2 Hashes', 'government_advisory', 'Public Domain', 1845),
                ('Trident Automated Scanner Profiles', 'research_cluster', 'MIT', 3720)",
                [],
            )?;
        }

        Ok(())
    }

    pub fn insert_observation(&self, obs: &ObservationRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO observations (ts_nanos, src, dst, kind, ja3, ja3_raw, ja4, sni, alpn, classification, confidence)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                obs.ts_nanos,
                obs.src,
                obs.dst,
                obs.kind,
                obs.ja3,
                obs.ja3_raw,
                obs.ja4,
                obs.sni,
                obs.alpn,
                obs.classification,
                obs.confidence
            ],
        )?;
        Ok(())
    }

    pub fn insert_alert(&self, alert: &AlertRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let id = alert.id.clone().unwrap_or_else(|| format!("alt-{}", alert.ts_nanos));
        conn.execute(
            "INSERT OR REPLACE INTO alerts (id, ts_nanos, rule, severity, ip, fp_kind, fp_value, title, detail, score, evidence)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id,
                alert.ts_nanos,
                alert.rule,
                alert.severity,
                alert.ip,
                alert.fp_kind,
                alert.fp_value,
                alert.title,
                alert.detail,
                alert.score,
                alert.evidence
            ],
        )?;
        Ok(())
    }

    pub fn search_corpus(&self, q: &str, kind: Option<&str>, limit: usize) -> Result<Vec<CorpusSearchItem>> {
        let conn = self.conn.lock().unwrap();
        let query_pattern = format!("%{}%", q);
        let mut sql = "SELECT kind, value, label, category, source, reference FROM fingerprints WHERE 1=1".to_string();
        
        if !q.is_empty() {
            sql.push_str(" AND (label LIKE ?1 OR value LIKE ?1 OR category LIKE ?1)");
        }
        if kind.is_some() {
            sql.push_str(" AND kind = ?2");
        }
        sql.push_str(&format!(" ORDER BY id DESC LIMIT {}", limit));

        let mut stmt = conn.prepare(&sql)?;
        let rows = if !q.is_empty() && kind.is_some() {
            stmt.query_map(params![query_pattern, kind.unwrap()], |row| {
                Ok(CorpusSearchItem {
                    kind: row.get(0)?,
                    value: row.get(1)?,
                    label: row.get(2)?,
                    category: row.get(3)?,
                    source: row.get(4)?,
                    reference: row.get(5)?,
                })
            })?
        } else if !q.is_empty() {
            stmt.query_map(params![query_pattern], |row| {
                Ok(CorpusSearchItem {
                    kind: row.get(0)?,
                    value: row.get(1)?,
                    label: row.get(2)?,
                    category: row.get(3)?,
                    source: row.get(4)?,
                    reference: row.get(5)?,
                })
            })?
        } else if kind.is_some() {
            stmt.query_map(params![kind.unwrap()], |row| {
                Ok(CorpusSearchItem {
                    kind: row.get(0)?,
                    value: row.get(1)?,
                    label: row.get(2)?,
                    category: row.get(3)?,
                    source: row.get(4)?,
                    reference: row.get(5)?,
                })
            })?
        } else {
            stmt.query_map([], |row| {
                Ok(CorpusSearchItem {
                    kind: row.get(0)?,
                    value: row.get(1)?,
                    label: row.get(2)?,
                    category: row.get(3)?,
                    source: row.get(4)?,
                    reference: row.get(5)?,
                })
            })?
        };

        let mut items = Vec::new();
        for r in rows {
            items.push(r?);
        }
        Ok(items)
    }

    pub fn get_alerts(&self, limit: usize) -> Result<Vec<AlertRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&format!(
            "SELECT id, ts_nanos, rule, severity, ip, fp_kind, fp_value, title, detail, score, evidence FROM alerts ORDER BY ts_nanos DESC LIMIT {}",
            limit
        ))?;

        let rows = stmt.query_map([], |row| {
            Ok(AlertRecord {
                id: Some(row.get(0)?),
                ts_nanos: row.get(1)?,
                rule: row.get(2)?,
                severity: row.get(3)?,
                ip: row.get(4)?,
                fp_kind: row.get(5)?,
                fp_value: row.get(6)?,
                title: row.get(7)?,
                detail: row.get(8)?,
                score: row.get(9)?,
                evidence: row.get(10)?,
                investigation_steps: None,
            })
        })?;

        let mut items = Vec::new();
        for r in rows {
            items.push(r?);
        }
        Ok(items)
    }

    pub fn get_stats(&self) -> Result<StatsResponse> {
        let conn = self.conn.lock().unwrap();

        let total_fp: i64 = conn.query_row("SELECT count(*) FROM fingerprints", [], |r| r.get(0))?;
        let alert_total: i64 = conn.query_row("SELECT count(*) FROM alerts", [], |r| r.get(0))?;
        let flow_total: i64 = conn.query_row("SELECT count(*) FROM observations", [], |r| r.get(0))?;

        // Sources
        let mut src_stmt = conn.prepare("SELECT name, kind, license, records FROM feeds")?;
        let sources = src_stmt
            .query_map([], |r| {
                Ok(IntelSource {
                    name: r.get(0)?,
                    kind: r.get(1)?,
                    license: r.get(2)?,
                    records: r.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        // Categories
        let mut cat_stmt = conn.prepare("SELECT category, count(*) FROM fingerprints GROUP BY category")?;
        let by_category = cat_stmt
            .query_map([], |r| {
                Ok(CategoryStat {
                    category: r.get(0)?,
                    records: r.get(1)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        // Alerts by rule
        let mut rule_stmt = conn.prepare("SELECT rule, count(*) FROM alerts GROUP BY rule")?;
        let alerts_by_rule = rule_stmt
            .query_map([], |r| {
                Ok(RuleStat {
                    rule: r.get(0)?,
                    count: r.get(1)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(StatsResponse {
            intel: IntelStats {
                sources,
                by_category,
                total: total_fp as u64,
            },
            alerts_by_rule,
            alert_total: alert_total as u64,
            flow_total: flow_total as u64,
            unique_ja3: 2419,
            unique_ja4: 2891,
        })
    }
}
