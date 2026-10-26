//! Data models for TLS Intelligence Platform
//! Author(s): Ac AngelaMos, CarterPerez-dev

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationRecord {
    pub id: i64,
    pub ts_nanos: u64,
    pub src: String,
    pub dst: String,
    pub kind: String,
    pub ja3: Option<String>,
    pub ja3_raw: Option<String>,
    pub ja4: Option<String>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub classification: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub id: Option<String>,
    pub ts_nanos: u64,
    pub rule: String,
    pub severity: String,
    pub ip: Option<String>,
    pub fp_kind: Option<String>,
    pub fp_value: Option<String>,
    pub title: String,
    pub detail: String,
    pub score: Option<u32>,
    pub evidence: Option<String>,
    pub investigation_steps: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelSource {
    pub name: String,
    pub kind: String,
    pub license: Option<String>,
    pub records: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryStat {
    pub category: String,
    pub records: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleStat {
    pub rule: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    pub intel: IntelStats,
    pub alerts_by_rule: Vec<RuleStat>,
    pub alert_total: u64,
    pub flow_total: u64,
    pub unique_ja3: u64,
    pub unique_ja4: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelStats {
    pub sources: Vec<IntelSource>,
    pub by_category: Vec<CategoryStat>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusSearchItem {
    pub kind: String,
    pub value: String,
    pub label: String,
    pub category: String,
    pub source: String,
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapJob {
    pub id: String,
    pub filename: String,
    pub file_size: u64,
    pub status: String,
    pub packet_count: u64,
    pub handshake_count: u64,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub error: Option<String>,
}
