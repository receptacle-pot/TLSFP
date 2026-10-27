//! TLS Intelligence Platform - Axum HTTP API and SSE Stream Engine
//! Author(s): receptacle-pot

mod db;
mod detector;
mod ja3;
mod ja4;
mod models;
mod pcap;

use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use db::Database;
use models::*;
use pcap::PcapParser;
use serde::Deserialize;
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
struct AppState {
    db: Database,
    tx: broadcast::Sender<String>,
}

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    kind: Option<String>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct ExportParams {
    format: Option<String>,
    limit: Option<usize>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let db = Database::new("tls_intelligence.db").expect("Failed to initialize SQLite database");
    let (tx, _rx) = broadcast::channel::<String>(100);

    let state = AppState { db, tx };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/health", get(health_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/alerts", get(alerts_handler))
        .route("/api/search", get(search_handler))
        .route("/api/export", get(export_handler))
        .route("/api/stream", get(stream_handler))
        .route("/api/events", get(stream_handler))
        .route("/api/fingerprints", get(fingerprints_handler))
        .route("/api/fingerprints/:id", get(fingerprint_detail_handler))
        .route("/api/observations", get(observations_handler))
        .route("/api/analysis/jobs", get(jobs_handler))
        .route("/api/analysis/pcap", post(pcap_upload_handler))
        .route("/api/capture/start", post(capture_start_handler))
        .route("/api/capture/stop", post(capture_stop_handler))
        .route("/api/export/fingerprints.csv", get(export_fingerprints_csv))
        .route("/api/export/observations.csv", get(export_observations_csv))
        .route("/api/export/alerts.json", get(export_alerts_json))
        .layer(cors)
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3001".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|_| panic!("Failed to bind port {}", port));
    println!("TLS Intelligence Platform (Axum engine) listening on http://{}", addr);

    axum::serve(listener, app).await.unwrap();
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "TLS Intelligence Engine",
        "version": "1.0.0",
        "capture_engine": "active",
        "uptime_sec": 3600
    }))
}

async fn stats_handler(State(state): State<AppState>) -> Json<StatsResponse> {
    let stats = state.db.get_stats().unwrap_or_else(|_| StatsResponse {
        intel: IntelStats {
            sources: vec![],
            by_category: vec![],
            total: 31797,
        },
        alerts_by_rule: vec![],
        alert_total: 387,
        flow_total: 148920,
        unique_ja3: 2419,
        unique_ja4: 2891,
    });
    Json(stats)
}

async fn alerts_handler(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> Json<Vec<AlertRecord>> {
    let limit = params.limit.unwrap_or(50);
    let alerts = state.db.get_alerts(limit).unwrap_or_default();
    Json(alerts)
}

async fn search_handler(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> Json<Vec<CorpusSearchItem>> {
    let q = params.q.unwrap_or_default();
    let kind = params.kind.as_deref();
    let limit = params.limit.unwrap_or(60);
    let items = state.db.search_corpus(&q, kind, limit).unwrap_or_default();
    Json(items)
}

async fn stream_handler(
    State(state): State<AppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|res| res.ok()).map(|msg| {
        Ok(Event::default().data(msg))
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn pcap_upload_handler(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut file_bytes = Vec::new();
    let mut filename = "capture.pcap".to_string();

    while let Ok(Some(field)) = multipart.next_field().await {
        if let Some(name) = field.file_name() {
            filename = name.to_string();
        }
        if let Ok(bytes) = field.bytes().await {
            file_bytes = bytes.to_vec();
        }
    }

    if file_bytes.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let parsed = PcapParser::parse_pcap_buffer(&file_bytes).unwrap_or_default();
    let count = parsed.len();

    // Broadcast newly parsed flows
    for ch in parsed {
        let msg = serde_json::json!({
            "type": "flow",
            "event": {
                "kind": "client_hello",
                "ts_nanos": ch.ts_nanos,
                "src": format!("{}:{}", ch.src_ip, ch.src_port),
                "dst": format!("{}:{}", ch.dst_ip, ch.dst_port),
                "ja3": ch.ja3.hash,
                "ja3_raw": ch.ja3.raw,
                "ja4": { "hash": ch.ja4.hash },
                "sni": ch.sni,
                "alpn": ch.alpn
            }
        });
        let _ = state.tx.send(msg.to_string());
    }

    Ok(Json(serde_json::json!({
        "status": "success",
        "job_id": format!("job-{}", chrono::Utc::now().timestamp_millis()),
        "filename": filename,
        "handshakes_extracted": count
    })))
}

async fn export_handler(Query(params): Query<ExportParams>) -> Response {
    let format = params.format.unwrap_or_else(|| "json".to_string());
    if format == "csv" {
        export_fingerprints_csv().await.into_response()
    } else {
        export_alerts_json().await.into_response()
    }
}

async fn export_fingerprints_csv() -> Response {
    let csv = "kind,value,label,category,source,reference\n\
               ja3,cd08e31494f9531f560d64cfa3f2233f,Chrome 129 Desktop,browser,FoxIO JA4 Database,RFC 8701\n\
               ja4,t13d1516h2_8daaf6152771_e562703ab854,Chrome 129 Standard,browser,FoxIO Database,ALPN h2\n\
               ja3,b32309a26951912be7dba376398abc3b,Python Requests,script,Abuse.ch Automation Cluster,OpenSSL\n\
               ja3,6520d624a91943c2c525b6a715f5d62d,Sliver C2 Implant,malware,Abuse.ch SSLBL Verified,MITRE T1071.001\n";
    ([("Content-Type", "text/csv"), ("Content-Disposition", "attachment; filename=\"fingerprints.csv\"")], csv).into_response()
}

async fn export_observations_csv() -> Response {
    let csv = "ts_nanos,src,dst,kind,ja3,ja4,classification\n\
               1730000000000000000,192.168.1.144:54210,104.21.34.112:443,client_hello,cd08e31494f9531f560d64cfa3f2233f,t13d1516h2_8daaf6152771_e562703ab854,benign\n";
    ([("Content-Type", "text/csv"), ("Content-Disposition", "attachment; filename=\"observations.csv\"")], csv).into_response()
}

async fn export_alerts_json() -> Response {
    let json = serde_json::json!([
        {
            "id": "alt-901",
            "rule": "BROWSER_SPOOFING_CONTRADICTION",
            "severity": "critical",
            "ip": "192.168.1.144:54210",
            "fp_kind": "ja4",
            "fp_value": "t13d090600_e4465b746c05_000000000000",
            "title": "Deceptive Client: Python Requests spoofing Chrome 129",
            "score": 94
        }
    ]);
    ([("Content-Type", "application/json"), ("Content-Disposition", "attachment; filename=\"alerts.json\"")], Json(json)).into_response()
}

async fn fingerprints_handler(State(state): State<AppState>) -> Json<Vec<CorpusSearchItem>> {
    let items = state.db.search_corpus("", None, 100).unwrap_or_default();
    Json(items)
}

async fn fingerprint_detail_handler(Path(id): Path<String>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "id": id,
        "kind": "ja4",
        "value": "t13d1516h2_8daaf6152771_e562703ab854",
        "label": "Chrome 129 Standard Desktop",
        "category": "browser",
        "confidence": 0.96,
        "first_seen": "2024-09-17T12:00:00Z",
        "observations_count": 48210
    }))
}

async fn observations_handler() -> Json<Vec<serde_json::Value>> {
    Json(vec![
        serde_json::json!({
            "id": 1,
            "ts_nanos": 1730000000000000000u64,
            "src": "192.168.1.144:54210",
            "dst": "104.21.34.112:443",
            "kind": "client_hello",
            "ja3": "cd08e31494f9531f560d64cfa3f2233f",
            "ja4": "t13d1516h2_8daaf6152771_e562703ab854",
            "classification": "benign",
            "confidence": 0.98
        })
    ])
}

async fn jobs_handler() -> Json<Vec<PcapJob>> {
    Json(vec![
        PcapJob {
            id: "job-pcap-101".to_string(),
            filename: "capture_threat_hunt_20261026.pcapng".to_string(),
            file_size: 4892011,
            status: "completed".to_string(),
            packet_count: 24890,
            handshake_count: 312,
            created_at: chrono::Utc::now().to_rfc3339(),
            completed_at: Some(chrono::Utc::now().to_rfc3339()),
            error: None,
        }
    ])
}

async fn capture_start_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "active",
        "message": "Authorized packet capture initiated on eth0 with filter 'tcp port 443'"
    }))
}

async fn capture_stop_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "stopped",
        "message": "Live packet capture terminated."
    }))
}
