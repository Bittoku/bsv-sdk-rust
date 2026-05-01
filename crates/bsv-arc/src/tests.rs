//! Tests for the ARC client.

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::client::ArcClient;
use crate::types::{ArcConfig, ArcStatus};

fn test_config(base_url: &str) -> ArcConfig {
    ArcConfig {
        base_url: base_url.to_string(),
        api_key: Some("test-key".to_string()),
        callback_url: Some("https://example.com/callback".to_string()),
        callback_token: Some("cb-token".to_string()),
        wait_for_status: Some(ArcStatus::SeenOnNetwork),
        skip_fee_validation: true,
        skip_script_validation: true,
        skip_tx_validation: true,
        cumulative_fee_validation: true,
        full_status_updates: true,
        max_timeout: Some(30),
    }
}

fn dummy_tx() -> bsv_transaction::Transaction {
    bsv_transaction::Transaction::new()
}

#[tokio::test]
async fn test_successful_broadcast() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "txid": "abc123",
            "txStatus": "SEEN_ON_NETWORK",
            "status": 8,
            "title": "OK"
        })))
        .mount(&server)
        .await;

    let client = ArcClient::new(test_config(&server.uri()));
    let tx = dummy_tx();
    let resp = client.broadcast_async(&tx).await.unwrap();

    assert_eq!(resp.txid, "abc123");
    assert_eq!(resp.tx_status.as_deref(), Some("SEEN_ON_NETWORK"));
    assert_eq!(resp.status, Some(8));
}

#[tokio::test]
async fn test_rejected_transaction() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "txid": "abc123",
            "txStatus": "REJECTED",
            "status": 0,
            "detail": "dust output"
        })))
        .mount(&server)
        .await;

    let client = ArcClient::new(test_config(&server.uri()));
    let tx = dummy_tx();
    let result = client.broadcast_async(&tx).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("dust output"));
}

#[tokio::test]
async fn test_status_query() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/tx/abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "txid": "abc123",
            "txStatus": "MINED",
            "status": 9,
            "blockHeight": 800000,
            "blockHash": "00000000000000000001"
        })))
        .mount(&server)
        .await;

    let client = ArcClient::new(test_config(&server.uri()));
    let resp = client.status("abc123").await.unwrap();

    assert_eq!(resp.txid, "abc123");
    assert_eq!(resp.block_height, Some(800000));
}

#[tokio::test]
async fn test_headers_are_set() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tx"))
        .and(header("Authorization", "Bearer test-key"))
        .and(header("X-CallbackUrl", "https://example.com/callback"))
        .and(header("X-CallbackToken", "cb-token"))
        .and(header("X-WaitForStatus", "8"))
        .and(header("X-SkipFeeValidation", "true"))
        .and(header("X-SkipScriptValidation", "true"))
        .and(header("X-SkipTxValidation", "true"))
        .and(header("X-CumulativeFeeValidation", "true"))
        .and(header("X-FullStatusUpdates", "true"))
        .and(header("X-MaxTimeout", "30"))
        .and(header("content-type", "application/octet-stream"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "txid": "abc123",
            "txStatus": "QUEUED",
            "status": 1
        })))
        .mount(&server)
        .await;

    let client = ArcClient::new(test_config(&server.uri()));
    let tx = dummy_tx();
    let resp = client.broadcast_async(&tx).await.unwrap();
    assert_eq!(resp.txid, "abc123");
}

#[test]
fn test_config_defaults() {
    let config = ArcConfig::default();
    assert_eq!(config.base_url, "https://arc.taal.com/v1");
    assert!(config.api_key.is_none());
    assert!(!config.skip_fee_validation);
    assert!(!config.skip_script_validation);
    assert!(!config.skip_tx_validation);
    assert!(!config.cumulative_fee_validation);
    assert!(!config.full_status_updates);
    assert!(config.max_timeout.is_none());
}

#[tokio::test]
async fn test_no_auth_header_when_no_api_key() {
    let server = MockServer::start().await;

    // Mount a mock that should NOT receive Authorization header.
    // We verify by checking the received request afterwards.
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "txid": "abc123",
            "txStatus": "QUEUED",
            "status": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = ArcConfig {
        base_url: server.uri(),
        api_key: None,
        ..ArcConfig::default()
    };
    let client = ArcClient::new(config);
    let resp = client.broadcast_async(&dummy_tx()).await.unwrap();
    assert_eq!(resp.txid, "abc123");

    // Verify the request was received (no auth header crash)
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0]
        .headers
        .iter()
        .any(|(name, _)| name == "authorization"));
}

#[tokio::test]
async fn test_malformed_json_response() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not valid json"))
        .mount(&server)
        .await;

    let client = ArcClient::new(ArcConfig {
        base_url: server.uri(),
        ..ArcConfig::default()
    });
    let result = client.broadcast_async(&dummy_tx()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_html_error_response() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(
            ResponseTemplate::new(502).set_body_string("<html><body>Bad Gateway</body></html>"),
        )
        .mount(&server)
        .await;

    let client = ArcClient::new(ArcConfig {
        base_url: server.uri(),
        ..ArcConfig::default()
    });
    let result = client.broadcast_async(&dummy_tx()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_empty_response_body() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let client = ArcClient::new(ArcConfig {
        base_url: server.uri(),
        ..ArcConfig::default()
    });
    let result = client.broadcast_async(&dummy_tx()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_already_known_tx() {
    let server = MockServer::start().await;

    // ARC returns 200 with existing status for already-known txs
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "txid": "abc123",
            "txStatus": "SEEN_ON_NETWORK",
            "status": 8,
            "title": "Already known"
        })))
        .mount(&server)
        .await;

    let client = ArcClient::new(ArcConfig {
        base_url: server.uri(),
        ..ArcConfig::default()
    });
    let resp = client.broadcast_async(&dummy_tx()).await.unwrap();
    assert_eq!(resp.txid, "abc123");
    assert_eq!(resp.title.as_deref(), Some("Already known"));
}

#[tokio::test]
async fn test_mined_response_with_merkle_path() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/tx/abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "txid": "abc123",
            "txStatus": "MINED",
            "status": 9,
            "blockHeight": 850000,
            "blockHash": "000000000000000000026f5a9cf8e64507d75e70a9c37acac5b59a5e8c4dfe3c",
            "merklePath": "fed123abc"
        })))
        .mount(&server)
        .await;

    let client = ArcClient::new(ArcConfig {
        base_url: server.uri(),
        ..ArcConfig::default()
    });
    let resp = client.status("abc123").await.unwrap();
    assert_eq!(resp.block_height, Some(850000));
    assert_eq!(resp.merkle_path.as_deref(), Some("fed123abc"));
}

#[tokio::test]
async fn test_connection_refused() {
    // Connect to a port that's definitely not listening
    let client = ArcClient::new(ArcConfig {
        base_url: "http://127.0.0.1:1".to_string(),
        ..ArcConfig::default()
    });
    let result = client.broadcast_async(&dummy_tx()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_all_statuses_deserialize() {
    let statuses = [
        "REJECTED",
        "QUEUED",
        "RECEIVED",
        "STORED",
        "ANNOUNCED_TO_NETWORK",
        "REQUESTED_BY_NETWORK",
        "SENT_TO_NETWORK",
        "ACCEPTED_BY_NETWORK",
        "SEEN_ON_NETWORK",
        "MINED",
        "CONFIRMED",
        "DOUBLE_SPEND_ATTEMPTED",
        "SEEN_IN_ORPHAN_MEMPOOL",
    ];
    for s in statuses {
        let json = format!("\"{s}\"");
        let parsed: ArcStatus = serde_json::from_str(&json).unwrap();
        let roundtrip = serde_json::to_string(&parsed).unwrap();
        assert_eq!(roundtrip, json);
    }
}

#[tokio::test]
async fn test_status_query_not_found() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/tx/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "txid": "",
            "status": 0,
            "title": "Not found"
        })))
        .mount(&server)
        .await;

    let client = ArcClient::new(ArcConfig {
        base_url: server.uri(),
        ..ArcConfig::default()
    });
    // This still parses — ARC returns JSON 404s. The caller checks status.
    let resp = client.status("nonexistent").await.unwrap();
    assert_eq!(resp.title.as_deref(), Some("Not found"));
}

#[test]
fn test_arc_status_serde() {
    let status = ArcStatus::SeenOnNetwork;
    let json = serde_json::to_string(&status).unwrap();
    assert_eq!(json, "\"SEEN_ON_NETWORK\"");

    let parsed: ArcStatus = serde_json::from_str("\"MINED\"").unwrap();
    assert_eq!(parsed, ArcStatus::Mined);
}
