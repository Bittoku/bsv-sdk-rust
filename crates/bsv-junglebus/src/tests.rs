//! Tests for the JungleBus client.

use wiremock::matchers::{header, header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::client::JungleBusClient;
use crate::types::JungleBusConfig;

fn test_config(server_url: &str) -> JungleBusConfig {
    JungleBusConfig {
        server_url: server_url.to_string(),
        token: Some("test-token".to_string()),
        api_version: "v1".to_string(),
    }
}

#[tokio::test]
async fn test_get_transaction_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/transaction/get/abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "abc123",
            "block_hash": "000000000000000000",
            "block_height": 800000,
            "block_time": 1700000000,
            "block_index": 42,
            "addresses": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
            "inputs": [],
            "outputs": [],
            "contexts": [],
            "data": []
        })))
        .mount(&server)
        .await;

    let client = JungleBusClient::new(test_config(&server.uri()));
    let tx = client.get_transaction("abc123").await.unwrap();

    assert_eq!(tx.id, "abc123");
    assert_eq!(tx.block_height, Some(800000));
    assert_eq!(tx.block_index, Some(42));
    assert_eq!(tx.addresses.len(), 1);
}

#[tokio::test]
async fn test_get_transaction_not_found() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/transaction/get/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;

    let client = JungleBusClient::new(test_config(&server.uri()));
    let result = client.get_transaction("nonexistent").await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        crate::error::JungleBusError::NotFound
    ));
}

#[tokio::test]
async fn test_get_block_header() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/block_header/get/800000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "hash": "00000000000000000001abc",
            "height": 800000,
            "time": 1700000000,
            "nonce": 12345,
            "version": 536870912,
            "merkle_root": "abcdef1234567890",
            "bits": "18034379",
            "synced": 1700000100
        })))
        .mount(&server)
        .await;

    let client = JungleBusClient::new(test_config(&server.uri()));
    let header = client.get_block_header("800000").await.unwrap();

    assert_eq!(header.hash, "00000000000000000001abc");
    assert_eq!(header.height, 800000);
    assert_eq!(header.merkle_root.as_deref(), Some("abcdef1234567890"));
}

#[tokio::test]
async fn test_get_block_headers_list() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/block_header/list/800000"))
        .and(query_param("limit", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"hash": "aaa", "height": 800000, "time": 1700000000},
            {"hash": "bbb", "height": 800001, "time": 1700000600}
        ])))
        .mount(&server)
        .await;

    let client = JungleBusClient::new(test_config(&server.uri()));
    let headers = client.get_block_headers("800000", 5).await.unwrap();

    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].height, 800000);
    assert_eq!(headers[1].height, 800001);
}

#[tokio::test]
async fn test_get_address_transactions() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/address/get/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "transaction_count": 100}
        ])))
        .mount(&server)
        .await;

    let client = JungleBusClient::new(test_config(&server.uri()));
    let info = client
        .get_address_transactions("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        .await
        .unwrap();

    assert_eq!(info.len(), 1);
    assert_eq!(info[0].transaction_count, Some(100));
}

#[tokio::test]
async fn test_token_header_set_when_configured() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/transaction/get/abc123"))
        .and(header("token", "test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "abc123"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = JungleBusClient::new(test_config(&server.uri()));
    let _ = client.get_transaction("abc123").await.unwrap();
}

#[tokio::test]
async fn test_token_header_absent_when_not_configured() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/transaction/get/abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "abc123"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = JungleBusConfig {
        server_url: server.uri(),
        token: None,
        api_version: "v1".to_string(),
    };
    let client = JungleBusClient::new(config);
    let _ = client.get_transaction("abc123").await.unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].headers.iter().any(|(name, _)| name == "token"));
}

#[tokio::test]
async fn test_server_error_handling() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/transaction/get/abc123"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal server error"))
        .mount(&server)
        .await;

    let client = JungleBusClient::new(test_config(&server.uri()));
    let result = client.get_transaction("abc123").await;

    assert!(result.is_err());
    match result.unwrap_err() {
        crate::error::JungleBusError::ServerError {
            status_code,
            message,
        } => {
            assert_eq!(status_code, 500);
            assert!(message.contains("internal server error"));
        }
        other => panic!("expected ServerError, got {:?}", other),
    }
}

#[test]
fn test_config_defaults() {
    let config = JungleBusConfig::default();
    assert_eq!(config.server_url, "https://junglebus.gorillapool.io");
    assert!(config.token.is_none());
    assert_eq!(config.api_version, "v1");
}
