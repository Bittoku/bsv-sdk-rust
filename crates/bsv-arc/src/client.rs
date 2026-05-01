//! ARC HTTP client for broadcasting and querying transactions.

use bsv_spv::broadcaster::{BroadcastSuccess, Broadcaster};
use bsv_spv::error::SpvError;
use bsv_transaction::Transaction;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};

use crate::error::ArcError;
use crate::types::{ArcConfig, ArcResponse};

/// Async broadcasting trait for ARC.
pub trait AsyncBroadcaster {
    /// Broadcast a transaction asynchronously.
    fn broadcast(
        &self,
        tx: &Transaction,
    ) -> impl std::future::Future<Output = Result<ArcResponse, ArcError>> + Send;
}

/// HTTP client for the ARC API.
#[derive(Debug, Clone)]
pub struct ArcClient {
    /// Client configuration.
    config: ArcConfig,
    /// Underlying HTTP client.
    client: reqwest::Client,
}

impl ArcClient {
    /// Create a new ARC client with the given configuration.
    pub fn new(config: ArcConfig) -> Self {
        let client = reqwest::Client::new();
        Self { config, client }
    }

    /// Broadcast a transaction to the ARC API.
    pub async fn broadcast_async(&self, tx: &Transaction) -> Result<ArcResponse, ArcError> {
        let url = format!("{}/tx", self.config.base_url);
        let raw_tx = tx.to_bytes();
        let headers = self.build_headers();

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(raw_tx)
            .send()
            .await?;

        let response: ArcResponse = resp.json().await?;

        // Check for rejection
        if let Some(status) = response.status {
            if status == 0 {
                return Err(ArcError::Rejected {
                    code: status,
                    description: response
                        .detail
                        .clone()
                        .unwrap_or_else(|| "rejected".to_string()),
                });
            }
        }

        Ok(response)
    }

    /// Query the status of a transaction by txid.
    pub async fn status(&self, txid: &str) -> Result<ArcResponse, ArcError> {
        let url = format!("{}/tx/{}", self.config.base_url, txid);
        let headers = self.build_headers();

        let resp = self.client.get(&url).headers(headers).send().await?;

        let response: ArcResponse = resp.json().await?;
        Ok(response)
    }

    /// Build common headers from config.
    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();

        if let Some(ref key) = self.config.api_key {
            if let Ok(val) = HeaderValue::from_str(&format!("Bearer {key}")) {
                headers.insert(AUTHORIZATION, val);
            }
        }

        if let Some(ref url) = self.config.callback_url {
            if let Ok(val) = HeaderValue::from_str(url) {
                headers.insert("X-CallbackUrl", val);
            }
        }

        if let Some(ref token) = self.config.callback_token {
            if let Ok(val) = HeaderValue::from_str(token) {
                headers.insert("X-CallbackToken", val);
            }
        }

        if let Some(ref status) = self.config.wait_for_status {
            if let Ok(val) = HeaderValue::from_str(&status.as_code().to_string()) {
                headers.insert("X-WaitForStatus", val);
            }
        }

        if self.config.skip_fee_validation {
            headers.insert("X-SkipFeeValidation", HeaderValue::from_static("true"));
        }

        if self.config.skip_script_validation {
            headers.insert("X-SkipScriptValidation", HeaderValue::from_static("true"));
        }

        if self.config.skip_tx_validation {
            headers.insert("X-SkipTxValidation", HeaderValue::from_static("true"));
        }

        if self.config.cumulative_fee_validation {
            headers.insert(
                "X-CumulativeFeeValidation",
                HeaderValue::from_static("true"),
            );
        }

        if self.config.full_status_updates {
            headers.insert("X-FullStatusUpdates", HeaderValue::from_static("true"));
        }

        if let Some(timeout) = self.config.max_timeout {
            if let Ok(val) = HeaderValue::from_str(&timeout.to_string()) {
                headers.insert("X-MaxTimeout", val);
            }
        }

        headers
    }
}

impl AsyncBroadcaster for ArcClient {
    async fn broadcast(&self, tx: &Transaction) -> Result<ArcResponse, ArcError> {
        self.broadcast_async(tx).await
    }
}

impl Broadcaster for ArcClient {
    fn broadcast(&self, tx: &Transaction) -> Result<BroadcastSuccess, SpvError> {
        let result = match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                // We're inside a tokio runtime but need to block.
                // Use block_in_place if in a multi-threaded runtime,
                // otherwise spawn a new thread.
                tokio::task::block_in_place(|| handle.block_on(self.broadcast_async(tx)))
            }
            Err(_) => {
                // No runtime, create one.
                let rt =
                    tokio::runtime::Runtime::new().map_err(|e| SpvError::General(e.to_string()))?;
                rt.block_on(self.broadcast_async(tx))
            }
        };

        match result {
            Ok(resp) => Ok(BroadcastSuccess {
                txid: resp.txid,
                message: resp.tx_status.unwrap_or_default(),
            }),
            Err(e) => Err(SpvError::General(e.to_string())),
        }
    }
}
