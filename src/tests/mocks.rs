//! Mock implementations for testing

use crate::client::{ApiClient, ApiResponse};
use crate::config::Config;
use crate::error::Result;
use reqwest::Method;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::{Arc, Mutex};

/// Simple mock API client for testing
#[derive(Debug, Clone)]
pub struct MockApiClient {
    pub is_authenticated: bool,
    pub username: Option<String>,
    pub config: Config,
    /// Store responses for different endpoints
    pub responses: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
}

impl MockApiClient {
    pub fn new(config: Config) -> Self {
        Self {
            is_authenticated: false,
            username: None,
            config,
            responses: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_auth(mut self, username: String) -> Self {
        self.is_authenticated = true;
        self.username = Some(username);
        self
    }

    pub fn add_response(&self, endpoint: String, response: serde_json::Value) {
        self.responses.lock().unwrap().push((endpoint, response));
    }
}

impl ApiClient for MockApiClient {
    fn is_authenticated(&self) -> bool {
        self.is_authenticated
    }

    async fn login(&mut self, _api_key: String) -> Result<String> {
        self.is_authenticated = true;
        self.username = Some("testuser".to_string());
        Ok("mock_access_token".to_string())
    }

    async fn logout(&self) -> Result<()> {
        Ok(())
    }

    fn get_current_username(&self) -> Option<String> {
        self.username.clone()
    }

    fn config(&self) -> &Config {
        &self.config
    }

    async fn authenticated_request<T, R>(
        &self,
        _method: Method,
        endpoint: &str,
        _payload: Option<&T>,
    ) -> Result<ApiResponse<R>>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static,
    {
        // Find matching response
        let responses = self.responses.lock().unwrap();
        for (ep, response) in responses.iter() {
            if ep == endpoint {
                let data: R = serde_json::from_value(response.clone())
                    .map_err(|e| crate::error::KoavaError::serialization(e.to_string()))?;
                return Ok(ApiResponse {
                    success: true,
                    data: Some(data),
                    message: None,
                    error: None,
                    timestamp: chrono::Utc::now(),
                });
            }
        }

        // Default empty response
        Ok(ApiResponse {
            success: true,
            data: None,
            message: None,
            error: None,
            timestamp: chrono::Utc::now(),
        })
    }
}
