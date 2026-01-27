//! Mock implementations for testing

use crate::client::{ApiClient, ApiResponse};
use crate::config::Config;
use crate::error::{KoavaError, Result};
use reqwest::Method;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Recorded request for verification
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: Method,
    pub endpoint: String,
    pub payload: Option<serde_json::Value>,
}

/// Simple mock API client for testing
#[derive(Debug, Clone)]
pub struct MockApiClient {
    pub is_authenticated: bool,
    pub username: Option<String>,
    pub config: Config,
    /// Store responses for different endpoints
    /// Key: endpoint
    /// Value: JSON response data
    pub responses: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    /// Store error responses for different endpoints
    /// Key: endpoint
    /// Value: KoavaError
    pub errors: Arc<Mutex<HashMap<String, KoavaError>>>,
    /// Recorded requests for verification
    pub requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl MockApiClient {
    pub fn new(config: Config) -> Self {
        Self {
            is_authenticated: false,
            username: None,
            config,
            responses: Arc::new(Mutex::new(HashMap::new())),
            errors: Arc::new(Mutex::new(HashMap::new())),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_auth(mut self, username: String) -> Self {
        self.is_authenticated = true;
        self.username = Some(username);
        self
    }

    pub fn add_response(&self, endpoint: String, response: serde_json::Value) {
        self.responses.lock().unwrap().insert(endpoint, response);
    }

    pub fn add_error(&self, endpoint: String, error: KoavaError) {
        self.errors.lock().unwrap().insert(endpoint, error);
    }

    pub fn get_requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
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
        method: Method,
        endpoint: &str,
        payload: Option<&T>,
    ) -> Result<ApiResponse<R>>
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static,
    {
        // Record the request
        let payload_json = if let Some(p) = payload {
            Some(serde_json::to_value(p).unwrap_or(serde_json::Value::Null))
        } else {
            None
        };

        self.requests.lock().unwrap().push(RecordedRequest {
            method: method.clone(),
            endpoint: endpoint.to_string(),
            payload: payload_json,
        });

        // Check for specific error first
        if let Some(err) = self.errors.lock().unwrap().get(endpoint) {
            return Err(err.clone());
        }

        // Find matching response
        let responses = self.responses.lock().unwrap();
        if let Some(response) = responses.get(endpoint) {
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
