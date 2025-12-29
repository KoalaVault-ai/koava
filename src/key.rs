//! Key management for KoalaVault SDK

use serde::Deserialize;

use crate::client::{ApiResponse, HttpClient};
use crate::error::{ClientError, Result};

/// Response for user sign key
#[derive(Debug, Deserialize)]
pub struct SignKeyResponse {
    pub private_key_jwk: serde_json::Value,
    pub public_key_jwk: Option<serde_json::Value>,
}

/// Response for master key
#[derive(Debug, Deserialize)]
pub struct MasterKeyResponse {
    pub master_key_jwk: serde_json::Value,
}

/// Key vault for caching keys
#[derive(Debug, Clone, Default)]
pub struct KeyVault {
    cache: Option<serde_json::Value>,
}

impl KeyVault {
    pub fn new() -> Self {
        Self { cache: None }
    }

    pub fn get(&self) -> Option<serde_json::Value> {
        self.cache.clone()
    }

    pub fn set(&mut self, key: serde_json::Value) {
        self.cache = Some(key);
    }

    pub fn clear(&mut self) {
        self.cache = None;
    }

    pub fn has(&self) -> bool {
        self.cache.is_some()
    }
}

/// Key service for handling cryptographic keys
pub struct KeyService<'a> {
    client: &'a HttpClient,
}

impl<'a> KeyService<'a> {
    pub fn new(client: &'a HttpClient) -> Self {
        Self { client }
    }

    /// Request user's sign key
    pub async fn request_sign_key(&self) -> Result<serde_json::Value> {
        let response: ApiResponse<SignKeyResponse> = self
            .client
            .authenticated_request(reqwest::Method::GET, "/users/sign-key", None::<&()>)
            .await?;

        match response.data {
            Some(sign_key_data) => Ok(sign_key_data.private_key_jwk),
            None => Err(ClientError::api(
                200,
                "No sign key found in response".to_string(),
            ).into()),
        }
    }

    /// Request master key for a model
    pub async fn request_master_key(&self, model_name: &str) -> Result<serde_json::Value> {
        let username = self
            .client
            .get_current_username()
            .ok_or_else(|| ClientError::api(401, "Username not available".to_string()))?;

        let endpoint = format!("/resources/{}/models/{}/master-key", username, model_name);

        let response: ApiResponse<MasterKeyResponse> = self
            .client
            .authenticated_request(reqwest::Method::GET, &endpoint, None::<&()>)
            .await?;

        match response.data {
            Some(master_key_data) => Ok(master_key_data.master_key_jwk),
            None => Err(ClientError::api(
                200,
                "No master key found in response".to_string(),
            ).into()),
        }
    }

    /// Request both sign key and master key
    pub async fn request_keys_for_model(
        &self,
        model_name: &str,
    ) -> Result<(serde_json::Value, serde_json::Value)> {
        let sign_key = self.request_sign_key().await?;
        let enc_key = self.request_master_key(model_name).await?;
        Ok((enc_key, sign_key))
    }
}

