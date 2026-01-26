//! Key management operations for KoalaVault clients

use crate::error::{KoavaError, Result};
use crate::ApiResponse;
use koalavault_protocol::api::{GetModelMasterKeyResponse, GetUserSignKeyResponse};

/// Expected jku prefix for KoalaVault keys
const EXPECTED_JKU_PREFIX: &str = "koalavault://";

/// Key vault for caching keys (stores raw JSON data)
#[derive(Debug, Clone)]
pub struct KeyVault {
    cache: Option<serde_json::Value>,
}

impl KeyVault {
    /// Create a new key vault
    pub fn new() -> Self {
        Self { cache: None }
    }

    /// Get cached key (raw JSON)
    pub fn get(&self) -> Option<serde_json::Value> {
        self.cache.clone()
    }

    /// Cache key (raw JSON)
    pub fn set(&mut self, key: serde_json::Value) {
        self.cache = Some(key);
    }

    /// Clear cached key using secure overwrite
    pub fn clear(&mut self) {
        // TODO: safe memory clearing
        self.cache = None;
    }

    /// Check if key is cached
    pub fn has(&self) -> bool {
        self.cache.is_some()
    }
}

impl Default for KeyVault {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that a JWK contains the expected jku prefix
fn validate_jku(jwk: &serde_json::Value, key_type: &str) -> Result<()> {
    let jku = jwk.get("jku").and_then(|v| v.as_str()).ok_or_else(|| {
        KoavaError::validation(format!("Server returned {} without jku field", key_type))
    })?;

    if !jku.starts_with(EXPECTED_JKU_PREFIX) {
        return Err(KoavaError::validation(format!(
            "Invalid jku in {}: expected prefix '{}', got '{}'",
            key_type, EXPECTED_JKU_PREFIX, jku
        )));
    }

    Ok(())
}

use crate::client::ApiClient;

/// Key service for handling cryptographic keys
pub struct KeyService<'a, C: ApiClient + ?Sized> {
    client: &'a C,
}

impl<'a, C: ApiClient + ?Sized> KeyService<'a, C> {
    /// Create a new key service
    pub fn new(client: &'a C) -> Self {
        Self { client }
    }

    /// Request user's sign key pair from the API
    ///
    /// This key is used for digital signing operations and is bound to the authenticated user.
    ///
    /// # Returns
    ///
    /// Returns the private key JWK as raw JSON on success. The private key contains both public and private components.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Authentication fails
    /// - User has no sign key configured
    /// - Network or API errors occur
    pub async fn request_sign_key(&self) -> Result<serde_json::Value> {
        let response: ApiResponse<GetUserSignKeyResponse> = self
            .client
            .authenticated_request(reqwest::Method::GET, "/users/sign-key", None::<&()>)
            .await?;

        match response.data {
            Some(sign_key_data) => {
                // Validate jku before returning
                validate_jku(&sign_key_data.private_key_jwk, "sign key")?;
                Ok(sign_key_data.private_key_jwk)
            }
            None => Err(KoavaError::api(
                200,
                "No sign key found in response".to_string(),
            )),
        }
    }

    /// Request master key for a specific model
    ///
    /// The master key is used for encrypting/decrypting model files. Only the model owner
    /// can access their model's master key. The username is automatically obtained from the authenticated client.
    ///
    /// # Arguments
    ///
    /// * `model_name` - Name/slug of the model
    ///
    /// # Returns
    ///
    /// Returns the master key JWK as raw JSON on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Authentication fails
    /// - Access is denied (not the model owner)
    /// - Model not found
    /// - Network or API errors occur
    /// - Username not available from client
    pub async fn request_master_key(&self, model_name: &str) -> Result<serde_json::Value> {
        let username = self.client.get_current_username().ok_or_else(|| {
            KoavaError::api(401, "Username not available from client".to_string())
        })?;
        let endpoint = format!("/resources/{}/models/{}/master-key", username, model_name);

        let response: ApiResponse<GetModelMasterKeyResponse> = self
            .client
            .authenticated_request(reqwest::Method::GET, &endpoint, None::<&()>)
            .await?;

        match response.data {
            Some(master_key_data) => {
                // Validate jku before returning
                validate_jku(&master_key_data.master_key_jwk, "master key")?;
                Ok(master_key_data.master_key_jwk)
            }
            None => Err(KoavaError::api(
                200,
                "No master key found in response".to_string(),
            )),
        }
    }

    /// Request both sign key and master key for a specific model
    ///
    /// Convenience method that returns encryption (master) key and signing key together.
    /// Returns a tuple in the order (enc_key, sign_key).
    pub async fn request_keys_for_model(
        &self,
        model_name: &str,
    ) -> Result<(serde_json::Value, serde_json::Value)> {
        // Fetch sign key (user-bound)
        let sign_key = self.request_sign_key().await?;
        // Fetch master key (model-bound)
        let enc_key = self.request_master_key(model_name).await?;
        Ok((enc_key, sign_key))
    }
}
