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

/// Load a key (JWK) from a file
///
/// Reads a JSON file and parses it as a JWK (serde_json::Value).
pub async fn load_key_from_file(path: &std::path::Path) -> Result<serde_json::Value> {
    if !path.exists() {
        return Err(KoavaError::validation(format!(
            "Key file not found: {}",
            path.display()
        )));
    }

    let content = tokio::fs::read_to_string(path).await.map_err(|e| {
        KoavaError::io(
            "Read key file",
            format!("Failed to read key file {}: {}", path.display(), e),
        )
    })?;

    let key: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
        KoavaError::validation(format!(
            "Invalid JSON in key file {}: {}",
            path.display(),
            e
        ))
    })?;

    // Basic JWK validation
    if key.get("kty").is_none() {
        return Err(KoavaError::validation(format!(
            "Invalid JWK: missing 'kty' field in {}",
            path.display()
        )));
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::tests::mocks::MockApiClient;
    use serde_json::json;

    // Helper to create client
    fn create_client() -> MockApiClient {
        MockApiClient::new(Config::default())
    }

    // ─────────────────────────────────────────────────────────────
    // KeyVault Tests
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn test_key_vault_crud() {
        let mut vault = KeyVault::new();
        assert!(!vault.has());
        assert!(vault.get().is_none());

        let key_data = json!({"kty": "OKP", "crv": "Ed25519"});
        vault.set(key_data.clone());

        assert!(vault.has());
        assert_eq!(vault.get(), Some(key_data));

        vault.clear();
        assert!(!vault.has());
        assert!(vault.get().is_none());
    }

    #[test]
    fn test_validate_jku_valid() {
        let valid_key = json!({
            "jku": "koalavault://users/testuser/sign-key"
        });
        assert!(validate_jku(&valid_key, "test key").is_ok());
    }

    #[test]
    fn test_validate_jku_invalid() {
        let invalid_prefix = json!({
            "jku": "https://malicious.com/key"
        });
        assert!(validate_jku(&invalid_prefix, "test key").is_err());

        let no_jku = json!({
            "kty": "OKP"
        });
        assert!(validate_jku(&no_jku, "test key").is_err());
    }

    // ─────────────────────────────────────────────────────────────
    // KeyService Tests
    // ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_request_sign_key_success() {
        let client = create_client().with_auth("testuser".to_string());
        let service = KeyService::new(&client);

        let expected_key = json!({
            "kty": "OKP",
            "jku": "koalavault://users/testuser/sign-key"
        });

        // Mock response
        let response_data = json!({
            "private_key_jwk": expected_key
        });
        client.add_response("/users/sign-key".to_string(), response_data);

        let result = service.request_sign_key().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_key);
    }

    #[tokio::test]
    async fn test_request_sign_key_invalid_jku() {
        let client = create_client().with_auth("testuser".to_string());
        let service = KeyService::new(&client);

        // Mock response with invalid JKU
        let response_data = json!({
            "private_key_jwk": {
                "jku": "http://unsafe.com/key"
            }
        });
        client.add_response("/users/sign-key".to_string(), response_data);

        let result = service.request_sign_key().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid jku"));
    }

    #[tokio::test]
    async fn test_request_sign_key_not_found() {
        let client = create_client().with_auth("testuser".to_string());
        let service = KeyService::new(&client); // No response added

        let result = service.request_sign_key().await;
        // Mock client returns None data by default if not found, which KeyService maps to error
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("200"));
    }

    #[tokio::test]
    async fn test_request_master_key_success() {
        let client = create_client().with_auth("testuser".to_string());
        let service = KeyService::new(&client);

        let expected_key = json!({
            "kty": "oct",
            "k": "secret",
            "jku": "koalavault://resources/testuser/models/test-model/master-key"
        });

        // Mock response
        let response_data = json!({
            "master_key_jwk": expected_key
        });
        client.add_response(
            "/resources/testuser/models/test-model/master-key".to_string(),
            response_data,
        );

        let result = service.request_master_key("test-model").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_key);
    }

    #[tokio::test]
    async fn test_request_master_key_no_username() {
        let client = create_client(); // Not authenticated
        let service = KeyService::new(&client);

        let result = service.request_master_key("test-model").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("401"));
    }

    #[tokio::test]
    async fn test_request_keys_for_model() {
        let client = create_client().with_auth("testuser".to_string());
        let service = KeyService::new(&client);

        // Mock Sign Key
        let sign_key = json!({ "jku": "koalavault://users/testuser/sign-key" });
        client.add_response(
            "/users/sign-key".to_string(),
            json!({ "private_key_jwk": sign_key }),
        );

        // Mock Master Key
        let master_key =
            json!({ "jku": "koalavault://resources/testuser/models/test-model/master-key" });
        client.add_response(
            "/resources/testuser/models/test-model/master-key".to_string(),
            json!({ "master_key_jwk": master_key }),
        );

        let result = service.request_keys_for_model("test-model").await;
        assert!(result.is_ok());
        let (enc, sign) = result.unwrap();
        assert_eq!(enc, master_key);
        assert_eq!(sign, sign_key);
    }

    #[tokio::test]
    async fn test_load_key_from_file_success() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("test_key.json");

        let valid_key = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "d": "some_private_bytes",
            "x": "some_public_bytes"
        });

        tokio::fs::write(&key_path, valid_key.to_string())
            .await
            .unwrap();

        let result = load_key_from_file(&key_path).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), valid_key);
    }

    #[tokio::test]
    async fn test_load_key_from_file_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("non_existent.json");

        let result = load_key_from_file(&key_path).await;
        assert!(result.is_err());
        // Error should be validation error about file not found
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_load_key_from_file_invalid_json() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("invalid.json");

        tokio::fs::write(&key_path, "not a json").await.unwrap();

        let result = load_key_from_file(&key_path).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid JSON"));
    }

    #[tokio::test]
    async fn test_load_key_from_file_missing_kty() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("no_kty.json");

        // Valid JSON but not a valid JWK (missing kty)
        let invalid_jwk = json!({
            "alg": "EdDSA"
        });

        tokio::fs::write(&key_path, invalid_jwk.to_string())
            .await
            .unwrap();

        let result = load_key_from_file(&key_path).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing 'kty'"));
    }
}
