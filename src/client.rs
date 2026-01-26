//! HTTP client types for KoalaVault API

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use koalavault_protocol::api::auth::{
    InferenceLoginRequest, InferenceLoginResponse as AuthResponse, RefreshTokenRequest,
    RefreshTokenResponse, RevokeRefreshTokenRequest,
};
// Re-export TokenResponse for external use
pub use koalavault_protocol::api::auth::InferenceLoginResponse as TokenResponse;

/// Standard API response wrapper
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

// Manually implement Clone only when T implements Clone
impl<T: Clone> Clone for ApiResponse<T> {
    fn clone(&self) -> Self {
        Self {
            success: self.success,
            data: self.data.clone(),
            message: self.message.clone(),
            error: self.error.clone(),
            timestamp: self.timestamp,
        }
    }
}
use reqwest::{Client, Method};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Mutex;
use std::time::Duration;

use crate::config::Config;
use crate::error::{KoavaError, Result};
use crate::store::{StoredToken, TokenStore};

/// Base HTTP client for API operations
#[derive(Debug, Clone)]
pub struct BaseClient {
    pub(crate) client: Client,
    config: Config,
}

impl BaseClient {
    /// Create a new base client
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;

        let mut client_builder = Client::builder().timeout(Duration::from_secs(config.timeout));

        // Handle proxy configuration
        if !config.use_proxy {
            client_builder = client_builder.no_proxy();
        }

        let client = client_builder.build()?;

        Ok(Self { client, config })
    }

    /// Make an HTTP request
    pub async fn request<T, R>(
        &self,
        method: Method,
        endpoint: &str,
        payload: Option<&T>,
    ) -> Result<ApiResponse<R>>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        let url = self.config.endpoint_url(endpoint);

        let mut request_builder = self
            .client
            .request(method, &url)
            .header("Content-Type", "application/json");

        if let Some(data) = payload {
            request_builder = request_builder.json(data);
        }

        let response = request_builder.send().await?;
        let status = response.status();

        let response_text = response.text().await?;

        // Try to parse as API response
        match serde_json::from_str::<ApiResponse<R>>(&response_text) {
            Ok(api_response) => {
                if !api_response.success {
                    let error_message = api_response
                        .error
                        .or(api_response.message)
                        .unwrap_or_else(|| "Unknown API error".to_string());

                    return Err(KoavaError::api(status.as_u16(), error_message));
                }
                Ok(api_response)
            }
            Err(_) => {
                // If parsing fails, treat as an error
                Err(KoavaError::api(
                    status.as_u16(),
                    format!("Invalid API response: {}", response_text),
                ))
            }
        }
    }

    /// Make an HTTP request with a Bearer token
    pub async fn request_with_bearer<T, R>(
        &self,
        method: Method,
        endpoint: &str,
        payload: Option<&T>,
        bearer_token: &str,
    ) -> Result<ApiResponse<R>>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        let url = self.config.endpoint_url(endpoint);

        let mut request_builder = self
            .client
            .request(method, &url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", bearer_token));

        if let Some(data) = payload {
            request_builder = request_builder.json(data);
        }

        let response = request_builder.send().await?;
        let status = response.status();

        let response_text = response.text().await?;

        match serde_json::from_str::<ApiResponse<R>>(&response_text) {
            Ok(api_response) => {
                if !api_response.success {
                    let error_message = api_response
                        .error
                        .or(api_response.message)
                        .unwrap_or_else(|| "Unknown API error".to_string());
                    return Err(KoavaError::api(status.as_u16(), error_message));
                }
                Ok(api_response)
            }
            Err(_) => Err(KoavaError::api(
                status.as_u16(),
                format!("Invalid API response: {}", response_text),
            )),
        }
    }

    /// Get the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }
}

/// Trait for API client operations
pub trait ApiClient: Send + Sync {
    /// Check if client has valid authentication
    fn is_authenticated(&self) -> bool;

    /// Login using API key
    fn login(
        &mut self,
        api_key: String,
    ) -> impl std::future::Future<Output = Result<String>> + Send;

    /// Logout and clear tokens
    fn logout(&self) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Get current username
    fn get_current_username(&self) -> Option<String>;

    /// Get configuration
    fn config(&self) -> &Config;

    /// Make an authenticated request
    fn authenticated_request<T, R>(
        &self,
        method: Method,
        endpoint: &str,
        payload: Option<&T>,
    ) -> impl std::future::Future<Output = Result<ApiResponse<R>>> + Send
    where
        T: Serialize + Send + Sync + 'static,
        R: DeserializeOwned + Send + 'static;
}

/// HTTP client with authentication support and automatic token refresh
#[derive(Debug)]
pub struct HttpClient {
    base_client: BaseClient,
    token_data: Mutex<Option<StoredToken>>,
    token_store: Mutex<TokenStore>,
}

impl HttpClient {
    /// Create a new authenticated HTTP client
    pub fn new(config: Config) -> Result<Self> {
        let base_client = BaseClient::new(config.clone())?;

        // Initialize token store
        let store_config = config.token_store_config();
        let token_store = TokenStore::new(store_config)?;

        let mut client = Self {
            base_client,
            token_data: Mutex::new(None),
            token_store: Mutex::new(token_store),
        };

        // Load available tokens
        client.load_available_tokens();

        Ok(client)
    }

    /// Check if client has valid authentication
    pub fn is_authenticated(&self) -> bool {
        self.token_data.lock().unwrap().is_some()
    }

    /// Make an authenticated HTTP request with automatic token refresh
    pub async fn authenticated_request<T, R>(
        &self,
        method: Method,
        endpoint: &str,
        payload: Option<&T>,
    ) -> Result<ApiResponse<R>>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        // Get a valid access token (will refresh if needed)
        let access_token = self.get_access_token().await?;

        // Use BaseClient's request_with_bearer method
        let response = self
            .base_client
            .request_with_bearer(method, endpoint, payload, &access_token)
            .await?;

        // Handle authentication/authorization errors with detailed messages
        // Note: request_with_bearer already handles API errors, but we add specific error handling here
        Ok(response)
    }

    /// Login using API key
    pub async fn login(&mut self, api_key: String) -> Result<String> {
        // Verify certificate pinning in release mode before authentication
        self.base_client
            .config()
            .verify_certificate_pinning()
            .await?;

        let request = InferenceLoginRequest { api_key };

        let response: ApiResponse<AuthResponse> = self
            .base_client
            .request(Method::POST, "/auth/inference-login", Some(&request))
            .await?;

        let data = response
            .data
            .ok_or_else(|| KoavaError::authentication("No data in authentication response"))?;

        // Store token data
        let stored_token = StoredToken {
            username: data.username.clone(),
            access_token: data.access_token.clone(),
            refresh_token: data.refresh_token.clone(),
            expires_at: data.expires_at,
            refresh_expires_at: data.refresh_expires_at,
            token_type: data.token_type.clone(),
        };

        *self.token_data.lock().unwrap() = Some(stored_token.clone());

        // Store tokens if storage is enabled
        self.token_store
            .lock()
            .unwrap()
            .store_tokens(stored_token)?;

        Ok(data.access_token)
    }

    /// Get the configuration
    pub fn config(&self) -> &Config {
        self.base_client.config()
    }

    /// Get current username
    pub fn get_current_username(&self) -> Option<String> {
        self.token_store.lock().unwrap().get_username()
    }

    /// Logout and clear all stored tokens
    pub async fn logout(&self) -> Result<()> {
        // Try to revoke refresh token on server if we have one
        let refresh_token = {
            let token_data = self.token_data.lock().unwrap();
            token_data.as_ref().map(|t| t.refresh_token.clone())
        };

        if let Some(refresh_token) = refresh_token {
            if let Err(_e) = self.revoke_refresh_token(&refresh_token).await {
                // Continue with local logout even if server revoke fails
            }
        }

        // Clear local storage
        self.token_store.lock().unwrap().remove_tokens()?;

        *self.token_data.lock().unwrap() = None;

        Ok(())
    }

    // Private methods

    /// Refresh access token using refresh token
    async fn refresh_token(&self) -> Result<String> {
        // Verify certificate pinning in release mode before refreshing token
        self.base_client
            .config()
            .verify_certificate_pinning()
            .await?;

        let refresh_token = {
            let token_data = self.token_data.lock().unwrap();
            token_data
                .as_ref()
                .map(|t| t.refresh_token.clone())
                .ok_or_else(|| KoavaError::authentication("No refresh token available"))?
        };

        let request = RefreshTokenRequest { refresh_token };

        let response: ApiResponse<RefreshTokenResponse> = self
            .base_client
            .request(Method::POST, "/auth/refresh", Some(&request))
            .await?;

        let data = response
            .data
            .ok_or_else(|| KoavaError::authentication("No data in refresh response"))?;

        // Update token data
        let mut token_data = self.token_data.lock().unwrap();
        if let Some(token) = token_data.as_mut() {
            token.access_token = data.access_token.clone();
            token.refresh_token = data.refresh_token.clone();
            token.expires_at = data.expires_at;
            token.refresh_expires_at = data.refresh_expires_at;
            token.token_type = data.token_type.clone();
            token.username = data.username.clone();

            // Sync with store
            self.token_store
                .lock()
                .unwrap()
                .store_tokens(token.clone())?;
        }

        Ok(data.access_token)
    }

    /// Get the current access token, refreshing if necessary
    async fn get_access_token(&self) -> Result<String> {
        // Check if we have a valid access token
        let token = {
            let token_data = self.token_data.lock().unwrap();
            token_data.clone()
        };

        if let Some(token) = token {
            let now = Utc::now();
            // Refresh if token expires in the next 60 seconds
            if token.expires_at > now + ChronoDuration::seconds(60) {
                return Ok(token.access_token.clone());
            }

            // Try to refresh token if refresh token is still valid
            if token.refresh_expires_at > now {
                match self.refresh_token().await {
                    Ok(new_token) => return Ok(new_token),
                    Err(_e) => {
                        // Fall through to return error
                    }
                }
            }
        }

        // Return error if no valid tokens - user needs to re-authenticate
        Err(KoavaError::authentication(
            "No valid tokens available. Please re-authenticate.",
        ))
    }

    /// Load stored tokens (only one user supported)
    fn load_available_tokens(&mut self) {
        if let Some(stored_token) = self.token_store.lock().unwrap().get_tokens() {
            *self.token_data.lock().unwrap() = Some(stored_token);
        }
    }

    /// Revoke refresh token on server
    async fn revoke_refresh_token(&self, refresh_token: &str) -> Result<()> {
        // Verify certificate pinning in release mode before revoking token
        self.base_client
            .config()
            .verify_certificate_pinning()
            .await?;

        let request = RevokeRefreshTokenRequest {
            refresh_token: refresh_token.to_string(),
        };

        // Prefer using access token if present for authenticated revoke
        let access_token = {
            let token_data = self.token_data.lock().unwrap();
            token_data.as_ref().map(|t| t.access_token.clone())
        };

        if let Some(access_token) = access_token {
            let _response: ApiResponse<serde_json::Value> = self
                .base_client
                .request_with_bearer(Method::POST, "/auth/revoke", Some(&request), &access_token)
                .await?;
        } else {
            // Fall back to unauthenticated request
            let _response: ApiResponse<serde_json::Value> = self
                .base_client
                .request(Method::POST, "/auth/revoke", Some(&request))
                .await?;
        }

        Ok(())
    }
}

impl ApiClient for HttpClient {
    fn is_authenticated(&self) -> bool {
        self.is_authenticated()
    }

    async fn login(&mut self, api_key: String) -> Result<String> {
        self.login(api_key).await
    }

    async fn logout(&self) -> Result<()> {
        self.logout().await
    }

    fn get_current_username(&self) -> Option<String> {
        self.get_current_username()
    }

    fn config(&self) -> &Config {
        self.config()
    }

    async fn authenticated_request<T, R>(
        &self,
        method: Method,
        endpoint: &str,
        payload: Option<&T>,
    ) -> Result<ApiResponse<R>>
    where
        T: Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        self.authenticated_request(method, endpoint, payload).await
    }
}
