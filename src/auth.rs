//! Authentication module for KoalaVault SDK

use chrono::{DateTime, Duration, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::client::{ApiResponse, BaseClient};
use crate::config::ClientConfig;
use crate::error::{ClientError, Result};
use crate::store::{StoredToken, TokenStore, TokenStoreConfig};

#[derive(Debug, Serialize)]
pub struct InferenceLoginRequest {
    pub api_key: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: Option<String>,
    pub expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub refresh_expires_in: i64,
    pub token_type: String,
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub refresh_expires_in: i64,
    pub token_type: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeRefreshTokenRequest {
    pub refresh_token: String,
}

/// Authentication client
#[derive(Debug)]
pub struct AuthClient {
    base_client: BaseClient,
    username: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    token_expires_at: Option<DateTime<Utc>>,
    refresh_token_expires_at: Option<DateTime<Utc>>,
    token_store: Option<TokenStore>,
}

impl AuthClient {
    pub fn new(config: ClientConfig) -> Result<Self> {
        let base_client = BaseClient::new(config.clone())?;

        let token_store = if config.token_storage.enabled {
            let store_config: TokenStoreConfig = config.token_storage.into();
            Some(TokenStore::new(store_config)?)
        } else {
            None
        };

        let mut auth_client = Self {
            base_client,
            username: None,
            access_token: None,
            refresh_token: None,
            token_expires_at: None,
            refresh_token_expires_at: None,
            token_store,
        };

        if auth_client.token_store.is_some() {
            auth_client.load_available_tokens();
        }

        Ok(auth_client)
    }

    pub async fn authenticate(&mut self, api_key: String) -> Result<String> {
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
            .ok_or_else(|| ClientError::authentication("No data in authentication response"))?;

        self.access_token = Some(data.access_token.clone());
        self.refresh_token = Some(data.refresh_token);

        let now = Utc::now();
        self.token_expires_at = Some(now + Duration::minutes(data.expires_in));
        self.refresh_token_expires_at = Some(now + Duration::hours(data.refresh_expires_in));

        self.username = Some(data.username.clone());
        self.store_current_tokens()?;

        Ok(data.access_token)
    }

    pub async fn refresh_token(&mut self) -> Result<String> {
        self.base_client
            .config()
            .verify_certificate_pinning()
            .await?;

        let refresh_token = self
            .refresh_token
            .as_ref()
            .ok_or_else(|| ClientError::authentication("No refresh token available"))?;

        let request = RefreshTokenRequest {
            refresh_token: refresh_token.clone(),
        };

        let response: ApiResponse<RefreshTokenResponse> = self
            .base_client
            .request(Method::POST, "/auth/refresh", Some(&request))
            .await?;

        let data = response
            .data
            .ok_or_else(|| ClientError::authentication("No data in refresh response"))?;

        self.access_token = Some(data.access_token.clone());
        self.refresh_token = Some(data.refresh_token);

        let now = Utc::now();
        self.token_expires_at = Some(now + Duration::minutes(data.expires_in));
        self.refresh_token_expires_at = Some(now + Duration::hours(data.refresh_expires_in));

        if self.username.is_none() {
            if let Some(store) = &self.token_store {
                if let Some(stored_username) = store.get_username() {
                    self.username = Some(stored_username);
                }
            }
        }

        self.store_current_tokens()?;
        Ok(data.access_token)
    }

    pub async fn get_access_token(&mut self) -> Result<String> {
        if let Some(token) = &self.access_token {
            if let Some(expires_at) = self.token_expires_at {
                let now = Utc::now();
                if expires_at > now + Duration::seconds(60) {
                    return Ok(token.clone());
                }
            }
        }

        if self.refresh_token.is_some() {
            if let Some(refresh_expires_at) = self.refresh_token_expires_at {
                let now = Utc::now();
                if refresh_expires_at > now {
                    if let Ok(token) = self.refresh_token().await {
                        return Ok(token);
                    }
                }
            }
        }

        Err(ClientError::authentication(
            "No valid tokens available. Please re-authenticate.",
        ).into())
    }

    pub fn is_authenticated(&self) -> bool {
        self.access_token.is_some() && self.refresh_token.is_some()
    }

    pub fn clear_tokens(&mut self) {
        self.username = None;
        self.access_token = None;
        self.refresh_token = None;
        self.token_expires_at = None;
        self.refresh_token_expires_at = None;
    }

    pub fn config(&self) -> &ClientConfig {
        self.base_client.config()
    }

    fn load_stored_tokens(&mut self, stored_token: StoredToken) {
        let now = Utc::now();

        if stored_token.refresh_token_expires_at > now {
            self.username = Some(stored_token.username);
            self.access_token = Some(stored_token.access_token);
            self.refresh_token = Some(stored_token.refresh_token);
            self.token_expires_at = Some(stored_token.access_token_expires_at);
            self.refresh_token_expires_at = Some(stored_token.refresh_token_expires_at);
        }
    }

    fn store_current_tokens(&mut self) -> Result<()> {
        if let Some(store) = &mut self.token_store {
            if let (
                Some(username),
                Some(access_token),
                Some(refresh_token),
                Some(access_expires),
                Some(refresh_expires),
            ) = (
                &self.username,
                &self.access_token,
                &self.refresh_token,
                &self.token_expires_at,
                &self.refresh_token_expires_at,
            ) {
                let stored_token = StoredToken {
                    username: username.clone(),
                    access_token: access_token.clone(),
                    refresh_token: refresh_token.clone(),
                    access_token_expires_at: *access_expires,
                    refresh_token_expires_at: *refresh_expires,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                };

                store.store_tokens(stored_token)?;
            }
        }
        Ok(())
    }

    pub async fn logout(&mut self) -> Result<()> {
        if let Some(refresh_token) = &self.refresh_token {
            let _ = self.revoke_refresh_token(refresh_token).await;
        }

        if let Some(store) = &mut self.token_store {
            store.remove_tokens()?;
        }

        self.clear_tokens();
        Ok(())
    }

    pub fn load_available_tokens(&mut self) {
        if let Some(store) = &mut self.token_store {
            if let Some(stored_token) = store.get_tokens() {
                self.load_stored_tokens(stored_token);
            }
        }
    }

    pub fn get_current_username(&self) -> Option<String> {
        self.username
            .clone()
            .or_else(|| self.token_store.as_ref().and_then(|store| store.get_username()))
    }

    async fn revoke_refresh_token(&self, refresh_token: &str) -> Result<()> {
        self.base_client
            .config()
            .verify_certificate_pinning()
            .await?;

        let request = RevokeRefreshTokenRequest {
            refresh_token: refresh_token.to_string(),
        };

        if let Some(access_token) = &self.access_token {
            let _: ApiResponse<serde_json::Value> = self
                .base_client
                .request_with_bearer(
                    reqwest::Method::POST,
                    "/auth/revoke",
                    Some(&request),
                    access_token,
                )
                .await?;
        } else {
            let _: ApiResponse<serde_json::Value> = self
                .base_client
                .request(reqwest::Method::POST, "/auth/revoke", Some(&request))
                .await?;
        }

        Ok(())
    }
}

