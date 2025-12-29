//! HTTP client implementations for KoalaVault SDK

use reqwest::{Client, Method};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;

use crate::auth::AuthClient;
use crate::config::ClientConfig;
use crate::error::{ClientError, Result};

/// API response wrapper
#[derive(Debug, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub message: Option<String>,
}

/// Base HTTP client for API operations
#[derive(Debug, Clone)]
pub struct BaseClient {
    pub(crate) client: Client,
    config: ClientConfig,
}

impl BaseClient {
    pub fn new(config: ClientConfig) -> Result<Self> {
        config.validate()?;

        let mut client_builder = Client::builder().timeout(Duration::from_secs(config.timeout));

        if !config.use_proxy {
            client_builder = client_builder.no_proxy();
        }

        let client = client_builder.build()?;

        Ok(Self { client, config })
    }

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

        match serde_json::from_str::<ApiResponse<R>>(&response_text) {
            Ok(api_response) => {
                if !api_response.success {
                    let error_message = api_response
                        .error
                        .or(api_response.message)
                        .unwrap_or_else(|| "Unknown API error".to_string());
                    return Err(ClientError::api(status.as_u16(), error_message).into());
                }
                Ok(api_response)
            }
            Err(_) => Err(ClientError::api(
                status.as_u16(),
                format!("Invalid API response: {}", response_text),
            ).into()),
        }
    }

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
                    return Err(ClientError::api(status.as_u16(), error_message).into());
                }
                Ok(api_response)
            }
            Err(_) => Err(ClientError::api(
                status.as_u16(),
                format!("Invalid API response: {}", response_text),
            ).into()),
        }
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }
}

/// HTTP client with authentication support
#[derive(Debug)]
pub struct HttpClient {
    base_client: BaseClient,
    auth_client: std::sync::Mutex<AuthClient>,
}

impl HttpClient {
    pub fn new(config: ClientConfig) -> Result<Self> {
        let base_client = BaseClient::new(config.clone())?;
        let auth_client = AuthClient::new(config)?;
        Ok(Self {
            base_client,
            auth_client: std::sync::Mutex::new(auth_client),
        })
    }

    pub fn is_authenticated(&self) -> bool {
        self.auth_client.lock().unwrap().is_authenticated()
    }

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
        let access_token = {
            let mut auth_client = self.auth_client.lock().unwrap();
            auth_client.get_access_token().await?
        };

        let url = self.base_client.config.endpoint_url(endpoint);

        let mut request_builder = self
            .base_client
            .client
            .request(method.clone(), &url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", access_token));

        if let Some(data) = payload {
            request_builder = request_builder.json(data);
        }

        let response = request_builder.send().await?;
        let status = response.status();
        let response_text = response.text().await?;

        if status.as_u16() == 401 {
            let error_detail = serde_json::from_str::<ApiResponse<R>>(&response_text)
                .ok()
                .and_then(|r| r.error.or(r.message))
                .unwrap_or_else(|| "Authentication failed".to_string());
            return Err(ClientError::authentication(&error_detail).into());
        }

        if status.as_u16() == 403 {
            let error_detail = serde_json::from_str::<ApiResponse<R>>(&response_text)
                .ok()
                .and_then(|r| r.error.or(r.message))
                .unwrap_or_else(|| "Insufficient permissions".to_string());
            return Err(ClientError::authorization(&error_detail).into());
        }

        match serde_json::from_str::<ApiResponse<R>>(&response_text) {
            Ok(api_response) => {
                if !api_response.success {
                    let error_message = api_response
                        .error
                        .or(api_response.message)
                        .unwrap_or_else(|| "Unknown API error".to_string());
                    return Err(ClientError::api(status.as_u16(), error_message).into());
                }
                Ok(api_response)
            }
            Err(_) => Err(ClientError::api(
                status.as_u16(),
                format!("Invalid API response: {}", response_text),
            ).into()),
        }
    }

    pub async fn authenticate(&mut self, api_key: String) -> Result<String> {
        self.auth_client.lock().unwrap().authenticate(api_key).await
    }

    pub fn config(&self) -> ClientConfig {
        self.auth_client.lock().unwrap().config().clone()
    }

    pub fn get_current_username(&self) -> Option<String> {
        self.auth_client.lock().unwrap().get_current_username()
    }

    pub async fn logout(&self) -> Result<()> {
        self.auth_client.lock().unwrap().logout().await
    }
}

