//! Authentication module for KoalaVault clients

use crate::config::Config;
use crate::error::{KoavaError, Result};
use crate::ui::UI;
use crate::{HttpClient, LoginArgs, CURRENT_VERSION};
use std::sync::Arc;

/// Status information for display
#[derive(Debug, Clone)]
pub struct StatusInfo {
    pub version: String,
    pub authenticated: bool,
    pub username: Option<String>,
    pub email: Option<String>,
    pub server_connected: bool,
    pub server_status_msg: String,
    pub hf_status_str: String,
}

/// Authentication service for CLI commands
pub struct AuthService {
    config: Config,
    ui: UI,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new(config: Config) -> Self {
        Self {
            config,
            ui: UI::new(),
        }
    }

    /// Handle login command
    pub async fn login(&self, args: LoginArgs) -> Result<(String, Arc<HttpClient>)> {
        let api_key = {
            #[cfg(debug_assertions)]
            {
                // Debug build: use command line argument
                args.api_key
            }
            #[cfg(not(debug_assertions))]
            {
                // Release build: use interactive input
                if args.api_key.is_some() {
                    // If API key was provided via command line in release build, warn and use interactive
                    self.ui.warning("API key provided via command line is ignored in release builds for security.");
                    self.ui.info("Please enter your API key interactively:");
                }

                dialoguer::Password::new()
                    .with_prompt("Enter your KoalaVault API key")
                    .interact()
                    .map_err(|e| {
                        KoavaError::invalid_input(format!("Failed to read API key: {}", e))
                    })?
            }
        };

        if api_key.is_empty() {
            return Err(KoavaError::invalid_input(
                "API key cannot be empty".to_string(),
            ));
        }

        // Create client and authenticate
        self.ui.info("Authenticating with server...");

        let mut client = HttpClient::new(self.config.clone())?;

        let _access_token = client
            .login(api_key)
            .await
            .map_err(|e| KoavaError::authentication(format!("Authentication failed: {}", e)))?;

        let username = client.get_current_username().ok_or_else(|| {
            KoavaError::authentication("Failed to get username after authentication".to_string())
        })?;

        // Verify that tokens were properly stored
        if !client.is_authenticated() {
            return Err(KoavaError::authentication(
                "Authentication succeeded but token storage failed. Please try again.".to_string(),
            ));
        }

        let client_arc = Arc::new(client);

        self.ui.blank_line();
        self.ui.status("Authentication", "Success", true);
        self.ui
            .success(&format!("Successfully authenticated as: {}", username));
        self.ui
            .info("Your credentials have been securely stored for future use.");

        Ok((username, client_arc))
    }

    /// Handle logout command
    pub async fn logout(&self, client: Option<Arc<HttpClient>>) -> Result<bool> {
        let mut performed_logout = false;

        if let Some(client) = client {
            if let Err(e) = client.logout().await {
                self.ui
                    .warning(&format!("Failed to logout from server: {}", e));
            } else {
                performed_logout = true;
            }
        } else {
            // Create a temporary client using current config so that SDK clears persisted tokens
            if let Ok(temp_client) = HttpClient::new(self.config.clone()) {
                if let Err(e) = temp_client.logout().await {
                    self.ui
                        .warning(&format!("Failed to logout from server: {}", e));
                } else {
                    performed_logout = true;
                }
            }
        }

        if performed_logout {
            self.ui.status("Logout", "Success", true);
            self.ui.success("Logged out successfully");
        } else {
            // Even if remote/logout fails, ensure local session is cleared
            self.ui.status("Logout", "Partial", false);
            self.ui
                .warning("Local session cleared, but remote logout may have failed");
        }

        Ok(performed_logout)
    }

    /// Get or create an authenticated client
    /// This will attempt to create a client using stored tokens.
    /// Returns an error if no valid tokens are found.
    pub async fn get_authenticated_client(&self) -> Result<Arc<HttpClient>> {
        // Create client (it will auto-load tokens if available)
        let client = HttpClient::new(self.config.clone())?;

        // Check if client has valid authentication
        if client.is_authenticated() {
            // Verify tokens are actually valid by making a test request
            if client.get_current_username().is_some() {
                return Ok(Arc::new(client));
            }
        }

        // Tokens invalid or missing - need to re-authenticate
        self.ui
            .warning("No valid stored tokens found. Please run 'koava login' again.");
        Err(KoavaError::authentication(
            "No valid stored tokens found. Please run 'koava login' again.".to_string(),
        ))
    }

    /// Get status information
    pub async fn get_status(&self) -> Result<StatusInfo> {
        // Check authentication status using client
        let mut username_opt: Option<String> = None;
        let mut authenticated = false;

        {
            if let Ok(client) = HttpClient::new(self.config.clone()) {
                // Check authentication status first
                if client.is_authenticated() {
                    username_opt = client.get_current_username();
                    authenticated = username_opt.is_some();
                }
            }
        }

        // Server connection status with detailed error message
        let (server_connected, server_status_msg) = match self.check_server_health().await {
            Ok(_) => (true, "Connected".to_string()),
            Err(e) => {
                let msg = match &e {
                    KoavaError::Network { message, .. } => {
                        // Extract meaningful error message
                        let err_str = message.clone();
                        if err_str.contains("dns error") || err_str.contains("failed to lookup") {
                            "DNS resolution failed - check endpoint URL".to_string()
                        } else if err_str.contains("Connection refused") {
                            "Connection refused - server not running?".to_string()
                        } else if err_str.contains("timeout") {
                            "Connection timeout - server unreachable".to_string()
                        } else {
                            format!("Network error: {}", err_str)
                        }
                    }
                    KoavaError::Config { message, .. } => {
                        if message.contains("Certificate") {
                            "Certificate verification failed".to_string()
                        } else {
                            message.clone()
                        }
                    }
                    _ => e.to_string(),
                };
                (false, msg)
            }
        };

        // Resolve username and email (email fetched from public profile if username is available)
        // If email cannot be fetched, authentication is considered failed
        let mut email_opt: Option<String> = None;

        if let Some(username) = &username_opt {
            // Normalize endpoint to include /api
            let normalized_endpoint = self.config.get_api_endpoint();

            // Build HTTP client (no proxy for localhost)
            let mut builder = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(self.config.timeout))
                .user_agent(format!("koalavault/{}", CURRENT_VERSION));
            let endpoint_lower = normalized_endpoint.to_lowercase();
            if endpoint_lower.contains("localhost") || endpoint_lower.contains("127.0.0.1") {
                builder = builder.no_proxy();
            }
            if let Ok(http) = builder.build() {
                let url = format!(
                    "{}/resources/{}",
                    normalized_endpoint.trim_end_matches('/'),
                    username
                );
                if let Ok(resp) = http.get(&url).send().await {
                    if resp.status().is_success() {
                        if let Ok(json) = resp.json::<serde_json::Value>().await {
                            if let Some(data_val) = json.get("data") {
                                if let Some(email) = data_val.get("email").and_then(|v| v.as_str())
                                {
                                    email_opt = Some(email.to_string());
                                } else if let Some(inner) = data_val.get("data") {
                                    if let Some(email) = inner.get("email").and_then(|v| v.as_str())
                                    {
                                        email_opt = Some(email.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // If email cannot be fetched, authentication is considered failed
            if email_opt.is_none() {
                authenticated = false;
            }
        }

        // Check Hugging Face CLI status
        let hf_status = crate::huggingface::check_huggingface_cli_status(&self.config).await?;
        let hf_status_str = self.ui.format_huggingface_cli_status(&hf_status);

        Ok(StatusInfo {
            version: CURRENT_VERSION.to_string(),
            authenticated,
            username: username_opt,
            email: email_opt,
            server_connected,
            server_status_msg,
            hf_status_str,
        })
    }

    /// Check server health by making a request to the health endpoint
    async fn check_server_health(&self) -> Result<()> {
        // First perform certificate verification
        self.config
            .verify_certificate_pinning()
            .await
            .map_err(|e| KoavaError::config(e.to_string()))?;

        // Normalize endpoint to include /api
        let normalized_endpoint = self.config.get_api_endpoint();

        // Disable proxy for localhost to avoid corporate/system proxy causing 502
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.config.timeout))
            .user_agent(format!("koalavault/{}", CURRENT_VERSION));

        let endpoint_lower = normalized_endpoint.to_lowercase();
        if endpoint_lower.contains("localhost") || endpoint_lower.contains("127.0.0.1") {
            builder = builder.no_proxy();
        }

        let client = builder
            .build()
            .map_err(|e| KoavaError::config(format!("Failed to create HTTP client: {}", e)))?;

        let health_url = format!("{}/health", normalized_endpoint.trim_end_matches('/'));

        let response = client.get(&health_url).send().await.map_err(|e| {
            // Health check failed - error will be propagated
            KoavaError::network_from_reqwest(e)
        })?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            // Server returned non-success status - error will be propagated
            Err(KoavaError::config(format!(
                "Server returned status: {}",
                status
            )))
        }
    }
}
