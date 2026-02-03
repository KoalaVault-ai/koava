//! Unified configuration for KoalaVault CLI tool

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;

use crate::error::{KoavaError, Result};
use crate::security::DEFAULT_SERVER_PUBLIC_KEY;
use crate::store::TokenStoreConfig;

/// Unified configuration for KoalaVault CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// API endpoint URL
    #[serde(default = "default_endpoint")]
    pub endpoint: String,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Storage directory for local state and tokens
    #[serde(default = "default_storage_dir")]
    pub storage_dir: PathBuf,

    /// Hugging Face CLI executable path (optional, auto-detected if not set)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub huggingface_cli_path: Option<PathBuf>,

    /// Use system proxy (default: true)
    #[serde(default = "default_use_proxy")]
    pub use_proxy: bool,

    /// Hardcoded public key for certificate pinning (internal use only, not serialized)
    #[serde(skip)]
    server_public_key: String,
}

fn default_endpoint() -> String {
    "https://api.koalavault.ai/api".to_string()
}

fn default_timeout() -> u64 {
    30
}

fn default_use_proxy() -> bool {
    true
}

/// Get default storage directory
pub fn default_storage_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("koalavault")
}

/// Get default configuration directory
pub fn default_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("koalavault")
}

/// Get default configuration file path
pub fn default_config_path() -> PathBuf {
    default_config_dir().join("config.json")
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: default_endpoint(),
            timeout: default_timeout(),
            storage_dir: default_storage_dir(),
            huggingface_cli_path: None,
            use_proxy: default_use_proxy(),
            server_public_key: DEFAULT_SERVER_PUBLIC_KEY.to_string(),
        }
    }
}

impl Config {
    /// Load configuration from file or create default
    pub async fn load() -> Result<Self> {
        Self::load_from(&default_config_path()).await
    }

    /// Load configuration from a specific path
    pub async fn load_from(config_file: &Path) -> Result<Self> {
        if config_file.exists() {
            let content = fs::read_to_string(config_file).await?;

            match serde_json::from_str::<Self>(&content) {
                Ok(mut config) => {
                    // Always set server public key (not serialized)
                    config.server_public_key = DEFAULT_SERVER_PUBLIC_KEY.to_string();

                    // In release mode, enforce default endpoint for security
                    #[cfg(not(debug_assertions))]
                    {
                        config.endpoint = default_endpoint();
                    }

                    Ok(config)
                }
                Err(e) => {
                    // If deserialization fails due to missing fields, try to merge with defaults
                    if e.to_string().contains("missing field") {
                        let partial: serde_json::Value =
                            serde_json::from_str(&content).unwrap_or_default();
                        let mut config = Self::default();

                        // Merge existing fields
                        #[cfg(debug_assertions)]
                        {
                            if let Some(endpoint) = partial.get("endpoint").and_then(|v| v.as_str())
                            {
                                config.endpoint = endpoint.to_string();
                            }
                        }

                        if let Some(timeout) = partial.get("timeout").and_then(|v| v.as_u64()) {
                            config.timeout = timeout;
                        }
                        if let Some(storage_dir) =
                            partial.get("storage_dir").and_then(|v| v.as_str())
                        {
                            config.storage_dir = PathBuf::from(storage_dir);
                        }
                        if let Some(hf_cli_path) =
                            partial.get("huggingface_cli_path").and_then(|v| v.as_str())
                        {
                            config.huggingface_cli_path = Some(PathBuf::from(hf_cli_path));
                        }
                        if let Some(use_proxy) = partial.get("use_proxy").and_then(|v| v.as_bool())
                        {
                            config.use_proxy = use_proxy;
                        }

                        Ok(config)
                    } else {
                        Err(KoavaError::config(format!(
                            "Failed to parse configuration: {}",
                            e
                        )))
                    }
                }
            }
        } else {
            let config = Self::default();
            config.save(config_file).await?;
            Ok(config)
        }
    }

    /// Save configuration to file
    pub async fn save(&self, config_path: &Path) -> Result<()> {
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let content = serde_json::to_string_pretty(self)?;
        fs::write(config_path, content).await?;
        Ok(())
    }

    /// Get token storage configuration
    pub fn token_store_config(&self) -> TokenStoreConfig {
        let token_path = self.storage_dir.join("tokens").join("token.json");
        TokenStoreConfig {
            storage_path: Some(token_path),
            encryption_key: None,
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.endpoint.is_empty() {
            return Err(KoavaError::invalid_input("Endpoint URL cannot be empty"));
        }

        #[cfg(feature = "cert-pinning")]
        {
            #[cfg(debug_assertions)]
            {
                if self.endpoint.starts_with("https://") {
                    crate::security::validate_certificate_pinning(&self.server_public_key)?;
                }
            }

            #[cfg(not(debug_assertions))]
            {
                crate::security::validate_certificate_pinning(&self.server_public_key)?;
            }
        }

        Ok(())
    }

    /// Verify server certificate against pinned public key
    pub async fn verify_certificate_pinning(&self) -> Result<()> {
        crate::security::verify_certificate_pinning(&self.endpoint, &self.server_public_key).await
    }

    /// Get the API base endpoint (ensuring /api suffix and proper scheme)
    pub fn get_api_endpoint(&self) -> String {
        let base = self.endpoint_url("");
        let base = base.trim_end_matches('/');

        if base.ends_with("/api") {
            base.to_string()
        } else {
            format!("{}/api", base)
        }
    }

    /// Get the full URL for an endpoint
    pub fn endpoint_url(&self, endpoint: &str) -> String {
        let endpoint = endpoint.strip_prefix('/').unwrap_or(endpoint);

        let base_url =
            if self.endpoint.starts_with("http://") || self.endpoint.starts_with("https://") {
                if cfg!(not(debug_assertions)) && self.endpoint.starts_with("http://") {
                    self.endpoint.replace("http://", "https://")
                } else {
                    self.endpoint.clone()
                }
            } else {
                format!("https://{}", self.endpoint)
            };

        format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            endpoint.trim_start_matches('/')
        )
    }
}

// ── Config Service for CLI commands ────────────────────────────────────────

use crate::ui::UI;
use crate::{ConfigArgs, ConfigCommand};

/// Config service for CLI commands
pub struct ConfigService {
    config: Config,
    config_path: Option<PathBuf>,
    ui: UI,
}

impl ConfigService {
    /// Create a new config service
    pub fn new(config: Config) -> Self {
        Self {
            config,
            config_path: None,
            ui: UI::new(),
        }
    }

    /// Create a new config service with a custom config path
    pub fn with_config_path(config: Config, path: PathBuf) -> Self {
        Self {
            config,
            config_path: Some(path),
            ui: UI::new(),
        }
    }

    /// Get the path to save/load configuration
    fn get_config_path(&self) -> PathBuf {
        self.config_path.clone().unwrap_or_else(default_config_path)
    }

    /// Handle config command
    pub async fn handle_config(&mut self, args: ConfigArgs) -> Result<()> {
        match args.command {
            ConfigCommand::Show => {
                let config_info = vec![
                    ("KoalaVault Endpoint", self.config.endpoint.clone()),
                    (
                        "KoalaVault Timeout",
                        format!("{} seconds", self.config.timeout),
                    ),
                    (
                        "Storage Directory",
                        self.config.storage_dir.display().to_string(),
                    ),
                    (
                        "Hugging Face CLI",
                        match &self.config.huggingface_cli_path {
                            Some(path) => path.display().to_string(),
                            None => "Auto-detect".to_string(),
                        },
                    ),
                ];
                self.ui.card("Configuration", config_info);
                Ok(())
            }
            #[cfg(debug_assertions)]
            ConfigCommand::SetEndpoint { url } => {
                self.config.endpoint = url.clone();
                self.config.save(&self.get_config_path()).await?;
                self.ui
                    .success(&format!("KoalaVault endpoint set to: {}", url));
                Ok(())
            }
            ConfigCommand::SetTimeout { seconds } => {
                self.config.timeout = seconds;
                self.config.save(&self.get_config_path()).await?;
                self.ui
                    .success(&format!("KoalaVault timeout set to: {} seconds", seconds));
                Ok(())
            }
            ConfigCommand::Reset => {
                self.config = Config::default();
                self.config.save(&self.get_config_path()).await?;
                self.ui.success("Configuration reset to default values");
                Ok(())
            }
            ConfigCommand::SetHuggingfaceCli { path } => {
                if path == "auto" {
                    if let Some(detected_path) =
                        crate::huggingface::detect_huggingface_cli(&mut self.config).await?
                    {
                        self.ui.success(&format!(
                            "Auto-detected Hugging Face CLI: {}",
                            detected_path.display()
                        ));
                    } else {
                        self.ui.warning("Hugging Face CLI not found in PATH");
                    }
                } else {
                    let cli_path = std::path::PathBuf::from(&path);
                    if cli_path.exists() && cli_path.is_file() {
                        self.config.huggingface_cli_path = Some(cli_path.clone());
                        self.config.save(&self.get_config_path()).await?;
                        self.ui.success(&format!(
                            "Hugging Face CLI path set to: {}",
                            cli_path.display()
                        ));
                    } else {
                        self.ui.error(&format!("File not found: {}", path));
                        return Err(KoavaError::config(
                            "Invalid Hugging Face CLI path".to_string(),
                        ));
                    }
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::utils::test_helpers::create_temp_dir;
    use proptest::prelude::*;
    use tokio::fs;

    // Strategy to generate arbitrary Configs
    prop_compose! {
        fn arb_config()(
            endpoint in "https://[a-z]+\\.koalavault\\.ai/api",
            timeout in 1u64..1000u64,
            use_proxy in any::<bool>(),
            storage_dir in "[a-z]+/storage",
            hf_path in proptest::option::of("[a-z]+/hf"),
        ) -> Config {
            Config {
                endpoint,
                timeout,
                storage_dir: PathBuf::from(storage_dir),
                huggingface_cli_path: hf_path.map(PathBuf::from),
                use_proxy,
                server_public_key: DEFAULT_SERVER_PUBLIC_KEY.to_string(), // Keep default for internals
            }
        }
    }

    /// Verifies that the default configuration has the expected values.
    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.timeout, 30);
        assert_eq!(config.endpoint, "https://api.koalavault.ai/api");
        assert!(config.use_proxy);
        assert_eq!(config.huggingface_cli_path, None);
    }

    /// Verifies basic validation logic (e.g. endpoint cannot be empty).
    #[tokio::test]
    async fn test_validate_config_basic() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());
        config.endpoint = "".to_string();
        assert!(config.validate().is_err());
    }

    /// Verifies that the Show command executes without error.
    #[tokio::test]
    async fn test_config_show_scenario() {
        let config = Config::default();
        let mut service = ConfigService::new(config);

        service
            .handle_config(ConfigArgs {
                command: ConfigCommand::Show,
            })
            .await
            .expect("Show command failed to execute");
    }

    /// Verifies that updating the timeout results in the config being updated and saved.
    #[tokio::test]
    async fn test_config_timeout_update_scenario() {
        let temp_dir = create_temp_dir();
        let config_path = temp_dir.path().join("config.json");
        let config = Config::default();
        config.save(&config_path).await.unwrap();

        let mut service = ConfigService::with_config_path(config, config_path.clone());
        service
            .handle_config(ConfigArgs {
                command: ConfigCommand::SetTimeout { seconds: 120 },
            })
            .await
            .expect("SetTimeout command failed");

        assert_eq!(service.config.timeout, 120);

        // Reload to verify persistence
        let loaded = Config::load_from(&config_path).await.unwrap();
        assert_eq!(loaded.timeout, 120);
    }

    /// Verifies that the API endpoint can be updated in debug mode.
    #[tokio::test]
    #[cfg(debug_assertions)]
    async fn test_config_endpoint_update_scenario() {
        let temp_dir = create_temp_dir();
        let config_path = temp_dir.path().join("config.json");
        let config = Config::default();
        config.save(&config_path).await.unwrap();

        let mut service = ConfigService::with_config_path(config, config_path.clone());
        let new_url = "https://custom.api.io".to_string();

        service
            .handle_config(ConfigArgs {
                command: ConfigCommand::SetEndpoint {
                    url: new_url.clone(),
                },
            })
            .await
            .expect("SetEndpoint command failed");

        assert_eq!(service.config.endpoint, new_url);

        let loaded = Config::load_from(&config_path).await.unwrap();
        assert_eq!(loaded.endpoint, new_url);
    }

    /// Verifies that the Reset command restores default configuration values.
    #[tokio::test]
    async fn test_config_reset_scenario() {
        let temp_dir = create_temp_dir();
        let config_path = temp_dir.path().join("config.json");

        // Start with non-default config
        let mut config = Config::default();
        config.timeout = 999;
        config.save(&config_path).await.unwrap();

        let mut service = ConfigService::with_config_path(config, config_path.clone());
        service
            .handle_config(ConfigArgs {
                command: ConfigCommand::Reset,
            })
            .await
            .expect("Reset command failed");

        assert_eq!(service.config.timeout, 30); // Default

        let loaded = Config::load_from(&config_path).await.unwrap();
        assert_eq!(loaded.timeout, 30);
    }

    /// Scenario: Successfully set a valid path for Hugging Face CLI.
    #[tokio::test]
    async fn test_config_hf_cli_valid_path_scenario() {
        let temp_dir = create_temp_dir();
        let config_path = temp_dir.path().join("config.json");
        let hf_cli_path = temp_dir.path().join("hf-cli-mock");
        fs::write(&hf_cli_path, "mock-binary").await.unwrap();

        let config = Config::default();
        config.save(&config_path).await.unwrap();

        let mut service = ConfigService::with_config_path(config, config_path.clone());
        service
            .handle_config(ConfigArgs {
                command: ConfigCommand::SetHuggingfaceCli {
                    path: hf_cli_path.display().to_string(),
                },
            })
            .await
            .expect("SetHuggingfaceCli failed with valid path");

        assert_eq!(
            service.config.huggingface_cli_path,
            Some(hf_cli_path.clone())
        );

        // Reload to verify persistence
        let loaded = Config::load_from(&config_path).await.unwrap();
        assert_eq!(loaded.huggingface_cli_path, Some(hf_cli_path));
    }

    /// Scenario: Attempt to set an invalid (non-existent) path for Hugging Face CLI.
    #[tokio::test]
    async fn test_config_hf_cli_invalid_path_scenario() {
        let config = Config::default();
        let mut service = ConfigService::new(config);

        let result = service
            .handle_config(ConfigArgs {
                command: ConfigCommand::SetHuggingfaceCli {
                    path: "/non/existent/path/to/cli".to_string(),
                },
            })
            .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid Hugging Face CLI path"));
    }

    proptest! {
        /// Verifies that any valid generated configuration can be saved and reloaded correctly (round-trip).
        #[test]
        fn test_save_and_load_roundtrip(config in arb_config()) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let temp_dir = create_temp_dir();
                let config_path = temp_dir.path().join("config.json");

                // Save
                config.save(&config_path).await.unwrap();
                prop_assert!(config_path.exists());

                // Load
                let loaded_config = Config::load_from(&config_path).await.unwrap();

                // Assert equality (ignoring internal fields if any, but Config is simple)
                prop_assert_eq!(loaded_config.endpoint, config.endpoint);
                prop_assert_eq!(loaded_config.timeout, config.timeout);
                prop_assert_eq!(loaded_config.storage_dir, config.storage_dir);
                prop_assert_eq!(loaded_config.huggingface_cli_path, config.huggingface_cli_path);
                prop_assert_eq!(loaded_config.use_proxy, config.use_proxy);
                Ok(())
            }).unwrap();
        }

        /// Verifies that a partial configuration file (only timeout/endpoint) is correctly merged with default values.
        #[test]
        fn test_partial_config_merge_pbt(
            timeout in 1u64..1000u64,
            endpoint in "https://[a-z]+\\.custom\\.com"
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let temp_dir = create_temp_dir();
                let config_path = temp_dir.path().join("partial_config.json");

                // Create partial JSON with just timeout and endpoint
                let partial_json = serde_json::json!({
                    "timeout": timeout,
                    "endpoint": endpoint
                });
                fs::write(&config_path, partial_json.to_string()).await.unwrap();

                // Load - should merge with defaults
                let config = Config::load_from(&config_path).await.unwrap();

                // specific fields updated
                prop_assert_eq!(config.timeout, timeout);
                prop_assert_eq!(config.endpoint, endpoint);

                // other fields should be defaults
                prop_assert_eq!(config.use_proxy, true); // default
                Ok(())
            }).unwrap();
        }

        /// Verifies that endpoint_url correctly joins base URL and endpoint with proper slash handling.
        #[test]
        fn test_endpoint_url_logic(
            base in "https://[a-z0-9.]+",
            endpoint in "[a-z0-9/]+"
        ) {
            let mut config = Config::default();

            // Case 1: Base with trailing slash, endpoint with leading slash
            config.endpoint = format!("{}/", base);
            let result = config.endpoint_url(&format!("/{}", endpoint));
            let expected_endpoint = endpoint.trim_start_matches('/');
            prop_assert_eq!(result, format!("{}/{}", base, expected_endpoint));

            // Case 2: Base without trailing slash, endpoint without leading slash
            config.endpoint = base.clone();
            let result = config.endpoint_url(&endpoint);
            prop_assert_eq!(result, format!("{}/{}", base, expected_endpoint));
        }

        /// Verifies that endpoint_url handles missing schemes by prepending https://.
        #[test]
        fn test_endpoint_url_scheme_handling(
            host in "[a-z0-9.]+",
            endpoint in "[a-z0-9]+"
        ) {
            let mut config = Config::default();
            config.endpoint = host.clone();
            let result = config.endpoint_url(&endpoint);
            prop_assert!(result.starts_with("https://"));
            prop_assert_eq!(result, format!("https://{}/{}", host, endpoint));
        }
    }

    #[test]
    fn test_endpoint_url_specific_cases() {
        let mut config = Config::default();

        // Test base URL with http (should stay http in debug mode)
        #[cfg(debug_assertions)]
        {
            config.endpoint = "http://api.test.com".to_string();
            assert_eq!(
                config.endpoint_url("v1/test"),
                "http://api.test.com/v1/test"
            );
        }

        // Test base URL already having https
        config.endpoint = "https://api.test.com/".to_string();
        assert_eq!(
            config.endpoint_url("/v1/test"),
            "https://api.test.com/v1/test"
        );

        // Test with empty endpoint (though validate() prevents this in practice, the method itself should handle it)
        config.endpoint = "api.test.com".to_string();
        assert_eq!(config.endpoint_url(""), "https://api.test.com/");
    }

    #[test]
    fn test_get_api_endpoint() {
        let mut config = Config::default();

        // Case 1: No /api suffix
        config.endpoint = "https://example.com".to_string();
        assert_eq!(config.get_api_endpoint(), "https://example.com/api");

        // Case 2: With /api suffix
        config.endpoint = "https://example.com/api".to_string();
        assert_eq!(config.get_api_endpoint(), "https://example.com/api");

        // Case 3: With trailing slash
        config.endpoint = "https://example.com/".to_string();
        assert_eq!(config.get_api_endpoint(), "https://example.com/api");

        // Case 4: With /api/ suffix
        config.endpoint = "https://example.com/api/".to_string();
        assert_eq!(config.get_api_endpoint(), "https://example.com/api");

        // Case 5: Missing scheme (adds https)
        config.endpoint = "example.com".to_string();
        assert_eq!(config.get_api_endpoint(), "https://example.com/api");
    }
}
