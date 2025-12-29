//! Configuration management for koava CLI and SDK

use config::{Config, Environment, File};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;

use crate::error::{ClientError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConverterConfig {
    pub endpoint: String,
    pub timeout: u64,
    pub verbose: bool,
    pub storage_dir: PathBuf,
    pub token_storage_enabled: bool,
    pub huggingface_cli_path: Option<PathBuf>,
}

impl Default for ConverterConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://api.koalavault.ai/api".to_string(),
            timeout: 30,
            verbose: false,
            storage_dir: default_storage_dir(),
            token_storage_enabled: true,
            huggingface_cli_path: None,
        }
    }
}

impl ConverterConfig {
    pub async fn load(config_path: Option<&Path>) -> Result<Self> {
        let config_file = match config_path {
            Some(path) => path.to_path_buf(),
            None => default_config_path(),
        };

        if config_file.exists() {
            let content = fs::read_to_string(&config_file).await?;

            match serde_json::from_str::<Self>(&content) {
                Ok(mut config) => {
                    #[cfg(not(debug_assertions))]
                    {
                        config.endpoint = Self::default().endpoint;
                    }

                    if config.huggingface_cli_path.is_none() {
                        let _ = config.detect_huggingface_cli().await;
                    }

                    Ok(config)
                }
                Err(_) => {
                    let mut config = Self::default();
                    let _ = config.detect_huggingface_cli().await;
                    config.save(&config_file).await?;
                    Ok(config)
                }
            }
        } else {
            let mut config = Self::default();
            let _ = config.detect_huggingface_cli().await;
            config.save(&config_file).await?;
            Ok(config)
        }
    }

    pub async fn save(&self, config_path: &Path) -> Result<()> {
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let content = serde_json::to_string_pretty(self)?;
        fs::write(config_path, content).await?;
        Ok(())
    }

    pub fn to_sdk_config(&self) -> ClientConfig {
        let normalized_endpoint = if self.endpoint.ends_with("/api") {
            self.endpoint.clone()
        } else if self.endpoint.ends_with("/") {
            format!("{}api", self.endpoint)
        } else {
            format!("{}/api", self.endpoint)
        };

        let use_proxy =
            !normalized_endpoint.contains("localhost") && !normalized_endpoint.contains("127.0.0.1");

        let mut builder = ClientConfigBuilder::new()
            .base_url(&normalized_endpoint)
            .timeout(self.timeout)
            .verbose(self.verbose)
            .use_proxy(use_proxy);

        if self.token_storage_enabled {
            let token_dir = self.storage_dir.join("tokens");
            let token_config = TokenStorageConfig {
                enabled: true,
                storage_path: Some(token_dir.to_string_lossy().to_string()),
                encryption_key: None,
            };
            builder = builder.token_storage(token_config);
        }

        builder.build().unwrap_or_else(|_| {
            ClientConfigBuilder::new()
                .base_url("https://api.koalavault.ai/api")
                .build()
                .unwrap()
        })
    }

    pub async fn detect_huggingface_cli(&mut self) -> Result<Option<PathBuf>> {
        if let Some(ref path) = self.huggingface_cli_path {
            if path.exists() {
                return Ok(Some(path.clone()));
            }
        }

        let possible_names = if cfg!(target_os = "windows") {
            vec!["hf.exe", "hf"]
        } else {
            vec!["hf"]
        };

        for name in possible_names {
            if let Ok(path) = which::which(name) {
                self.huggingface_cli_path = Some(path.clone());
                self.save(&default_config_path()).await?;
                return Ok(Some(path));
            }
        }

        Ok(None)
    }

    pub async fn check_huggingface_cli_status(&self) -> Result<HuggingFaceCliStatus> {
        let cli_path = match &self.huggingface_cli_path {
            Some(path) if path.exists() => path.clone(),
            _ => return Ok(HuggingFaceCliStatus::NotFound),
        };

        if !cli_path.is_file() {
            return Ok(HuggingFaceCliStatus::NotFound);
        }

        let output = tokio::process::Command::new(&cli_path)
            .arg("auth")
            .arg("whoami")
            .output()
            .await;

        match output {
            Ok(result) if result.status.success() => {
                let stdout = String::from_utf8_lossy(&result.stdout).to_string();
                let stderr = String::from_utf8_lossy(&result.stderr).to_string();
                let merged = if !stdout.trim().is_empty() {
                    stdout
                } else {
                    stderr
                };
                let merged_lower = merged.to_lowercase();

                if merged_lower.contains("not logged in") || merged_lower.contains("not authenticated")
                {
                    return Ok(HuggingFaceCliStatus::NotLoggedIn);
                }

                if let Some(username) = parse_hf_whoami_username(&merged) {
                    Ok(HuggingFaceCliStatus::LoggedIn(username))
                } else {
                    let trimmed = merged.trim();
                    if !trimmed.is_empty() && trimmed.len() < 100 {
                        Ok(HuggingFaceCliStatus::LoggedIn(trimmed.to_string()))
                    } else {
                        Ok(HuggingFaceCliStatus::NotLoggedIn)
                    }
                }
            }
            Ok(_) => Ok(HuggingFaceCliStatus::NotLoggedIn),
            Err(_) => Ok(HuggingFaceCliStatus::NotFound),
        }
    }
}

#[derive(Debug, Clone)]
pub enum HuggingFaceCliStatus {
    NotFound,
    NotLoggedIn,
    LoggedIn(String),
}

fn parse_hf_whoami_username(raw: &str) -> Option<String> {
    let cleaned = strip_ansi_codes(raw);
    let normalized = cleaned.replace('\r', "");

    let first_line = normalized
        .lines()
        .find(|l| !l.trim().is_empty())?
        .trim()
        .to_string();

    let lower = first_line.to_lowercase();
    if lower.contains("not logged in") {
        return None;
    }

    let mut candidate = first_line.clone();
    if let Some(pos) = lower.find("logged in as") {
        let after = &first_line[pos + "logged in as".len()..];
        candidate = after.trim().to_string();
    }

    if candidate.contains(':') {
        if let Some(idx) = candidate.rfind(':') {
            candidate = candidate[idx + 1..].trim().to_string();
        }
    }

    candidate = candidate.trim_matches('"').trim().to_string();

    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.';
    let mut extracted = String::new();
    for ch in candidate.chars() {
        if allowed(ch) {
            extracted.push(ch);
        } else if !extracted.is_empty() {
            break;
        }
    }

    if extracted.is_empty() {
        None
    } else {
        Some(extracted)
    }
}

fn strip_ansi_codes(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&next_ch) = chars.peek() {
                    chars.next();
                    if next_ch.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

pub fn default_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("koalavault")
}

pub fn default_config_path() -> PathBuf {
    default_config_dir().join("config.json")
}

pub fn default_storage_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("koalavault")
}

/// Token storage configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TokenStorageConfig {
    #[serde(default)]
    pub enabled: bool,
    pub storage_path: Option<String>,
    pub encryption_key: Option<String>,
}

impl From<TokenStorageConfig> for crate::store::TokenStoreConfig {
    fn from(config: TokenStorageConfig) -> Self {
        Self {
            enabled: config.enabled,
            storage_path: config.storage_path.map(PathBuf::from),
            encryption_key: config.encryption_key,
        }
    }
}

/// Client configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientConfig {
    pub base_url: String,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub verbose: bool,
    #[serde(default)]
    pub token_storage: TokenStorageConfig,
    #[serde(default = "default_use_proxy")]
    pub use_proxy: bool,
}

fn default_timeout() -> u64 {
    30
}

fn default_use_proxy() -> bool {
    true
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.koalavault.ai/api".to_string(),
            timeout: default_timeout(),
            verbose: false,
            token_storage: TokenStorageConfig::default(),
            use_proxy: default_use_proxy(),
        }
    }
}

/// Builder for ClientConfig
#[derive(Debug, Default)]
pub struct ClientConfigBuilder {
    base_url: Option<String>,
    timeout: Option<u64>,
    verbose: Option<bool>,
    token_storage: Option<TokenStorageConfig>,
    config_file: Option<PathBuf>,
    use_proxy: Option<bool>,
}

impl ClientConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn base_url<S: Into<String>>(mut self, base_url: S) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = Some(verbose);
        self
    }

    pub fn use_proxy(mut self, use_proxy: bool) -> Self {
        self.use_proxy = Some(use_proxy);
        self
    }

    pub fn token_storage(mut self, token_storage: TokenStorageConfig) -> Self {
        self.token_storage = Some(token_storage);
        self
    }

    pub fn config_file<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.config_file = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn build(self) -> Result<ClientConfig> {
        let mut config = ClientConfig::from_file_and_env(self.config_file.as_deref())?;

        #[cfg(debug_assertions)]
        if let Some(base_url) = self.base_url {
            config.base_url = base_url;
        }

        if let Some(timeout) = self.timeout {
            config.timeout = timeout;
        }
        if let Some(verbose) = self.verbose {
            config.verbose = verbose;
        }
        if let Some(token_storage) = self.token_storage {
            config.token_storage = token_storage;
        }
        if let Some(use_proxy) = self.use_proxy {
            config.use_proxy = use_proxy;
        }

        config.validate()?;
        Ok(config)
    }
}

impl ClientConfig {
    pub fn new() -> Result<Self> {
        Self::from_file_and_env::<&str>(None)
    }

    pub fn builder() -> ClientConfigBuilder {
        ClientConfigBuilder::new()
    }

    pub fn from_file_and_env<P: AsRef<Path>>(config_file: Option<P>) -> Result<Self> {
        let mut builder = Config::builder()
            .set_default("base_url", "https://api.koalavault.ai/api")?
            .set_default("timeout", 30)?
            .set_default("verbose", false)?
            .set_default("use_proxy", true)?;

        #[cfg(debug_assertions)]
        {
            if let Some(config_path) = config_file {
                if config_path.as_ref().exists() {
                    builder = builder.add_source(File::from(config_path.as_ref()));
                }
            }
            builder = builder.add_source(Environment::with_prefix("KOALAVAULT").try_parsing(true));
        }

        #[cfg(not(debug_assertions))]
        {
            if let Some(config_path) = config_file {
                if config_path.as_ref().exists() {
                    builder = builder.add_source(File::from(config_path.as_ref()));
                }
            }
            builder = builder.add_source(Environment::with_prefix("KOALAVAULT").try_parsing(true));
            builder = builder.set_override("base_url", "https://api.koalavault.ai/api")?;
        }

        let config = builder.build()?;
        Ok(config.try_deserialize()?)
    }

    pub fn validate(&self) -> Result<()> {
        if self.base_url.is_empty() {
            return Err(ClientError::invalid_input("Base URL cannot be empty").into());
        }
        Ok(())
    }

    pub fn endpoint_url(&self, endpoint: &str) -> String {
        let endpoint = endpoint.strip_prefix('/').unwrap_or(endpoint);
        let base_url = if self.base_url.starts_with("http://") || self.base_url.starts_with("https://")
        {
            if cfg!(not(debug_assertions)) && self.base_url.starts_with("http://") {
                self.base_url.replace("http://", "https://")
            } else {
                self.base_url.clone()
            }
        } else {
            format!("https://{}", self.base_url)
        };

        format!("{}/{}", base_url.trim_end_matches('/'), endpoint)
    }

    /// Verify certificate pinning (placeholder - always returns Ok for now)
    pub async fn verify_certificate_pinning(&self) -> Result<()> {
        Ok(())
    }
}
