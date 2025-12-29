//! Token storage for KoalaVault SDK

use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{ClientError, Result};

/// Stored token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub username: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_expires_at: DateTime<Utc>,
    pub refresh_token_expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Token storage configuration
#[derive(Debug, Clone, Default)]
pub struct TokenStoreConfig {
    pub enabled: bool,
    pub storage_path: Option<PathBuf>,
    pub encryption_key: Option<String>,
}

/// Token storage manager
#[derive(Debug)]
pub struct TokenStore {
    config: TokenStoreConfig,
    token: Option<StoredToken>,
}

impl TokenStore {
    pub fn new(config: TokenStoreConfig) -> Result<Self> {
        let mut store = Self {
            config,
            token: None,
        };

        if store.config.enabled {
            store.load_tokens()?;
        }

        Ok(store)
    }

    pub fn store_tokens(&mut self, tokens: StoredToken) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        self.token = Some(tokens);
        self.save_tokens()?;
        Ok(())
    }

    pub fn get_tokens(&self) -> Option<StoredToken> {
        if !self.config.enabled {
            return None;
        }
        self.token.clone()
    }

    pub fn has_tokens(&self) -> bool {
        self.config.enabled && self.token.is_some()
    }

    pub fn remove_tokens(&mut self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        self.token = None;
        self.save_tokens()?;
        Ok(())
    }

    pub fn get_username(&self) -> Option<String> {
        if !self.config.enabled {
            return None;
        }
        self.token.as_ref().map(|t| t.username.clone())
    }

    pub fn storage_path(&self) -> Option<&Path> {
        self.config.storage_path.as_deref()
    }

    fn get_storage_path(&self) -> Result<PathBuf> {
        self.config
            .storage_path
            .clone()
            .ok_or_else(|| ClientError::invalid_input("Token storage path not configured").into())
    }

    fn load_tokens(&mut self) -> Result<()> {
        let path = self.get_storage_path()?;

        if !path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&path)
            .map_err(|e| ClientError::internal(format!("Failed to read token storage: {}", e)))?;

        if content.trim().is_empty() {
            return Ok(());
        }

        let decrypted_content = if let Some(key) = &self.config.encryption_key {
            self.decrypt_content(&content, key)?
        } else {
            content
        };

        self.token = serde_json::from_str(&decrypted_content)
            .map_err(|e| ClientError::internal(format!("Failed to parse token storage: {}", e)))?;

        Ok(())
    }

    fn save_tokens(&self) -> Result<()> {
        let path = self.get_storage_path()?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                ClientError::internal(format!("Failed to create storage directory: {}", e))
            })?;
        }

        let content = serde_json::to_string_pretty(&self.token)
            .map_err(|e| ClientError::internal(format!("Failed to serialize tokens: {}", e)))?;

        let final_content = if let Some(key) = &self.config.encryption_key {
            self.encrypt_content(&content, key)?
        } else {
            content
        };

        fs::write(&path, final_content)
            .map_err(|e| ClientError::internal(format!("Failed to write token storage: {}", e)))?;

        Ok(())
    }

    fn encrypt_content(&self, content: &str, key: &str) -> Result<String> {
        let key_bytes = key.as_bytes();
        let content_bytes = content.as_bytes();
        let mut encrypted = Vec::new();

        for (i, &byte) in content_bytes.iter().enumerate() {
            let key_byte = key_bytes[i % key_bytes.len()];
            encrypted.push(byte ^ key_byte);
        }

        Ok(base64::engine::general_purpose::STANDARD.encode(encrypted))
    }

    fn decrypt_content(&self, encrypted_content: &str, key: &str) -> Result<String> {
        let encrypted_bytes = base64::engine::general_purpose::STANDARD
            .decode(encrypted_content)
            .map_err(|e| ClientError::crypto(format!("Failed to decode encrypted content: {}", e)))?;

        let key_bytes = key.as_bytes();
        let mut decrypted = Vec::new();

        for (i, &byte) in encrypted_bytes.iter().enumerate() {
            let key_byte = key_bytes[i % key_bytes.len()];
            decrypted.push(byte ^ key_byte);
        }

        String::from_utf8(decrypted)
            .map_err(|e| ClientError::crypto(format!("Failed to decode decrypted content: {}", e)).into())
    }
}

