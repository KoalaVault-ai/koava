//! Token storage and persistence for KoalaVault clients

use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{KoavaError, Result};

/// Stored token information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredToken {
    /// Username associated with the tokens
    pub username: String,
    /// Access token for API requests
    pub access_token: String,
    /// Refresh token for getting new access tokens
    pub refresh_token: String,
    /// When the access token expires
    pub expires_at: DateTime<Utc>,
    /// When the refresh token expires
    pub refresh_expires_at: DateTime<Utc>,
    /// Token type (usually "Bearer")
    pub token_type: String,
}

/// Token storage configuration
#[derive(Debug, Clone, Default)]
pub struct TokenStoreConfig {
    /// Path where tokens should be stored
    pub storage_path: Option<PathBuf>,
    /// Encryption key for stored tokens
    pub encryption_key: Option<String>,
}

/// Token storage manager
#[derive(Debug)]
pub struct TokenStore {
    config: TokenStoreConfig,
    token: Option<StoredToken>,
}

impl TokenStore {
    /// Create a new token store
    pub fn new(config: TokenStoreConfig) -> Result<Self> {
        let mut store = Self {
            config,
            token: None,
        };

        // Always load tokens (storage is always enabled)
        store.load_tokens()?;

        Ok(store)
    }

    /// Store tokens
    pub fn store_tokens(&mut self, tokens: StoredToken) -> Result<()> {
        self.token = Some(tokens.clone());
        self.save_tokens()?;
        Ok(())
    }

    /// Retrieve stored tokens
    pub fn get_tokens(&self) -> Option<StoredToken> {
        self.token.clone()
    }

    /// Check if tokens exist
    pub fn has_tokens(&self) -> bool {
        self.token.is_some()
    }

    /// Remove stored tokens (logout)
    pub fn remove_tokens(&mut self) -> Result<()> {
        if self.token.is_some() {
            self.token = None;
            self.save_tokens()?;
        }
        Ok(())
    }

    /// Clear stored tokens
    pub fn clear_tokens(&mut self) -> Result<()> {
        self.token = None;
        self.save_tokens()?;
        Ok(())
    }

    /// Get stored username
    pub fn get_username(&self) -> Option<String> {
        self.token.as_ref().map(|token| token.username.clone())
    }

    /// Check if stored tokens exist and are valid
    pub fn is_token_valid(&self) -> bool {
        if let Some(token) = &self.token {
            let now = Utc::now();
            token.refresh_expires_at > now
        } else {
            false
        }
    }

    /// Get storage path
    pub fn storage_path(&self) -> Option<&Path> {
        self.config.storage_path.as_deref()
    }

    // Private methods

    fn get_storage_path(&self) -> Result<PathBuf> {
        self.config
            .storage_path
            .clone()
            .ok_or_else(|| KoavaError::invalid_input("Token storage path not configured"))
    }

    fn load_tokens(&mut self) -> Result<()> {
        let path = self.get_storage_path()?;

        if !path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&path)
            .map_err(|e| KoavaError::internal(format!("Failed to read token storage: {}", e)))?;

        if content.trim().is_empty() {
            return Ok(());
        }

        // Try to decrypt if encryption is enabled
        let decrypted_content = if let Some(key) = &self.config.encryption_key {
            self.decrypt_content(&content, key)?
        } else {
            content
        };

        self.token = serde_json::from_str(&decrypted_content)
            .map_err(|e| KoavaError::internal(format!("Failed to parse token storage: {}", e)))?;

        Ok(())
    }

    fn save_tokens(&self) -> Result<()> {
        let path = self.get_storage_path()?;

        // Create directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                KoavaError::internal(format!("Failed to create storage directory: {}", e))
            })?;
        }

        let content = serde_json::to_string_pretty(&self.token)
            .map_err(|e| KoavaError::internal(format!("Failed to serialize tokens: {}", e)))?;

        // Encrypt if encryption is enabled
        let final_content = if let Some(key) = &self.config.encryption_key {
            self.encrypt_content(&content, key)?
        } else {
            content
        };

        fs::write(&path, final_content)
            .map_err(|e| KoavaError::internal(format!("Failed to write token storage: {}", e)))?;

        Ok(())
    }

    fn encrypt_content(&self, content: &str, key: &str) -> Result<String> {
        // Simple XOR encryption for demonstration
        // In production, use a proper encryption library
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
        // Simple XOR decryption for demonstration
        let encrypted_bytes = base64::engine::general_purpose::STANDARD
            .decode(encrypted_content)
            .map_err(|e| {
                KoavaError::crypto(format!("Failed to decode encrypted content: {}", e))
            })?;

        let key_bytes = key.as_bytes();
        let mut decrypted = Vec::new();

        for (i, &byte) in encrypted_bytes.iter().enumerate() {
            let key_byte = key_bytes[i % key_bytes.len()];
            decrypted.push(byte ^ key_byte);
        }

        String::from_utf8(decrypted)
            .map_err(|e| KoavaError::crypto(format!("Failed to decode decrypted content: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::utils::test_helpers::*;
    use chrono::Duration;

    mod unit {
        use super::*;

        fn create_test_token() -> StoredToken {
            StoredToken {
                username: "testuser".to_string(),
                access_token: "access123".to_string(),
                refresh_token: "refresh456".to_string(),
                expires_at: Utc::now() + Duration::hours(1),
                refresh_expires_at: Utc::now() + Duration::days(7),
                token_type: "Bearer".to_string(),
            }
        }

        #[test]
        fn test_token_store_new_empty() {
            let temp_dir = create_temp_dir();
            let config = TokenStoreConfig {
                storage_path: Some(temp_dir.path().join("tokens.json")),
                encryption_key: None,
            };

            let store = TokenStore::new(config).unwrap();
            assert!(!store.has_tokens());
            assert_eq!(store.get_tokens(), None);
        }

        #[test]
        fn test_store_and_retrieve_tokens() {
            let temp_dir = create_temp_dir();
            let config = TokenStoreConfig {
                storage_path: Some(temp_dir.path().join("tokens.json")),
                encryption_key: None,
            };

            let mut store = TokenStore::new(config).unwrap();
            let token = create_test_token();

            store.store_tokens(token.clone()).unwrap();

            assert!(store.has_tokens());
            let retrieved = store.get_tokens().unwrap();
            assert_eq!(retrieved.username, token.username);
            assert_eq!(retrieved.access_token, token.access_token);
        }

        #[test]
        fn test_token_persistence() {
            let temp_dir = create_temp_dir();
            let storage_path = temp_dir.path().join("tokens.json");
            let config = TokenStoreConfig {
                storage_path: Some(storage_path.clone()),
                encryption_key: None,
            };

            // Store tokens
            {
                let mut store = TokenStore::new(config.clone()).unwrap();
                let token = create_test_token();
                store.store_tokens(token).unwrap();
            }

            // Load tokens in new instance
            {
                let store = TokenStore::new(config).unwrap();
                assert!(store.has_tokens());
                let retrieved = store.get_tokens().unwrap();
                assert_eq!(retrieved.username, "testuser");
            }
        }

        #[test]
        fn test_token_encryption() {
            let temp_dir = create_temp_dir();
            let config = TokenStoreConfig {
                storage_path: Some(temp_dir.path().join("tokens.json")),
                encryption_key: Some("encryption_key_123".to_string()),
            };

            let mut store = TokenStore::new(config.clone()).unwrap();
            let token = create_test_token();

            store.store_tokens(token.clone()).unwrap();

            // Read raw file content - should be encrypted (base64)
            let raw_content = std::fs::read_to_string(temp_dir.path().join("tokens.json")).unwrap();
            assert!(!raw_content.contains("testuser")); // Should not contain plaintext

            // Load in new instance with same key
            let store2 = TokenStore::new(config).unwrap();
            let retrieved = store2.get_tokens().unwrap();
            assert_eq!(retrieved.username, token.username);
        }

        #[test]
        fn test_remove_tokens() {
            let temp_dir = create_temp_dir();
            let config = TokenStoreConfig {
                storage_path: Some(temp_dir.path().join("tokens.json")),
                encryption_key: None,
            };

            let mut store = TokenStore::new(config).unwrap();
            let token = create_test_token();

            store.store_tokens(token).unwrap();
            assert!(store.has_tokens());

            store.remove_tokens().unwrap();
            assert!(!store.has_tokens());
            assert_eq!(store.get_tokens(), None);
        }

        #[test]
        fn test_clear_tokens() {
            let temp_dir = create_temp_dir();
            let config = TokenStoreConfig {
                storage_path: Some(temp_dir.path().join("tokens.json")),
                encryption_key: None,
            };

            let mut store = TokenStore::new(config).unwrap();
            let token = create_test_token();

            store.store_tokens(token).unwrap();
            store.clear_tokens().unwrap();

            assert!(!store.has_tokens());
        }

        #[test]
        fn test_get_username() {
            let temp_dir = create_temp_dir();
            let config = TokenStoreConfig {
                storage_path: Some(temp_dir.path().join("tokens.json")),
                encryption_key: None,
            };

            let mut store = TokenStore::new(config).unwrap();
            assert_eq!(store.get_username(), None);

            let token = create_test_token();
            store.store_tokens(token).unwrap();

            assert_eq!(store.get_username(), Some("testuser".to_string()));
        }

        #[test]
        fn test_is_token_valid() {
            let temp_dir = create_temp_dir();
            let config = TokenStoreConfig {
                storage_path: Some(temp_dir.path().join("tokens.json")),
                encryption_key: None,
            };

            let mut store = TokenStore::new(config).unwrap();
            assert!(!store.is_token_valid());

            // Valid token
            let token = create_test_token();
            store.store_tokens(token).unwrap();
            assert!(store.is_token_valid());

            // Expired token
            let expired_token = StoredToken {
                username: "testuser".to_string(),
                access_token: "access123".to_string(),
                refresh_token: "refresh456".to_string(),
                expires_at: Utc::now() - Duration::hours(1),
                refresh_expires_at: Utc::now() - Duration::hours(1),
                token_type: "Bearer".to_string(),
            };
            store.store_tokens(expired_token).unwrap();
            assert!(!store.is_token_valid());
        }

        #[test]
        fn test_encrypt_decrypt_roundtrip() {
            let temp_dir = create_temp_dir();
            let config = TokenStoreConfig {
                storage_path: Some(temp_dir.path().join("tokens.json")),
                encryption_key: Some("test_key".to_string()),
            };

            let store = TokenStore::new(config).unwrap();
            let original = "test content";

            let encrypted = store.encrypt_content(original, "test_key").unwrap();
            let decrypted = store.decrypt_content(&encrypted, "test_key").unwrap();

            assert_eq!(original, decrypted);
        }

        #[test]
        fn test_wrong_encryption_key() {
            let temp_dir = create_temp_dir();
            let config1 = TokenStoreConfig {
                storage_path: Some(temp_dir.path().join("tokens.json")),
                encryption_key: Some("key1".to_string()),
            };

            let mut store1 = TokenStore::new(config1).unwrap();
            let token = create_test_token();
            store1.store_tokens(token).unwrap();

            // Try to load with different key
            let config2 = TokenStoreConfig {
                storage_path: Some(temp_dir.path().join("tokens.json")),
                encryption_key: Some("key2".to_string()),
            };

            let result = TokenStore::new(config2);
            // Should fail to parse due to wrong decryption
            assert!(result.is_err());
        }
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn test_encrypt_decrypt_any_content(content in "\\PC*") {
                let temp_dir = create_temp_dir();
                let config = TokenStoreConfig {
                    storage_path: Some(temp_dir.path().join("tokens.json")),
                    encryption_key: Some("test_key".to_string()),
                };

                let store = TokenStore::new(config).unwrap();
                let encrypted = store.encrypt_content(&content, "test_key").unwrap();
                let decrypted = store.decrypt_content(&encrypted, "test_key").unwrap();

                prop_assert_eq!(content, decrypted);
            }

            #[test]
            fn test_different_keys_different_encryption(content in "\\PC+", key1 in "\\PC+", key2 in "\\PC+") {
                if key1 != key2 && !content.is_empty() {
                    let temp_dir = create_temp_dir();
                    let config = TokenStoreConfig {
                        storage_path: Some(temp_dir.path().join("tokens.json")),
                        encryption_key: Some(key1.clone()),
                    };

                    let store = TokenStore::new(config).unwrap();
                    let encrypted1 = store.encrypt_content(&content, &key1).unwrap();
                    let encrypted2 = store.encrypt_content(&content, &key2).unwrap();

                    // Different keys should produce different encrypted content
                    prop_assert_ne!(encrypted1, encrypted2);
                }
            }
        }
    }
}
