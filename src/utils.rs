//! Utility functions for KoalaVault clients

use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::error::{KoavaError, Result};

/// File header information for encrypted models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHeader {
    /// Name of the file
    pub filename: String,
    /// Base64 encoded header data
    pub file_header: String,
}

/// File hash information for deployment verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHash {
    /// Name of the file
    pub filename: String,
    /// SHA256 hash of the header
    pub header_hash: String,
}

/// File information from deployment response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// Optional file ID
    pub id: Option<String>,
    /// Name of the file
    pub filename: String,
    /// Optional file header data
    pub file_header: Option<String>,
    /// When the file was created
    pub created_at: Option<String>,
    /// When the file was last updated
    pub updated_at: Option<String>,
}

/// Crypto utilities for file operations
pub struct CryptoUtils;

impl CryptoUtils {
    pub const HEADER_LENGTH_SIZE: usize = 8;
    pub const MAX_HEADER_SIZE: usize = 1024 * 1024;
    pub const METADATA_KEY: &str = "__metadata__";
    pub const ENCRYPTION_KEY: &str = "__encryption__";

    /// Calculate SHA256 hash of a string (used for header hashing)
    pub fn calculate_sha256_hash(data: &str) -> String {
        Self::calculate_sha256_hash_bytes(data.as_bytes())
    }

    /// Calculate SHA256 hash of bytes
    pub fn calculate_sha256_hash_bytes(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Read the safetensors header raw bytes (excluding length prefix).
    /// This function handles the 8-byte length reading and size validation.
    pub async fn read_safetensors_header_raw<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
        let file_path = file_path.as_ref();
        let mut file = tokio::fs::File::open(file_path)
            .await
            .map_err(|e| KoavaError::io("File open", format!("Failed to open file: {}", e)))?;

        let mut header_len_bytes = [0u8; Self::HEADER_LENGTH_SIZE];
        use tokio::io::AsyncReadExt;
        file.read_exact(&mut header_len_bytes).await.map_err(|e| {
            KoavaError::io(
                "Header read",
                format!("Failed to read header length: {}", e),
            )
        })?;

        let header_len = u64::from_le_bytes(header_len_bytes) as usize;

        if header_len > Self::MAX_HEADER_SIZE {
            return Err(KoavaError::validation(
                "Header too large (exceeds 1MB limit)",
            ));
        }

        let mut header_json_bytes = vec![0u8; header_len];
        file.read_exact(&mut header_json_bytes).await.map_err(|e| {
            KoavaError::io("Header read", format!("Failed to read header JSON: {}", e))
        })?;

        Ok(header_json_bytes)
    }

    /// Extract header data from a Safetensors file
    /// This reads the first 8 bytes (header length) + header JSON and encodes as base64
    pub async fn extract_safetensors_header<P: AsRef<Path>>(file_path: P) -> Result<String> {
        let header_json_bytes = Self::read_safetensors_header_raw(file_path).await?;
        let header_len = header_json_bytes.len();
        let header_len_bytes = (header_len as u64).to_le_bytes();

        // Combine header length + header JSON
        let mut header_data = Vec::with_capacity(Self::HEADER_LENGTH_SIZE + header_len);
        header_data.extend_from_slice(&header_len_bytes);
        header_data.extend_from_slice(&header_json_bytes);

        // Encode as base64
        let header_b64 = general_purpose::STANDARD.encode(&header_data);
        Ok(header_b64)
    }

    /// Create file hash from file header
    pub fn create_file_hash(header: &FileHeader) -> FileHash {
        let header_hash = Self::calculate_sha256_hash(&header.file_header);

        FileHash {
            filename: header.filename.clone(),
            header_hash,
        }
    }

    /// Create multiple file hashes from headers
    pub fn create_file_hashes(headers: &[FileHeader]) -> Vec<FileHash> {
        headers.iter().map(Self::create_file_hash).collect()
    }

    /// Decode base64 string
    pub fn decode_base64(data: &str) -> Result<Vec<u8>> {
        general_purpose::STANDARD
            .decode(data)
            .map_err(|e| KoavaError::crypto(format!("Failed to decode base64: {}", e)))
    }

    /// Encode bytes as base64
    pub fn encode_base64(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }

    /// Detect if a safetensors file is encrypted by checking its header metadata
    /// This function only reads the file header portion, not the entire file
    pub async fn detect_safetensors_encryption<P: AsRef<Path>>(file_path: P) -> Result<bool> {
        let header_json_bytes = Self::read_safetensors_header_raw(file_path).await?;

        // Parse the header JSON to check for encryption metadata
        let header_json: serde_json::Value =
            serde_json::from_slice(&header_json_bytes).map_err(|e| {
                KoavaError::serialization(format!("Failed to parse header JSON: {}", e))
            })?;

        // Check if the file contains encryption metadata
        if let Some(metadata) = header_json.get(Self::METADATA_KEY) {
            if let Some(metadata_obj) = metadata.as_object() {
                if metadata_obj.contains_key(Self::ENCRYPTION_KEY) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

/// Format bytes into human readable string
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::utils::test_helpers::*;

    mod unit {
        use super::*;

        #[test]
        fn test_calculate_sha256_hash() {
            // Test with known input
            let input = "hello world";
            let hash = CryptoUtils::calculate_sha256_hash(input);

            // SHA256 of "hello world" is known
            assert_eq!(
                hash,
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            );
        }

        #[test]
        fn test_calculate_sha256_hash_empty() {
            let hash = CryptoUtils::calculate_sha256_hash("");
            // SHA256 of empty string
            assert_eq!(
                hash,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
        }

        #[test]
        fn test_calculate_sha256_hash_bytes() {
            let input = b"hello world";
            let hash = CryptoUtils::calculate_sha256_hash_bytes(input);

            assert_eq!(
                hash,
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            );
        }

        #[test]
        fn test_base64_encode_decode() {
            let original = b"test data";
            let encoded = CryptoUtils::encode_base64(original);
            let decoded = CryptoUtils::decode_base64(&encoded).unwrap();

            assert_eq!(original.to_vec(), decoded);
        }

        #[test]
        fn test_base64_decode_invalid() {
            let result = CryptoUtils::decode_base64("invalid!@#$%");
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn test_extract_safetensors_header() {
            let temp_dir = create_temp_dir();
            let file_path = create_mock_safetensors_file(&temp_dir, "model.safetensors", false);

            let header_b64 = CryptoUtils::extract_safetensors_header(&file_path)
                .await
                .unwrap();

            // Verify it's valid base64
            let decoded = CryptoUtils::decode_base64(&header_b64).unwrap();

            // First 8 bytes should be the header length
            assert!(decoded.len() >= 8);
        }

        #[tokio::test]
        async fn test_extract_safetensors_header_nonexistent_file() {
            let result =
                CryptoUtils::extract_safetensors_header("/nonexistent/file.safetensors").await;
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn test_detect_safetensors_encryption_unencrypted() {
            let temp_dir = create_temp_dir();
            let file_path = create_mock_safetensors_file(&temp_dir, "model.safetensors", false);

            let is_encrypted = CryptoUtils::detect_safetensors_encryption(&file_path)
                .await
                .unwrap();

            assert!(!is_encrypted);
        }

        #[tokio::test]
        async fn test_detect_safetensors_encryption_encrypted() {
            let temp_dir = create_temp_dir();
            let file_path = create_mock_safetensors_file(&temp_dir, "model.safetensors", true);

            let is_encrypted = CryptoUtils::detect_safetensors_encryption(&file_path)
                .await
                .unwrap();

            assert!(is_encrypted);
        }

        #[test]
        fn test_create_file_hash() {
            let header = FileHeader {
                filename: "test.safetensors".to_string(),
                file_header: "base64encodeddata".to_string(),
            };

            let file_hash = CryptoUtils::create_file_hash(&header);

            assert_eq!(file_hash.filename, "test.safetensors");
            assert!(!file_hash.header_hash.is_empty());
            assert_eq!(file_hash.header_hash.len(), 64); // SHA256 hex is 64 chars
        }

        #[test]
        fn test_create_file_hashes() {
            let headers = vec![
                FileHeader {
                    filename: "file1.safetensors".to_string(),
                    file_header: "data1".to_string(),
                },
                FileHeader {
                    filename: "file2.safetensors".to_string(),
                    file_header: "data2".to_string(),
                },
            ];

            let hashes = CryptoUtils::create_file_hashes(&headers);

            assert_eq!(hashes.len(), 2);
            assert_eq!(hashes[0].filename, "file1.safetensors");
            assert_eq!(hashes[1].filename, "file2.safetensors");
            // Different data should produce different hashes
            assert_ne!(hashes[0].header_hash, hashes[1].header_hash);
        }

        #[test]
        fn test_format_bytes() {
            assert_eq!(format_bytes(100), "100 B");
            assert_eq!(format_bytes(1024), "1.0 KB");
            assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
            assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
            assert_eq!(format_bytes(1536), "1.5 KB");
        }
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn test_hash_deterministic(s in "\\PC*") {
                // Same input should always produce same hash
                let hash1 = CryptoUtils::calculate_sha256_hash(&s);
                let hash2 = CryptoUtils::calculate_sha256_hash(&s);
                prop_assert_eq!(hash1, hash2);
            }

            #[test]
            fn test_hash_length(s in "\\PC*") {
                // SHA256 hash should always be 64 hex characters
                let hash = CryptoUtils::calculate_sha256_hash(&s);
                prop_assert_eq!(hash.len(), 64);
            }

            #[test]
            fn test_base64_roundtrip(data in prop::collection::vec(any::<u8>(), 0..1000)) {
                // Encode then decode should return original data
                let encoded = CryptoUtils::encode_base64(&data);
                let decoded = CryptoUtils::decode_base64(&encoded).unwrap();
                prop_assert_eq!(data, decoded);
            }

            #[test]
            fn test_different_inputs_different_hashes(s1 in "\\PC+", s2 in "\\PC+") {
                // Different inputs should (almost always) produce different hashes
                if s1 != s2 {
                    let hash1 = CryptoUtils::calculate_sha256_hash(&s1);
                    let hash2 = CryptoUtils::calculate_sha256_hash(&s2);
                    prop_assert_ne!(hash1, hash2);
                }
            }

            #[test]
            fn test_format_bytes_no_panic(bytes in any::<u64>()) {
                // Should not panic for any input
                let formatted = format_bytes(bytes);
                prop_assert!(!formatted.is_empty());
            }

            #[test]
            fn test_format_bytes_scaling(bytes in 0u64..u64::MAX) {
                // Larger bytes should produce result containing appropriate unit
                // (This is a bit loose, but checks basic logic)
                let formatted = format_bytes(bytes);
                if bytes < 1024 {
                    prop_assert!(formatted.contains("B"));
                } else if bytes < 1024 * 1024 {
                    prop_assert!(formatted.contains("KB"));
                }
            }
        }
    }
}
