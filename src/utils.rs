//! Utility functions for KoalaVault SDK

use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::error::{ClientError, Result};

/// File header information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHeader {
    pub filename: String,
    pub file_header: String,
}

/// File hash information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHash {
    pub filename: String,
    pub header_hash: String,
}

/// File information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub id: Option<String>,
    pub filename: String,
    pub file_header: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Crypto utilities
pub struct CryptoUtils;

impl CryptoUtils {
    pub fn calculate_sha256_hash(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn calculate_sha256_hash_bytes(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Extract header from a safetensors file
    pub fn extract_safetensors_header<P: AsRef<Path>>(file_path: P) -> Result<String> {
        let file_path = file_path.as_ref();
        let mut file = BufReader::new(File::open(file_path)?);

        let mut header_len_bytes = [0u8; 8];
        file.read_exact(&mut header_len_bytes)
            .map_err(|e| ClientError::crypto(format!("Failed to read header length: {}", e)))?;

        let header_len = u64::from_le_bytes(header_len_bytes) as usize;

        if header_len > 1024 * 1024 {
            return Err(ClientError::crypto("Header too large").into());
        }

        let mut header_json_bytes = vec![0u8; header_len];
        file.read_exact(&mut header_json_bytes)
            .map_err(|e| ClientError::crypto(format!("Failed to read header JSON: {}", e)))?;

        let mut header_data = Vec::with_capacity(8 + header_len);
        header_data.extend_from_slice(&header_len_bytes);
        header_data.extend_from_slice(&header_json_bytes);

        let header_b64 = general_purpose::STANDARD.encode(&header_data);
        Ok(header_b64)
    }

    pub fn create_file_hash(header: &FileHeader) -> FileHash {
        let header_hash = Self::calculate_sha256_hash(&header.file_header);
        FileHash {
            filename: header.filename.clone(),
            header_hash,
        }
    }

    pub fn create_file_hashes(headers: &[FileHeader]) -> Vec<FileHash> {
        headers.iter().map(|h| Self::create_file_hash(h)).collect()
    }

    pub fn decode_base64(data: &str) -> Result<Vec<u8>> {
        general_purpose::STANDARD
            .decode(data)
            .map_err(|e| ClientError::crypto(format!("Failed to decode base64: {}", e)).into())
    }

    pub fn encode_base64(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }

    /// Detect if a safetensors file is encrypted
    pub async fn detect_safetensors_encryption<P: AsRef<Path>>(file_path: P) -> Result<bool> {
        let file_path = file_path.as_ref();

        let mut file = tokio::fs::File::open(file_path)
            .await
            .map_err(|e| ClientError::file(format!("Failed to open file: {}", e)))?;

        let mut header_len_bytes = [0u8; 8];
        use tokio::io::AsyncReadExt;
        file.read_exact(&mut header_len_bytes)
            .await
            .map_err(|e| ClientError::file(format!("Failed to read header length: {}", e)))?;

        let header_len = u64::from_le_bytes(header_len_bytes) as usize;

        if header_len > 1024 * 1024 {
            return Err(ClientError::file("Header too large").into());
        }

        let mut header_json_bytes = vec![0u8; header_len];
        file.read_exact(&mut header_json_bytes)
            .await
            .map_err(|e| ClientError::file(format!("Failed to read header JSON: {}", e)))?;

        let header_json: serde_json::Value = serde_json::from_slice(&header_json_bytes)
            .map_err(|e| ClientError::file(format!("Failed to parse header JSON: {}", e)))?;

        if let Some(metadata) = header_json.get("__metadata__") {
            if let Some(metadata_obj) = metadata.as_object() {
                if metadata_obj.contains_key("__encryption__") {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

