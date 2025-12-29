//! Model directory management for KoalaVault SDK

use std::path::{Path, PathBuf};
use tokio::fs;
use walkdir::WalkDir;

use cryptotensors::{KeyMaterial, SerializeCryptoConfig};
use cryptotensors::policy::AccessPolicy;
use cryptotensors::tensor::{SafeTensors, serialize_to_file};

use crate::error::{ClientError, Result};
use crate::utils::CryptoUtils;

/// Represents a model directory
#[derive(Debug, Clone)]
pub struct ModelDirectory {
    pub path: PathBuf,
    pub all_files: Vec<ModelFile>,
    pub unencrypted_files: Vec<ModelFile>,
    pub encrypted_files: Vec<ModelFile>,
    pub total_size: u64,
}

/// Information about a model file
#[derive(Debug, Clone)]
pub struct ModelFile {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
    pub is_encrypted: bool,
}

impl ModelDirectory {
    /// Scan a model directory
    pub async fn from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(ClientError::file(format!(
                "Model path does not exist: {}",
                path.display()
            )).into());
        }

        if !path.is_dir() {
            return Err(ClientError::file(format!(
                "Path is not a directory: {}",
                path.display()
            )).into());
        }

        let mut all_files = Vec::new();
        let mut total_size = 0u64;

        let walker = WalkDir::new(path)
            .max_depth(1)
            .into_iter()
            .filter_map(|e| e.ok());

        for entry in walker {
            if entry.file_type().is_file() {
                let file_path = entry.path();

                if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                    let ext_lower = ext.to_lowercase();
                    if ext_lower == "safetensors" || ext_lower == "cryptotensors" {
                        if let Ok(model_file) = ModelFile::from_path(file_path).await {
                            total_size += model_file.size;
                            all_files.push(model_file);
                        }
                    }
                }
            }
        }

        if all_files.is_empty() {
            return Err(ClientError::file(
                "No safetensors or cryptotensors files found",
            ).into());
        }

        let mut unencrypted_files = Vec::new();
        let mut encrypted_files = Vec::new();

        for file in &all_files {
            if file.is_encrypted {
                encrypted_files.push(file.clone());
            } else {
                unencrypted_files.push(file.clone());
            }
        }

        Ok(Self {
            path: path.to_path_buf(),
            all_files,
            unencrypted_files,
            encrypted_files,
            total_size,
        })
    }

    pub fn get_unencrypted_files(&self) -> &[ModelFile] {
        &self.unencrypted_files
    }

    pub fn get_encrypted_files(&self) -> &[ModelFile] {
        &self.encrypted_files
    }

    pub fn get_all_files(&self) -> &[ModelFile] {
        &self.all_files
    }

    pub fn is_fully_encrypted(&self) -> bool {
        self.unencrypted_files.is_empty()
    }

    pub fn formatted_size(&self) -> String {
        format_bytes(self.total_size)
    }
}

impl ModelFile {
    pub async fn from_path(path: &Path) -> Result<Self> {
        if !path.exists() || !path.is_file() {
            return Err(ClientError::file(format!(
                "File not found: {}",
                path.display()
            )).into());
        }

        let metadata = fs::metadata(path).await?;
        let size = metadata.len();

        let is_encrypted = CryptoUtils::detect_safetensors_encryption(path).await?;

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(Self {
            name: filename,
            path: path.to_path_buf(),
            size,
            is_encrypted,
        })
    }

    pub fn formatted_size(&self) -> String {
        format_bytes(self.size)
    }
}

/// Encrypt a safetensors file
pub async fn encrypt_safetensors_file(
    input_path: &Path,
    output_path: &Path,
    enc_key_jwk: &serde_json::Value,
    sign_key_jwk: &serde_json::Value,
    policy: &AccessPolicy,
) -> Result<()> {
    let enc_key = KeyMaterial::from_jwk(enc_key_jwk, false)
        .map_err(|e| ClientError::crypto(format!("Failed to parse encryption key: {}", e)))?;
    let sign_key = KeyMaterial::from_jwk(sign_key_jwk, false)
        .map_err(|e| ClientError::crypto(format!("Failed to parse signing key: {}", e)))?;

    let file_content = fs::read(input_path).await?;

    let safetensors = SafeTensors::deserialize(&file_content)
        .map_err(|e| ClientError::file(format!("Failed to deserialize safetensors: {}", e)))?;

    // Get metadata from SafeTensors::read_metadata
    let (_, metadata) = SafeTensors::read_metadata(&file_content)
        .map_err(|e| ClientError::file(format!("Failed to read metadata: {}", e)))?;
    let original_metadata = metadata.metadata().clone();

    let crypto_config = SerializeCryptoConfig::new("1".to_string(), None, enc_key, sign_key, policy.clone())
        .map_err(|e| ClientError::file(format!("Failed to create encryption config: {}", e)))?;

    // tensors() returns Vec directly, not Result
    let tensor_views = safetensors.tensors();

    serialize_to_file(
        tensor_views.into_iter(),
        original_metadata,
        output_path,
        Some(&crypto_config),
    )
    .map_err(|e| ClientError::file(format!("Failed to encrypt file: {}", e)))?;

    Ok(())
}

/// Format bytes to human readable string
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

