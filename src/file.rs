//! File management operations for KoalaVault clients

use serde::Serialize;

use crate::client::ApiClient;
use crate::error::{KoavaError, Result};
use crate::utils::FileInfo;
use crate::ApiResponse;
use koalavault_protocol::api::{
    GetModelFileResponse, ModelFilesListResponse, UploadModelFilesRequest,
    UploadModelFilesResponse,
};

/// Configuration for model encryption
#[derive(Debug, Serialize)]
pub struct EncryptionConfig {
    /// Encryption key for the model (raw JSON)
    pub enc_key: serde_json::Value,
    /// Signing key for the model (raw JSON)
    pub sign_key: serde_json::Value,
}

/// Metadata for encrypted models
#[derive(Debug, Serialize)]
pub struct ModelMetadata {
    /// Model format (e.g., "safetensors", "cryptotensor")
    pub format: String,
}

/// File manager for handling model file operations
pub struct ModelFileService<'a, C: ApiClient + ?Sized> {
    client: &'a C,
}

impl<'a, C: ApiClient + ?Sized> ModelFileService<'a, C> {
    /// Create a new file manager
    pub fn new(client: &'a C) -> Self {
        Self { client }
    }

    /// Upload model files by uploading their headers to the server
    ///
    /// This method extracts headers from encrypted model files and uploads them to the server.
    /// The actual file data remains local, only headers are transmitted.
    ///
    /// # Arguments
    ///
    /// * `username` - Username of the model owner
    /// * `model_name` - Name/slug of the model
    /// * `file_headers` - List of file headers to upload
    ///
    /// # Returns
    ///
    /// Returns upload statistics and file information on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Authentication fails
    /// - Access is denied (not the model owner)
    /// - Invalid file headers provided
    /// - Network or API errors occur
    pub async fn upload_model_files(
        &self,
        username: &str,
        model_name: &str,
        file_infos: Vec<FileInfo>,
    ) -> Result<UploadModelFilesResponse> {
        if file_infos.is_empty() {
            return Err(KoavaError::invalid_input("No file headers provided"));
        }

        // Validate file infos and convert to UploadSingleFileHeaderRequest
        let mut file_headers = Vec::new();
        for file_info in &file_infos {
            if file_info.filename.is_empty() {
                return Err(KoavaError::invalid_input("Empty filename in file info"));
            }
            match &file_info.file_header {
                Some(header_data) if !header_data.is_empty() => {
                    file_headers.push(koalavault_protocol::api::UploadSingleFileHeaderRequest {
                        filename: file_info.filename.clone(),
                        file_header: header_data.clone(),
                    });
                }
                _ => {
                    return Err(KoavaError::invalid_input(
                        "Empty or missing file header data",
                    ))
                }
            }
        }

        let endpoint = format!("/resources/{}/models/{}/files", username, model_name);
        let request = UploadModelFilesRequest { files: file_headers };

        let response: ApiResponse<UploadModelFilesResponse> = self
            .client
            .authenticated_request(reqwest::Method::POST, &endpoint, Some(&request))
            .await?;

        match response.data {
            Some(upload_data) => Ok(upload_data),
            None => Err(KoavaError::api(
                200,
                "No upload data in response".to_string(),
            )),
        }
    }

    /// List files for a model
    ///
    /// # Arguments
    ///
    /// * `username` - Username of the model owner
    /// * `model_name` - Name/slug of the model
    ///
    /// # Returns
    ///
    /// Returns a list of files associated with the model.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Authentication fails (for private models)
    /// - Model not found
    /// - Access denied (insufficient permissions)
    /// - Network or API errors occur
    pub async fn list_model_files(
        &self,
        username: &str,
        model_name: &str,
    ) -> Result<Vec<FileInfo>> {
        let endpoint = format!("/resources/{}/models/{}/files", username, model_name);

        let response: ApiResponse<ModelFilesListResponse> = self
            .client
            .authenticated_request(reqwest::Method::GET, &endpoint, None::<&()>)
            .await?;

        match response.data {
            Some(list_data) => {
                // Convert protocol ModelFile to FileInfo
                let file_infos: Vec<FileInfo> = list_data
                    .files
                    .into_iter()
                    .map(|mf| FileInfo {
                        id: Some(mf.id.to_string()),
                        filename: mf.filename,
                        file_header: None,
                        created_at: Some(mf.created_at.to_rfc3339()),
                        updated_at: Some(mf.updated_at.to_rfc3339()),
                    })
                    .collect();
                Ok(file_infos)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Get a specific model file by filename
    ///
    /// This method retrieves a specific file from a model by its filename.
    /// The file header data is returned as base64 encoded content.
    ///
    /// # Arguments
    ///
    /// * `username` - Username of the model owner
    /// * `model_name` - Name/slug of the model
    /// * `filename` - Name of the specific file to retrieve
    ///
    /// # Returns
    ///
    /// Returns the model file information including the file header on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Authentication fails
    /// - Model not found
    /// - File not found
    /// - Access denied (insufficient permissions)
    /// - Network or API errors occur
    pub async fn get_model_file(
        &self,
        username: &str,
        model_name: &str,
        filename: &str,
    ) -> Result<GetModelFileResponse> {
        let endpoint = format!(
            "/resources/{}/models/{}/files/{}",
            username, model_name, filename
        );

        let response: ApiResponse<GetModelFileResponse> = self
            .client
            .authenticated_request(reqwest::Method::GET, &endpoint, None::<&()>)
            .await?;

        match response.data {
            Some(file_data) => Ok(file_data),
            None => Err(KoavaError::api(200, "No file data in response".to_string())),
        }
    }

    /// Delete all files for a model
    ///
    /// This operation removes all file headers from the server for the specified model.
    /// Only the model owner can delete files.
    ///
    /// # Arguments
    ///
    /// * `username` - Username of the model owner
    /// * `model_name` - Name/slug of the model
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Authentication fails
    /// - Access is denied (not the model owner)
    /// - Model not found
    /// - Network or API errors occur
    pub async fn delete_all_model_files(&self, username: &str, model_name: &str) -> Result<()> {
        let endpoint = format!("/resources/{}/models/{}/files", username, model_name);

        let _response: ApiResponse<serde_json::Value> = self
            .client
            .authenticated_request(reqwest::Method::DELETE, &endpoint, None::<&()>)
            .await?;

        Ok(())
    }
}
