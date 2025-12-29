//! File management for KoalaVault SDK

use serde::{Deserialize, Serialize};

use crate::client::{ApiResponse, HttpClient};
use crate::error::{ClientError, Result};
use crate::utils::{FileHeader, FileInfo};

#[derive(Debug, Serialize)]
pub struct UploadFileHeadersRequest {
    pub files: Vec<FileHeader>,
}

#[derive(Debug, Deserialize)]
pub struct FileUploadResponse {
    pub total_uploaded: usize,
    #[serde(default)]
    pub files: Vec<FileInfo>,
}

#[derive(Debug, Deserialize)]
pub struct FileListResponse {
    pub files: Vec<FileInfo>,
}

#[derive(Debug, Deserialize)]
pub struct ModelFileResponse {
    pub id: String,
    pub model_id: String,
    pub filename: String,
    pub file_header: String,
    pub created_at: String,
    pub updated_at: String,
}

/// File service for model file operations
pub struct ModelFileService<'a> {
    client: &'a HttpClient,
}

impl<'a> ModelFileService<'a> {
    pub fn new(client: &'a HttpClient) -> Self {
        Self { client }
    }

    /// Upload model files
    pub async fn upload_model_files(
        &self,
        username: &str,
        model_name: &str,
        file_infos: Vec<FileInfo>,
    ) -> Result<FileUploadResponse> {
        if file_infos.is_empty() {
            return Err(ClientError::file("No file headers provided").into());
        }

        let mut file_headers = Vec::new();
        for file_info in &file_infos {
            if file_info.filename.is_empty() {
                return Err(ClientError::file("Empty filename in file info").into());
            }
            match &file_info.file_header {
                Some(header_data) if !header_data.is_empty() => {
                    file_headers.push(FileHeader {
                        filename: file_info.filename.clone(),
                        file_header: header_data.clone(),
                    });
                }
                _ => return Err(ClientError::file("Empty or missing file header data").into()),
            }
        }

        let endpoint = format!("/resources/{}/models/{}/files", username, model_name);
        let request = UploadFileHeadersRequest {
            files: file_headers,
        };

        let response: ApiResponse<FileUploadResponse> = self
            .client
            .authenticated_request(reqwest::Method::POST, &endpoint, Some(&request))
            .await?;

        match response.data {
            Some(upload_data) => Ok(upload_data),
            None => Err(ClientError::api(
                200,
                "No upload data in response".to_string(),
            ).into()),
        }
    }

    /// List files for a model
    pub async fn list_model_files(
        &self,
        username: &str,
        model_name: &str,
    ) -> Result<Vec<FileInfo>> {
        let endpoint = format!("/resources/{}/models/{}/files", username, model_name);

        let response: ApiResponse<FileListResponse> = self
            .client
            .authenticated_request(reqwest::Method::GET, &endpoint, None::<&()>)
            .await?;

        match response.data {
            Some(list_data) => Ok(list_data.files),
            None => Ok(Vec::new()),
        }
    }

    /// Get a specific model file
    pub async fn get_model_file(
        &self,
        username: &str,
        model_name: &str,
        filename: &str,
    ) -> Result<ModelFileResponse> {
        let endpoint = format!(
            "/resources/{}/models/{}/files/{}",
            username, model_name, filename
        );

        let response: ApiResponse<ModelFileResponse> = self
            .client
            .authenticated_request(reqwest::Method::GET, &endpoint, None::<&()>)
            .await?;

        match response.data {
            Some(file_data) => Ok(file_data),
            None => Err(ClientError::api(
                200,
                "No file data in response".to_string(),
            ).into()),
        }
    }

    /// Delete all files for a model
    pub async fn delete_all_model_files(&self, username: &str, model_name: &str) -> Result<()> {
        let endpoint = format!("/resources/{}/models/{}/files", username, model_name);

        let _: ApiResponse<serde_json::Value> = self
            .client
            .authenticated_request(reqwest::Method::DELETE, &endpoint, None::<&()>)
            .await?;

        Ok(())
    }
}

