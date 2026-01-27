//! File management operations for KoalaVault clients

use serde::Serialize;

use crate::client::ApiClient;
use crate::error::{KoavaError, Result};
use crate::utils::FileInfo;
use crate::ApiResponse;
use koalavault_protocol::api::{
    GetModelFileResponse, ModelFilesListResponse, UploadModelFilesRequest, UploadModelFilesResponse,
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
        let request = UploadModelFilesRequest {
            files: file_headers,
        };

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::tests::mocks::MockApiClient;
    use serde_json::json;

    fn create_client() -> MockApiClient {
        MockApiClient::new(Config::default())
    }

    #[tokio::test]
    async fn test_upload_model_files_success() {
        let client = create_client().with_auth("testuser".to_string());
        let service = ModelFileService::new(&client);

        let file_infos = vec![FileInfo {
            id: None,
            filename: "model.safetensors".to_string(),
            file_header: Some("base64header".to_string()),
            created_at: None,
            updated_at: None,
        }];

        // Mock response
        let response_data = json!({
            "total_uploaded": 1,
            "files": [{
                "filename": "model.safetensors",
                "status": "uploaded"
            }]
        });
        client.add_response(
            "/resources/testuser/models/test-model/files".to_string(),
            response_data,
        );

        let result = service
            .upload_model_files("testuser", "test-model", file_infos)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().total_uploaded, 1);
    }

    #[tokio::test]
    async fn test_upload_model_files_empty() {
        let client = create_client().with_auth("testuser".to_string());
        let service = ModelFileService::new(&client);

        let result = service
            .upload_model_files("testuser", "test-model", vec![])
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No file headers provided"));
    }

    #[tokio::test]
    async fn test_upload_model_files_api_error() {
        let client = create_client().with_auth("testuser".to_string());
        let service = ModelFileService::new(&client);

        let file_infos = vec![FileInfo {
            id: None,
            filename: "error.safetensors".to_string(),
            file_header: Some("header".to_string()),
            created_at: None,
            updated_at: None,
        }];

        // By default, if the mock client doesn't find a matching response, it returns "empty" success.
        // But for upload expecting UploadModelFilesResponse, empty data might fail parsing or custom logic.
        // However, let's explicitly add an error response using `KoavaError::api` is not easily mockable via MockApiClient
        // because MockApiClient returns Ok(ApiResponse). We need to verify how MockApiClient handles errors?
        // MockApiClient `authenticated_request` always returns `Ok(ApiResponse)`.
        // To simulate API error, we should return `ApiResponse { success: false, error: Some(...) }`
        // But MockApiClient implementation in `src/tests/mocks.rs` seems to always set `success: true`.
        // Let's verify `src/tests/mocks.rs` content again.
        // Line 80: returns success: true.
        // Line 92: returns success: true.
        // So we can only test success paths or parse errors with current MockApiClient unless we modify it.
        // However, we can test "unexpected response structure" which causes serialization error or "None" data handling.

        // Let's skip explicit API error simulation if MockApiClient doesn't support it,
        // or we can mock a response with `data: None` (which is default) to trigger "No upload data in response".

        let result = service
            .upload_model_files("testuser", "test-model", file_infos)
            .await;
        // Default mock returns None data
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No upload data in response"));
    }

    #[tokio::test]
    async fn test_list_model_files_success() {
        let client = create_client().with_auth("testuser".to_string());
        let service = ModelFileService::new(&client);

        let files = vec![json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "model_id": "888e8400-e29b-41d4-a716-446655440888",
            "header_size": 1024,
            "size": 2048,
            "filename": "model-001.safetensors",
            "created_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-01T00:00:00Z"
        })];

        client.add_response(
            "/resources/testuser/models/test-model/files".to_string(),
            json!({
                "model_id": "888e8400-e29b-41d4-a716-446655440888",
                "total_count": 1,
                "files": files
            }),
        );

        let result = service.list_model_files("testuser", "test-model").await;
        let file_list = result.expect("Failed to list files");
        assert_eq!(file_list.len(), 1);
        assert_eq!(file_list[0].filename, "model-001.safetensors");
    }

    #[tokio::test]
    async fn test_get_model_file_success() {
        let client = create_client().with_auth("testuser".to_string());
        let service = ModelFileService::new(&client);

        let file_data = json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "model_id": "888e8400-e29b-41d4-a716-446655440888",
            "filename": "model.safetensors",
            "file_header": "header-content",
            "created_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-01T00:00:00Z"
        });

        client.add_response(
            "/resources/testuser/models/test-model/files/model.safetensors".to_string(),
            file_data,
        );

        let result = service
            .get_model_file("testuser", "test-model", "model.safetensors")
            .await;
        let file_resp = result.expect("Failed to get file");
        assert_eq!(file_resp.file_header, "header-content");
    }

    #[tokio::test]
    async fn test_delete_all_model_files() {
        let client = create_client().with_auth("testuser".to_string());
        let service = ModelFileService::new(&client);

        // Delete returns arbitrary JSON value, usually just success
        client.add_response(
            "/resources/testuser/models/test-model/files".to_string(),
            json!({}),
        );

        let result = service
            .delete_all_model_files("testuser", "test-model")
            .await;
        assert!(result.is_ok());
    }
}
