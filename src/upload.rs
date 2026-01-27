use std::sync::Arc;

use crate::client::ApiClient;
use crate::error::{KoavaError, Result};
use crate::ui::UI;
use crate::utils::{CryptoUtils, FileInfo};
use crate::{ModelDirectory, ModelFileService};

/// Upload service for encrypting and uploading model headers
pub struct UploadService<C: ApiClient + ?Sized> {
    client: Arc<C>,
    progress_enabled: bool,
    ui: UI,
}

impl<C: ApiClient + ?Sized> UploadService<C> {
    /// Create a new upload service
    pub fn new(client: Arc<C>, progress_enabled: bool) -> Self {
        Self {
            client,
            progress_enabled,
            ui: UI::new(),
        }
    }

    /// Upload a model by extracting and uploading file headers
    pub async fn upload_model(
        &self,
        model: &ModelDirectory,
        model_name: &str,
        force: bool,
    ) -> Result<()> {
        self.ui
            .info(&format!("Starting upload for model: {}", model_name));
        self.ui.info(&format!(
            "Model has {} files, total size: {}",
            model.all_files.len(),
            crate::ui::format_size_colored(model.total_size)
        ));
        self.ui.info(&format!("Force mode: {}", force));

        // Get current username from authenticated client
        let username = self.client.get_current_username().ok_or_else(|| {
            KoavaError::authentication("Failed to get current username".to_string())
        })?;

        // If force mode, delete existing files first
        if force {
            self.delete_existing_files(&username, model_name).await?;
        }

        // Extract file headers from encrypted files
        let file_infos = self.extract_file_headers(model).await?;

        if file_infos.is_empty() {
            return Err(KoavaError::validation(
                "No valid file headers could be extracted".to_string(),
            ));
        }

        // Upload file headers using SDK
        let file_service = ModelFileService::new(&*self.client);

        self.ui.info(&format!(
            "Uploading {} file headers to server...",
            file_infos.len()
        ));

        let progress_bar = if self.progress_enabled {
            Some(crate::ui::create_progress_bar(
                file_infos.len() as u64,
                "Uploading files...",
            ))
        } else {
            None
        };

        // Upload files in batches to avoid overwhelming the server
        let batch_size = 5;
        let mut uploaded_count = 0;

        for (i, chunk) in file_infos.chunks(batch_size).enumerate() {
            let batch_num = i + 1;
            let total_batches = file_infos.len().div_ceil(batch_size);

            if let Some(ref pb) = progress_bar {
                pb.set_message(format!("Uploading batch {}/{}", batch_num, total_batches));
            }

            match file_service
                .upload_model_files(&username, model_name, chunk.to_vec())
                .await
            {
                Ok(upload_response) => {
                    uploaded_count += upload_response.total_uploaded;
                    // Batch upload successful - no debug output needed

                    if let Some(ref pb) = progress_bar {
                        pb.inc(chunk.len() as u64);
                    }
                }
                Err(e) => {
                    // Check if this is a 409 conflict error (file already exists)
                    let is_conflict_error =
                        e.to_string().contains("409") || e.to_string().contains("already exists");

                    if is_conflict_error && force {
                        // In force mode, treat 409 conflicts as warnings, not errors
                        self.ui.warning(&format!(
                            "Batch {}/{} skipped (files already exist): {}",
                            batch_num, total_batches, e
                        ));
                        self.ui
                            .info("Continuing with remaining batches due to force mode");

                        if let Some(ref pb) = progress_bar {
                            pb.inc(chunk.len() as u64);
                        }
                    } else if is_conflict_error && !force {
                        // 409 conflict in non-force mode - provide helpful guidance
                        self.ui.error(&format!("Upload failed: {}", e));
                        self.ui
                            .info("💡 The model files already exist on the server.");
                        self.ui
                            .info("   To overwrite existing files, use the --force flag:");
                        self.ui
                            .info(&format!("   koava push {} --force", model_name));
                        return Err(KoavaError::upload(
                            "Files already exist on server. Use --force to overwrite.".to_string(),
                        ));
                    } else {
                        // For other errors, treat as error
                        self.ui.error(&format!(
                            "Failed to upload batch {}/{}: {}",
                            batch_num, total_batches, e
                        ));

                        if !force {
                            return Err(KoavaError::upload(e.to_string()));
                        }

                        self.ui
                            .warning("Continuing with remaining batches due to force mode");
                    }
                }
            }

            // Small delay between batches to be respectful to the server
            if batch_num < total_batches {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }

        if let Some(pb) = progress_bar {
            pb.finish_with_message("Upload completed");
        }

        self.ui.info(&format!(
            "Successfully uploaded {} out of {} files for model: {}",
            uploaded_count,
            file_infos.len(),
            model_name
        ));

        if uploaded_count < file_infos.len() {
            self.ui.warning(
                "Some files failed to upload. Use --force to continue with partial uploads.",
            );
        }

        Ok(())
    }

    /// Delete existing files for a model (used in force mode)
    async fn delete_existing_files(&self, username: &str, model_name: &str) -> Result<()> {
        self.ui.info(&format!(
            "Force mode: deleting existing files for model {}/{}",
            username, model_name
        ));

        // Use SDK to delete all existing files
        let file_service = ModelFileService::new(&*self.client);

        match file_service
            .delete_all_model_files(username, model_name)
            .await
        {
            Ok(()) => {
                self.ui.info(&format!(
                    "Successfully deleted all existing files for model {}/{}",
                    username, model_name
                ));
                Ok(())
            }
            Err(e) => {
                // If deletion fails, log warning but continue
                // This could happen if no files exist yet, which is fine
                self.ui.warning(&format!(
                    "Failed to delete existing files (this may be normal if no files exist): {}",
                    e
                ));
                Ok(())
            }
        }
    }

    /// Extract file headers from encrypted model files
    async fn extract_file_headers(&self, model: &ModelDirectory) -> Result<Vec<FileInfo>> {
        let mut file_infos = Vec::new();

        for file in &model.all_files {
            if !file.is_encrypted {
                self.ui
                    .warning(&format!("Skipping unencrypted file: {}", file.name));
                continue;
            }

            match CryptoUtils::extract_safetensors_header(&file.path) {
                Ok(header_data) => {
                    let file_info = FileInfo {
                        id: None,
                        filename: file.name.clone(),
                        file_header: Some(header_data),
                        created_at: None,
                        updated_at: None,
                    };

                    file_infos.push(file_info);
                }
                Err(e) => {
                    self.ui.error(&format!(
                        "Failed to extract header from {}: {}",
                        file.name, e
                    ));

                    // Try to get basic file info even if header extraction fails
                    let file_info = FileInfo {
                        id: None,
                        filename: file.name.clone(),
                        file_header: None,
                        created_at: None,
                        updated_at: None,
                    };

                    file_infos.push(file_info);
                }
            }
        }

        Ok(file_infos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::tests::mocks::MockApiClient;
    use crate::tests::utils::test_helpers::*;
    use reqwest::Method;
    use serde_json::json;
    use std::sync::Arc;

    fn create_client() -> MockApiClient {
        MockApiClient::new(Config::default())
    }

    async fn create_test_model_directory(temp_dir: &tempfile::TempDir) -> ModelDirectory {
        let model_dir_path = temp_dir.path().join("test-model");
        tokio::fs::create_dir(&model_dir_path).await.unwrap();

        // Create encrypted files
        create_mock_safetensors_file(
            temp_dir,
            "test-model/model-00001-of-00002.safetensors",
            true,
        );
        create_mock_safetensors_file(
            temp_dir,
            "test-model/model-00002-of-00002.safetensors",
            true,
        );

        // Create unencrypted file (should be ignored or warned)
        create_mock_safetensors_file(temp_dir, "test-model/config.json", false);

        ModelDirectory::from_path(&model_dir_path).await.unwrap()
    }

    #[tokio::test]
    async fn test_upload_model_success() {
        let client = Arc::new(create_client().with_auth("testuser".to_string()));
        let service = UploadService::new(client.clone(), false);

        let temp_dir = create_temp_dir();
        let model = create_test_model_directory(&temp_dir).await;

        // Mock upload response
        let upload_response = json!({
            "total_uploaded": 2,
            "files": []
        });

        // We expect upload for batch. Since we have 2 encrypted files and batch size is 5, it will be 1 request.
        client.add_response(
            "/resources/testuser/models/test-model/files".to_string(),
            upload_response,
        );

        let result = service.upload_model(&model, "test-model", false).await;
        assert!(result.is_ok());

        // Verify requests - ensure files were uploaded
        let requests = client.get_requests();
        let upload_requests: Vec<_> = requests
            .iter()
            .filter(|r| r.method == Method::POST && r.endpoint.contains("/files"))
            .collect();

        assert_eq!(upload_requests.len(), 1);

        // Check payload contains 2 files
        let payload = upload_requests[0].payload.as_ref().unwrap();
        let files = payload.get("files").unwrap().as_array().unwrap();
        assert_eq!(files.len(), 2);
    }

    #[tokio::test]
    async fn test_upload_model_force_mode() {
        let client = Arc::new(create_client().with_auth("testuser".to_string()));
        let service = UploadService::new(client.clone(), false);

        let temp_dir = create_temp_dir();
        let model = create_test_model_directory(&temp_dir).await;

        // Mock responses
        // 1. Delete (for force mode)
        client.add_response(
            "/resources/testuser/models/test-model/files".to_string(),
            json!({}),
        );
        // 2. Upload
        client.add_response(
            "/resources/testuser/models/test-model/files".to_string(),
            json!({ "total_uploaded": 2 }),
        );

        let result = service.upload_model(&model, "test-model", true).await;
        assert!(result.is_ok());

        let requests = client.get_requests();

        // Verify delete was called first
        let delete_requests: Vec<_> = requests
            .iter()
            .filter(|r| r.method == Method::DELETE && r.endpoint.contains("/files"))
            .collect();
        assert_eq!(delete_requests.len(), 1);
    }

    #[tokio::test]
    async fn test_upload_model_no_files() {
        let client = Arc::new(create_client().with_auth("testuser".to_string()));
        let service = UploadService::new(client.clone(), false);

        let temp_dir = create_temp_dir();
        // Create only unencrypted file, so no files to upload
        let model_dir_path = temp_dir.path().join("test-model");
        tokio::fs::create_dir(&model_dir_path).await.unwrap();
        create_mock_safetensors_file(&temp_dir, "test-model/model.safetensors", false);
        let model = ModelDirectory::from_path(&model_dir_path).await.unwrap();

        let result = service.upload_model(&model, "test-model", false).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No valid file headers"));
    }

    #[tokio::test]
    async fn test_upload_model_api_error() {
        let client = Arc::new(create_client().with_auth("testuser".to_string()));
        let service = UploadService::new(client.clone(), false);

        let temp_dir = create_temp_dir();
        let model = create_test_model_directory(&temp_dir).await;

        // Register error response
        client.add_error(
            "/resources/testuser/models/test-model/files".to_string(),
            KoavaError::api(500, "Server Error".to_string()),
        );

        let result = service.upload_model(&model, "test-model", false).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Server Error"));
    }

    #[tokio::test]
    async fn test_upload_model_conflict_error_no_force() {
        let client = Arc::new(create_client().with_auth("testuser".to_string()));
        let service = UploadService::new(client.clone(), false);

        let temp_dir = create_temp_dir();
        let model = create_test_model_directory(&temp_dir).await;

        // Register conflict error
        client.add_error(
            "/resources/testuser/models/test-model/files".to_string(),
            KoavaError::api(409, "Files already exist".to_string()),
        );

        let result = service.upload_model(&model, "test-model", false).await;
        assert!(result.is_err());
        // Should convert to friendly upload error
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Files already exist on server. Use --force to overwrite"));
    }

    #[tokio::test]
    async fn test_upload_model_conflict_error_with_force() {
        let client = Arc::new(create_client().with_auth("testuser".to_string()));
        let service = UploadService::new(client.clone(), false);

        let temp_dir = create_temp_dir();
        let model = create_test_model_directory(&temp_dir).await;

        // 1. Delete succeeds
        client.add_response(
            "/resources/testuser/models/test-model/files".to_string(),
            json!({}),
        );

        // 2. Upload fails with conflict (simulating race condition or partial delete failure)
        // Note: Logic says if force is true, we delete first. But if upload still returns 409, we should warn and continue (skip batch).
        client.add_error(
            "/resources/testuser/models/test-model/files".to_string(),
            KoavaError::api(409, "Files already exist".to_string()),
        );

        let result = service.upload_model(&model, "test-model", true).await;

        // Should succeed (partial success / warning)
        // Logic: if conflict & force -> warn & continue.
        // Since we only have 1 batch, it continues and finishes.
        // But since batch failed, uploaded_count stays 0.
        // At end: if uploaded_count < file_infos.len(), logs warning.
        // Method returns Ok(()) unless catastrophic error.

        assert!(result.is_ok());
    }
}
