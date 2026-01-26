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
