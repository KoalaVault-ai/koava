use dialoguer::{theme::ColorfulTheme, Confirm};
use regex::Regex;
use std::path::{Path, PathBuf};
use tokio::fs;

use crate::error::{KoavaError, Result};
use crate::policy::LoadPolicy;
use crate::ui::UI;
use crate::{encrypt_safetensors_file, KeyService, ModelDirectory, ModelFile};
use crate::{EncryptArgs, RestoreArgs};

/// Backup status information
#[derive(Debug, Clone)]
enum BackupStatus {
    /// No backup directory exists or backup is empty
    NotExists,
    /// Backup exists and contains only unencrypted safetensors files
    ValidUnencrypted(Vec<ModelFile>),
    /// Backup exists but is invalid (contains encrypted files or non-safetensors files)
    Invalid,
}

/// Input file status information
#[derive(Debug, Clone)]
enum InputFileStatus {
    /// No safetensors files found in input directory
    NoFiles,
    /// Files are already encrypted or mixed state (need backup)
    Encrypted,
    /// All files are unencrypted
    AllUnencrypted(Vec<ModelFile>),
}

/// Output directory status information
#[derive(Debug, PartialEq, Clone)]
enum OutputStatus {
    /// Output directory is the same as input directory (in-place encryption)
    InPlace,
    /// Output directory does not exist or is empty
    NotExists,
    /// Output directory contains files
    HasFiles,
}

/// Action types for encryption plan
#[derive(Debug, Clone, PartialEq)]
enum Action {
    /// Copy file from source to destination
    Copy,
    /// Encrypt file from source to destination
    Encrypt,
    /// Move file from source to destination
    Move,
}

/// Status of an operation
/// Individual operation in the encryption plan
#[derive(Debug, Clone)]
struct Operation {
    /// Action to perform
    action: Action,
    /// Input path
    input: PathBuf,
    /// Output path
    output: PathBuf,
    /// Optional file information for display
    file_info: Option<ModelFile>,
}

/// Encryption keys for file encryption
#[derive(Debug, Clone)]
struct EncryptionKeys {
    /// User sign key
    user_sign_key: serde_json::Value,
    /// Master key
    master_key: serde_json::Value,
}

/// Complete encryption plan with multiple phases
#[derive(Debug, Clone)]
struct EncryptionPlan {
    /// Backup operations (e.g., move files to backup)
    backup: Vec<Operation>,
    /// Main operations (e.g., encrypt files)
    main: Vec<Operation>,
}

// TODO: Complete Git LFS Support Implementation
//
// Current Status: Basic support for Hugging Face models with symlinks
// Future Goals: Full Git LFS compatibility with user-configurable options
//
// Implementation Plan:
// 1. Git LFS Detection
//    - Detect .gitattributes files
//    - Identify symlink patterns
//    - Determine LFS repository structure
//
// 2. Enhanced File Handling
//    - Preserve symlink relationships
//    - Copy blobs directory structure
//    - Maintain refs for version management
//
// 3. User Configuration
//    - --preserve-lfs: Keep LFS structure
//    - --flatten-lfs: Convert to regular files (current behavior)
//    - --lfs-mode: Auto-detect and suggest best approach
//
// 4. Improved User Experience
//    - LFS structure warnings
//    - Size estimation for LFS operations
//    - Progress tracking for large LFS repositories
//
// 5. Testing and Validation
//    - Test with various LFS repository structures
//    - Validate symlink preservation
//    - Ensure backward compatibility

pub struct EncryptService {
    ui: UI,
    config: crate::config::Config,
}

impl EncryptService {
    pub fn new(config: crate::config::Config) -> Self {
        Self {
            ui: UI::new(),
            config,
        }
    }

    /// Execute encryption based on arguments
    pub async fn encrypt<C: crate::client::ApiClient + ?Sized>(
        &self,
        client: &C,
        args: EncryptArgs,
    ) -> Result<()> {
        self.ui.info(&format!(
            "Scanning model directory: {}",
            args.model_path.display()
        ));

        // Load model directory
        let model = ModelDirectory::from_path(&args.model_path).await?;

        // Check backup status
        let backup_dir = args.model_path.join(".backup");
        let backup_status = self.check_backup_status(&backup_dir).await?;

        // Handle invalid backup status
        if matches!(backup_status, BackupStatus::Invalid) {
            return Err(KoavaError::validation("Backup directory is invalid, may contain encrypted files or non-safetensors files."));
        }

        // Check input file status
        let input_status = self.check_input_file_status(&model).await?;

        // Check output status
        let output_status = self.check_output_status(&args).await?;

        // Generate complete encryption plan
        let plan = self
            .generate_encrypt_plan(&model, &args, backup_status, input_status, output_status)
            .await?;

        let total_operations = plan.backup.len() + plan.main.len();

        if total_operations == 0 {
            self.ui.warning("No operations to perform");
            return Ok(());
        }

        // Display encryption plan
        self.display_encryption_plan(&plan.backup, &plan.main);

        if args.dry_run {
            return Ok(());
        }

        // Get encryption keys BEFORE doing any file operations
        self.ui
            .info("Verifying authentication and retrieving encryption keys...");
        let keys = self.get_encryption_keys(client, &args).await?;

        // Execute the encryption plan
        if let Err(e) = self.execute_encryption_plan(&plan, &args, &keys).await {
            self.ui.error(&format!("Encryption failed: {}", e));

            // Check if this was in-place encryption and suggest restore
            let is_in_place =
                args.output.is_none() || args.output.as_ref() == Some(&args.model_path);
            if is_in_place {
                self.ui
                    .info("💡 Tip: You can use 'restore' to restore your files from backup");
            }

            return Err(e);
        }

        // Copy auxiliary files after successful encryption
        if let Some(output_dir) = &args.output {
            if output_dir != &args.model_path {
                self.ui
                    .info("Copying auxiliary files to output directory...");
                self.copy_auxiliary_files(&args.model_path, output_dir)
                    .await?;
            }
        }

        // Post-processing: insert README compliance block and add parallel license
        self.handle_readme_and_license(&args).await?;

        self.ui.success("Encryption completed successfully!");

        Ok(())
    }

    /// Infer model name from args: prefer --name, then --output basename, then model_path basename
    fn infer_model_name(&self, args: &EncryptArgs) -> Result<String> {
        use std::path::{Component, Path};

        let basename_from = |p: &Path| -> Option<String> {
            p.components().rev().find_map(|c| match c {
                Component::Normal(s) => s.to_str().map(|s| s.to_string()),
                _ => None,
            })
        };

        if let Some(name) = &args.name {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(KoavaError::validation(
                    "Model name cannot be empty".to_string(),
                ));
            }
            return Ok(trimmed.to_string());
        }

        if let Some(output_dir) = &args.output {
            if let Some(base) = basename_from(output_dir).filter(|s| !s.trim().is_empty()) {
                return Ok(base);
            } else {
                return Err(KoavaError::validation(
                    "Failed to derive model name from --output path".to_string(),
                ));
            }
        }

        let canonical_path = args
            .model_path
            .canonicalize()
            .map_err(|e| KoavaError::validation(format!("Failed to canonicalize path: {}", e)))?;
        if let Some(dir_name) = basename_from(&canonical_path) {
            return Ok(dir_name);
        }

        Err(KoavaError::validation(
            "Failed to derive model name from canonicalized path".to_string(),
        ))
    }

    /// Execute the encryption plan by running all phases in order
    async fn execute_encryption_plan(
        &self,
        plan: &EncryptionPlan,
        args: &EncryptArgs,
        keys: &EncryptionKeys,
    ) -> Result<()> {
        // Create necessary directories before executing operations

        // Create backup directory if there are backup operations
        if !plan.backup.is_empty() {
            let backup_dir = args.model_path.join(".backup");
            self.ui.info("Creating backup directory...");
            fs::create_dir_all(&backup_dir).await?;
        }

        // Create output directory if it's different from input directory
        if let Some(output_dir) = &args.output {
            if output_dir != &args.model_path {
                self.ui.info("Creating output directory...");
                fs::create_dir_all(output_dir).await?;
            }
        }

        // Calculate total operations for progress bar
        let total_operations = plan.backup.len() + plan.main.len();
        let progress_bar =
            crate::ui::create_progress_bar(total_operations as u64, "Processing operations...");

        // Execute backup operations first
        for (i, operation) in plan.backup.iter().enumerate() {
            let operation_name = match operation.action {
                Action::Move => "Moving to backup",
                Action::Copy => "Copying",
                Action::Encrypt => "Encrypting",
            };

            if let Some(file) = &operation.file_info {
                progress_bar.set_message(format!("{} {}", operation_name, file.name));
            } else {
                progress_bar.set_message(format!("{} operation {}", operation_name, i + 1));
            }

            if let Err(e) = self.execute_operation(operation, args, keys).await {
                progress_bar.finish_with_message("Encryption failed");
                self.ui
                    .error(&format!("Backup operation {} failed: {}", i + 1, e));
                return Err(e);
            }

            progress_bar.inc(1);
        }

        // Execute main operations
        for (i, operation) in plan.main.iter().enumerate() {
            let operation_name = match operation.action {
                Action::Move => "Moving",
                Action::Copy => "Copying",
                Action::Encrypt => "Encrypting",
            };

            if let Some(file) = &operation.file_info {
                progress_bar.set_message(format!("{} {}", operation_name, file.name));
            } else {
                progress_bar.set_message(format!("{} operation {}", operation_name, i + 1));
            }

            if let Err(e) = self.execute_operation(operation, args, keys).await {
                progress_bar.finish_with_message("Encryption failed");
                self.ui
                    .error(&format!("Main operation {} failed: {}", i + 1, e));
                return Err(e);
            }

            progress_bar.inc(1);
        }

        progress_bar.finish_with_message("Encryption completed");
        Ok(())
    }

    /// Execute a single operation
    async fn execute_operation(
        &self,
        operation: &Operation,
        _args: &EncryptArgs,
        keys: &EncryptionKeys,
    ) -> Result<()> {
        match operation.action {
            Action::Move => {
                // Ensure target directory exists
                if let Some(parent) = operation.output.parent() {
                    fs::create_dir_all(parent).await?;
                }
                fs::rename(&operation.input, &operation.output).await?;
            }
            Action::Copy => {
                // Ensure target directory exists
                if let Some(parent) = operation.output.parent() {
                    fs::create_dir_all(parent).await?;
                }
                fs::copy(&operation.input, &operation.output).await?;
            }
            Action::Encrypt => {
                // Ensure target directory exists
                if let Some(parent) = operation.output.parent() {
                    fs::create_dir_all(parent).await?;
                }

                // Use the existing encryption logic
                let load_policy = LoadPolicy::new(None, None);
                encrypt_safetensors_file(
                    &operation.input,
                    &operation.output,
                    &keys.master_key,
                    &keys.user_sign_key,
                    &load_policy,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Execute restore from backup
    pub async fn restore(&self, args: RestoreArgs) -> Result<()> {
        let backup_dir = args.model_path.join(".backup");

        // Check backup status first
        let backup_status = self.check_backup_status(&backup_dir).await?;

        match backup_status {
            BackupStatus::NotExists => Err(KoavaError::validation("No backup directory found")),
            BackupStatus::Invalid => Err(KoavaError::validation("Backup directory is invalid")),
            BackupStatus::ValidUnencrypted(backup_files) => {
                self.ui
                    .info(&format!("Found {} files in backup", backup_files.len()));

                // Delete existing model files in input directory
                self.ui.info("Removing existing model files...");
                self.delete_model_files(&args.model_path).await?;

                // Move files from backup to input directory
                self.ui.info("Moving files from backup...");
                for backup_file in &backup_files {
                    let target_path = args.model_path.join(&backup_file.name);
                    fs::rename(&backup_file.path, &target_path).await?;
                    self.ui.info(&format!("Moved: {}", backup_file.name));
                }

                // Restore README and LICENSE files if they exist in backup
                self.restore_readme_and_license(&args.model_path, &backup_dir)
                    .await?;

                self.ui.success("Restore completed successfully!");
                Ok(())
            }
        }
    }

    /// Check backup status and validate file encryption state
    async fn check_backup_status(&self, backup_dir: &Path) -> Result<BackupStatus> {
        if !backup_dir.exists() {
            return Ok(BackupStatus::NotExists);
        }

        // First check if directory has any files at all
        let mut entries = fs::read_dir(backup_dir).await?;
        let mut has_any_files = false;

        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_file() {
                has_any_files = true;
                break;
            }
        }

        if !has_any_files {
            return Ok(BackupStatus::NotExists);
        }

        // Directory has files, now use ModelDirectory to scan and validate
        match ModelDirectory::from_path(backup_dir).await {
            Ok(backup_model) => {
                // Check for invalid states first
                if !backup_model.encrypted_files.is_empty() {
                    return Ok(BackupStatus::Invalid);
                }

                // Check for non-safetensors files by comparing total files with safetensors files
                let total_files = backup_model.all_files.len();
                let safetensors_files =
                    backup_model.unencrypted_files.len() + backup_model.encrypted_files.len();

                if total_files != safetensors_files {
                    return Ok(BackupStatus::Invalid);
                }

                // Valid backup: return unencrypted files
                Ok(BackupStatus::ValidUnencrypted(
                    backup_model.unencrypted_files.clone(),
                ))
            }
            Err(_) => {
                // ModelDirectory::from_path failed but we know directory has files
                // This means files exist but are not valid safetensors files
                Ok(BackupStatus::Invalid)
            }
        }
    }

    /// Check input file status and encryption state
    async fn check_input_file_status(&self, model: &ModelDirectory) -> Result<InputFileStatus> {
        let unencrypted_files = model.get_unencrypted_files();
        let encrypted_files = model.get_encrypted_files();

        let total_files = unencrypted_files.len() + encrypted_files.len();

        if total_files == 0 {
            return Ok(InputFileStatus::NoFiles);
        }

        // Determine input file status based on encryption counts
        if encrypted_files.is_empty() {
            Ok(InputFileStatus::AllUnencrypted(unencrypted_files.to_vec()))
        } else {
            // Encrypted or Mixed - both need backup
            Ok(InputFileStatus::Encrypted)
        }
    }

    /// Check output directory status and file state
    async fn check_output_status(&self, args: &EncryptArgs) -> Result<OutputStatus> {
        let output_dir = args.output.as_ref().unwrap_or(&args.model_path);

        // Check if output is the same as input (in-place encryption)
        if output_dir == &args.model_path {
            return Ok(OutputStatus::InPlace);
        }

        // Output directory is different from input
        if !output_dir.exists() {
            return Ok(OutputStatus::NotExists);
        }

        // Check if output directory has files
        let mut entries = fs::read_dir(output_dir).await?;
        let mut has_files = false;

        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            if file_type.is_file() {
                has_files = true;
                break;
            }
        }

        if has_files {
            Ok(OutputStatus::HasFiles)
        } else {
            Ok(OutputStatus::NotExists)
        }
    }

    /// Generate complete encryption plan based on all status checks
    async fn generate_encrypt_plan(
        &self,
        model: &ModelDirectory,
        args: &EncryptArgs,
        backup_status: BackupStatus,
        input_status: InputFileStatus,
        output_status: OutputStatus,
    ) -> Result<EncryptionPlan> {
        // Get source files (supports both in-place and non-in-place)
        let source_result = self
            .get_source_files(model, args, &backup_status, &input_status, &output_status)
            .await?;
        if source_result.is_none() {
            // No valid source state, exit early
            return Ok(EncryptionPlan {
                backup: vec![],
                main: vec![],
            });
        }

        let (source_files, is_in_backup) = source_result.unwrap();
        let is_in_place = matches!(output_status, OutputStatus::InPlace);

        let mut backup_operations = Vec::new();
        let main_operations;

        if is_in_place {
            // In-place encryption: generate backup and main operations
            let backup_dir = args.model_path.join(".backup");

            // Generate backup operations if needed
            if !is_in_backup {
                backup_operations = source_files
                    .iter()
                    .map(|file| {
                        let backup_path = backup_dir.join(&file.name);
                        Operation {
                            action: Action::Move,
                            input: file.path.clone(),
                            output: backup_path,
                            file_info: Some(file.clone()),
                        }
                    })
                    .collect();
            }

            // Generate main operations based on exclude logic
            main_operations = source_files
                .iter()
                .map(|file| {
                    let input_path = backup_dir.join(&file.name);

                    if self.is_excluded(&file.name, args) {
                        // File is excluded, copy from backup to original location
                        Operation {
                            action: Action::Copy,
                            input: input_path,
                            output: file.path.clone(),
                            file_info: Some(file.clone()),
                        }
                    } else {
                        // File is not excluded, encrypt it
                        let output_name = file.name.clone(); // Keep .safetensors suffix
                        let output_path = args.model_path.join(&output_name);

                        Operation {
                            action: Action::Encrypt,
                            input: input_path,
                            output: output_path,
                            file_info: Some(file.clone()),
                        }
                    }
                })
                .collect();
        } else {
            // Non-in-place encryption: only generate main operations
            let output_dir = args.output.as_ref().unwrap_or(&args.model_path);

            main_operations = source_files
                .iter()
                .map(|file| {
                    let output_name = file.name.clone(); // Keep .safetensors suffix
                    let output_path = output_dir.join(&output_name);

                    Operation {
                        action: Action::Encrypt,
                        input: file.path.clone(),
                        output: output_path,
                        file_info: Some(file.clone()),
                    }
                })
                .collect();
        }

        Ok(EncryptionPlan {
            backup: backup_operations,
            main: main_operations,
        })
    }

    /// Get source files for encryption (supports both in-place and non-in-place)
    /// Returns: (source_files, is_in_backup) or None if no valid state
    async fn get_source_files(
        &self,
        _model: &ModelDirectory,
        args: &EncryptArgs,
        backup_status: &BackupStatus,
        input_status: &InputFileStatus,
        output_status: &OutputStatus,
    ) -> Result<Option<(Vec<ModelFile>, bool)>> {
        // Check if this is in-place encryption
        let is_in_place = matches!(output_status, OutputStatus::InPlace);

        match input_status {
            InputFileStatus::AllUnencrypted(source_files) => {
                if is_in_place {
                    // For in-place encryption, check if backup has files and handle force parameter
                    if let BackupStatus::ValidUnencrypted(_) = backup_status {
                        if args.force {
                            self.ui
                                .info("📁 Found existing backup directory, will overwrite backup");
                            Ok(Some((source_files.clone(), false)))
                        } else {
                            self.ui.info(
                                "📁 Found existing backup directory, will encrypt from backup",
                            );
                            Ok(Some((source_files.clone(), true)))
                        }
                    } else {
                        // No pre operations needed for unencrypted files
                        Ok(Some((source_files.clone(), false)))
                    }
                } else {
                    // For non-in-place encryption, don't care about backup
                    Ok(Some((source_files.clone(), false)))
                }
            }
            InputFileStatus::NoFiles | InputFileStatus::Encrypted => {
                if is_in_place {
                    // For in-place encryption, these cases all need to check backup status and force has no effect
                    self.handle_backup_dependent_cases(args, backup_status, input_status)
                        .await
                } else {
                    // For non-in-place encryption, only check if backup has files
                    if let BackupStatus::ValidUnencrypted(source_files) = backup_status {
                        self.ui
                            .info("📁 Found existing backup directory, will encrypt from backup");
                        Ok(Some((source_files.clone(), true)))
                    } else {
                        // No valid backup available for non-in-place encryption
                        self.ui.error(
                            "No valid backup available for encryption, encryption cancelled",
                        );
                        Ok(None)
                    }
                }
            }
        }
    }

    /// Handle cases that depend on backup status (NoFiles, AllEncrypted, Mixed)
    /// Returns: (source_files, is_in_backup) or None if no valid state
    async fn handle_backup_dependent_cases(
        &self,
        args: &EncryptArgs,
        backup_status: &BackupStatus,
        input_status: &InputFileStatus,
    ) -> Result<Option<(Vec<ModelFile>, bool)>> {
        // Display appropriate message based on input status
        self.ui
            .warning("Input model directory contains encrypted files, checking backup...");

        // Check backup status
        if let BackupStatus::ValidUnencrypted(source_files) = backup_status {
            // if backup has unencrypted files
            // Check if --force has any effect in these cases
            if args.force {
                self.ui
                    .warning("Got backup, but --force parameter has no effect in this case");
            }

            // For Encrypted, ask for user confirmation
            if matches!(input_status, InputFileStatus::Encrypted) {
                let proceed = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Do you want to re-encrypt from the existing backup? The existing encrypted files will be deleted first")
                    .default(false)
                    .interact()?;

                if !proceed {
                    self.ui.info("Encryption cancelled");
                    return Ok(None);
                }
            }
            Ok(Some((source_files.clone(), true)))
        } else {
            // No valid backup available - all cases cannot proceed with encryption
            self.ui
                .error("No valid backup available for encryption, encryption cancelled");
            Ok(None)
        }
    }

    /// Check if a file should be excluded based on args filters
    fn is_excluded(&self, file_name: &str, args: &EncryptArgs) -> bool {
        // Check if exclude list is provided
        if let Some(exclude_list) = &args.exclude {
            // Split by comma and check if file_name matches any excluded file
            let excluded_files: Vec<&str> = exclude_list.split(',').map(|s| s.trim()).collect();
            excluded_files.contains(&file_name)
        } else {
            // No exclude list provided, file is not excluded
            false
        }
    }

    /// Display detailed encryption plan based on all status information
    fn display_encryption_plan(
        &self,
        backup_operations: &[Operation],
        main_operations: &[Operation],
    ) {
        self.ui.info("Encryption Plan:");

        // Count total operations
        let total_operations = backup_operations.len() + main_operations.len();

        self.ui
            .info(&format!("Total operations: {}", total_operations));

        // Display backup operations
        if !backup_operations.is_empty() {
            self.ui.info("Backup operations:");
            for operation in backup_operations {
                if operation.action == Action::Move {
                    if let Some(file) = &operation.file_info {
                        self.ui.info(&format!("  - Move {} to backup", file.name));
                    }
                }
            }
        }

        // Display main operations
        if !main_operations.is_empty() {
            self.ui.info("Main operations:");
            for operation in main_operations {
                if let Some(file) = &operation.file_info {
                    match operation.action {
                        Action::Encrypt => {
                            self.ui.info(&format!("  - Encrypt {}", file.name));
                        }
                        Action::Copy => {
                            self.ui.info(&format!("  - Copy {}", file.name));
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Copy non-safetensors files (config, tokenizer, etc.)
    async fn copy_auxiliary_files(&self, input_dir: &Path, output_dir: &Path) -> Result<()> {
        use walkdir::WalkDir;

        for entry in WalkDir::new(input_dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let file_path = entry.path();

                // Skip safetensors files (they are handled separately)
                if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                    let ext_lower = ext.to_lowercase();
                    if ext_lower == "safetensors" || ext_lower == "cryptotensors" {
                        continue;
                    }
                }

                // Skip backup and hidden directories
                let path_str = file_path.to_string_lossy();
                if path_str.contains("/.") {
                    continue;
                }

                // Calculate relative path and copy
                let relative_path = match file_path.strip_prefix(input_dir) {
                    Ok(rel) => rel,
                    Err(_) => continue,
                };
                let target_path = output_dir.join(relative_path);

                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent).await?;
                }

                fs::copy(file_path, target_path).await?;
            }
        }

        Ok(())
    }

    /// Get encryption keys from SDK
    async fn get_encryption_keys<C: crate::client::ApiClient + ?Sized>(
        &self,
        client: &C,
        args: &EncryptArgs,
    ) -> Result<EncryptionKeys> {
        // Use the authenticated client passed from caller
        let key_service = KeyService::new(client);

        // Get user's sign key for signing
        let sign_key_jwk = key_service.request_sign_key().await?;

        // Resolve model name using unified inference
        let model_name = self.infer_model_name(args)?;
        let enc_key_jwk = key_service.request_master_key(&model_name).await?;

        Ok(EncryptionKeys {
            user_sign_key: sign_key_jwk,
            master_key: enc_key_jwk,
        })
    }

    /// Delete all model files in the directory
    async fn delete_model_files(&self, model_path: &Path) -> Result<()> {
        let mut entries = fs::read_dir(model_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_type = entry.file_type().await?;

            if file_type.is_file() {
                // Remove all safetensors-related files
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    let ext_lower = ext.to_lowercase();
                    if ext_lower == "safetensors" || ext_lower == "cryptotensors" {
                        fs::remove_file(&path).await?;
                        self.ui.info(&format!(
                            "Removed: {}",
                            path.file_name().unwrap().to_string_lossy()
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle README and LICENSE files for Hugging Face compliance
    async fn handle_readme_and_license(&self, args: &EncryptArgs) -> Result<()> {
        let model_name = self.infer_model_name(args)?;

        // Determine target directory for README injection
        let target_dir = if let Some(output_dir) = &args.output {
            output_dir
        } else {
            &args.model_path
        };

        // Handle README.md in target directory only (no backup for README)
        self.handle_readme_file(target_dir, &model_name).await?;

        // Handle LICENSE file (parallel license in target directory)
        self.handle_license_file(target_dir).await?;

        Ok(())
    }

    /// Handle README.md file creation or update
    async fn handle_readme_file(&self, target_dir: &Path, model_name: &str) -> Result<()> {
        let target_readme_path = target_dir.join("README.md");
        let compliance_block = crate::templates::README_TEMPLATE;

        if target_readme_path.exists() {
            let existing_content = fs::read_to_string(&target_readme_path).await?;
            if existing_content.contains("<!-- KOALAVAULT_ENCRYPTED_MODEL_START -->") {
                self.ui
                    .info("README.md already contains encrypted model information");
                return Ok(());
            }
            // Determine license URL if possible (only affect when front matter exists)
            let mut license_url: Option<String> = None;
            if self.has_yaml_front_matter(&existing_content) {
                // Try to get HF username via local login
                if let Ok(Some(owner)) = self.detect_hf_username().await {
                    let url = Self::build_hf_license_url(&owner, model_name);
                    license_url = Some(url);
                } else if let Some((owner, repo)) =
                    Self::infer_owner_repo_from_text(&existing_content)
                {
                    let url = Self::build_hf_license_url(&owner, &repo);
                    license_url = Some(url);
                }
            }
            // Normalize YAML front matter license fields first (only if front matter exists)
            let normalized = if let Some(url) = license_url.as_deref() {
                // Use HTTPS URL if available
                self.normalize_front_matter_license_with_link(&existing_content, Some(url))
            } else {
                // Fallback to local path when URL is not available
                self.normalize_front_matter_license(&existing_content)
            };
            let new_content = self.insert_block_after_first_heading(&normalized, compliance_block);
            fs::write(&target_readme_path, new_content).await?;
            self.ui.info("Inserted encrypted model compliance block into README.md and normalized license fields");
        } else {
            // Create minimal README if not exists (no YAML front matter is added)
            let mut new_readme = String::new();
            new_readme.push_str(&format!("# {}\n\n", model_name));
            new_readme.push_str(compliance_block);
            new_readme.push('\n');
            fs::write(&target_readme_path, new_readme).await?;
            self.ui
                .info("Created README.md with encrypted model compliance block");
        }

        Ok(())
    }

    /// Handle LICENSE file creation or update
    async fn handle_license_file(&self, model_path: &Path) -> Result<()> {
        // Always create a separate KoalaVault license file without touching the original LICENSE
        let kv_license_path = model_path.join("LICENSE.KOALAVAULT");

        // If already present and looks valid, skip
        if kv_license_path.exists() {
            let existing = fs::read_to_string(&kv_license_path)
                .await
                .unwrap_or_default();
            if existing.contains("KoalaVault Proprietary License") {
                self.ui.info("KoalaVault license already present; skipping");
                return Ok(());
            }
        }

        // Write/update KoalaVault license
        fs::write(&kv_license_path, crate::templates::LICENSE_TEMPLATE).await?;
        self.ui.info(&format!(
            "Created KoalaVault license: {}",
            kv_license_path.display()
        ));

        Ok(())
    }

    /// Restore README and LICENSE files
    async fn restore_readme_and_license(
        &self,
        model_path: &Path,
        _backup_dir: &Path,
    ) -> Result<()> {
        // Check if current README was inserted by our tool (contains marker) and/or YAML annotations, and revert in-place
        let target_readme = model_path.join("README.md");
        if target_readme.exists() {
            if let Ok(current) = fs::read_to_string(&target_readme).await {
                let without_block = self.remove_compliance_block(&current);
                let restored_yaml = self.restore_front_matter_from_comments(&without_block);
                if restored_yaml != current {
                    fs::write(&target_readme, restored_yaml).await?;
                    self.ui.info("Reverted README.md compliance block and restored original model card fields");
                }
            }
        }

        // Remove KoalaVault parallel license file if present
        let kv_license_path = model_path.join("LICENSE.KOALAVAULT");
        if kv_license_path.exists() {
            let _ = fs::remove_file(&kv_license_path).await;
            self.ui.info(&format!(
                "Removed KoalaVault license: {}",
                kv_license_path.display()
            ));
        }

        Ok(())
    }

    /// Normalize license fields in YAML front matter if present; otherwise return content unchanged
    fn normalize_front_matter_license(&self, content: &str) -> String {
        let bytes = content.as_bytes();
        if bytes.starts_with(b"---\n") {
            // Find end of front matter (line with only ---)
            let mut end_idx = None;
            let mut pos = 4; // after initial ---\n
            while pos < bytes.len() {
                if let Some(nl) = content[pos..].find('\n') {
                    let line_start = pos;
                    let line_end = pos + nl; // exclusive
                    let line = &content[line_start..line_end];
                    if line.trim() == "---" {
                        end_idx = Some(line_end + 1); // include trailing \n
                        break;
                    }
                    pos = line_end + 1;
                } else {
                    break;
                }
            }
            if let Some(end) = end_idx {
                let header = &content[0..end];
                let body = &content[end..];

                // Split header lines (skip first '---' and last '---')
                let mut lines: Vec<&str> = header.lines().collect();
                if !lines.is_empty() && lines[0].trim() == "---" {
                    lines.remove(0);
                }
                if !lines.is_empty() && lines[lines.len() - 1].trim() == "---" {
                    lines.pop();
                }

                // Track if keys exist
                let mut has_license = false;
                let mut has_license_link = false;

                // Rebuild lines with updates
                let mut new_header_lines: Vec<String> = Vec::new();
                new_header_lines.push(String::from("---"));
                for l in lines {
                    let trimmed = l.trim_start();
                    if trimmed.starts_with("license:") {
                        has_license = true;
                        new_header_lines.push(String::from("license: other"));
                    } else if trimmed.starts_with("license_link:") {
                        has_license_link = true;
                        new_header_lines.push(String::from("license_link: ./LICENSE.KOALAVAULT"));
                    } else {
                        new_header_lines.push(l.to_string());
                    }
                }
                if !has_license {
                    new_header_lines.push(String::from("license: other"));
                }
                if !has_license_link {
                    new_header_lines.push(String::from("license_link: ./LICENSE.KOALAVAULT"));
                }
                new_header_lines.push(String::from("---"));

                let mut new_content = new_header_lines.join("\n");
                if !new_content.ends_with('\n') {
                    new_content.push('\n');
                }
                new_content.push_str(body);
                return new_content;
            }
        }
        // No front matter present; return as-is
        content.to_string()
    }

    /// Insert compliance block after first markdown heading; if none, prepend
    fn insert_block_after_first_heading(&self, existing_content: &str, block: &str) -> String {
        let lines: Vec<&str> = existing_content.lines().collect();
        let mut insert_idx = None;
        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with('#') {
                insert_idx = Some(i + 1);
                break;
            }
        }
        let mut new_content = String::new();
        match insert_idx {
            Some(idx) => {
                new_content.push_str(&lines[..idx].join("\n"));
                new_content.push_str("\n\n");
                new_content.push_str(block);
                if idx < lines.len() {
                    new_content.push_str("\n\n");
                    new_content.push_str(&lines[idx..].join("\n"));
                } else {
                    new_content.push('\n');
                }
            }
            None => {
                new_content.push_str(block);
                new_content.push_str("\n\n");
                new_content.push_str(existing_content);
                if !new_content.ends_with('\n') {
                    new_content.push('\n');
                }
            }
        }
        new_content
    }

    // Returns Ok(Some(username)) on success, Ok(None) on not found, Err on execution failure
    async fn detect_hf_username(&self) -> std::result::Result<Option<String>, KoavaError> {
        match crate::huggingface::check_huggingface_cli_status(&self.config).await? {
            crate::huggingface::HuggingFaceCliStatus::LoggedIn(username) => Ok(Some(username)),
            _ => Ok(None),
        }
    }

    fn has_yaml_front_matter(&self, content: &str) -> bool {
        content.as_bytes().starts_with(b"---\n")
    }

    fn build_hf_license_url(owner: &str, model: &str) -> String {
        format!(
            "https://huggingface.co/{}/{}/blob/main/LICENSE.KOALAVAULT",
            owner, model
        )
    }

    fn infer_owner_repo_from_text(text: &str) -> Option<(String, String)> {
        // Match https://huggingface.co/<owner>/<repo>
        let re =
            Regex::new(r"https?://huggingface\.co/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)").ok()?;
        if let Some(caps) = re.captures(text) {
            let owner = caps.get(1)?.as_str().to_string();
            let repo = caps.get(2)?.as_str().to_string();
            return Some((owner, repo));
        }
        None
    }

    /// Normalize license fields in YAML front matter; if license_url is Some, set license_link to it.
    /// Stores original values as HTML comments after the YAML block for restore.
    fn normalize_front_matter_license_with_link(
        &self,
        content: &str,
        license_url: Option<&str>,
    ) -> String {
        let bytes = content.as_bytes();
        if !bytes.starts_with(b"---\n") {
            return content.to_string();
        }
        // Find end of front matter (line with only ---)
        let mut end_idx = None;
        let mut pos = 4; // after initial ---\n
        while pos < bytes.len() {
            if let Some(nl) = content[pos..].find('\n') {
                let line_start = pos;
                let line_end = pos + nl; // exclusive
                let line = &content[line_start..line_end];
                if line.trim() == "---" {
                    end_idx = Some(line_end + 1); // include trailing \n
                    break;
                }
                pos = line_end + 1;
            } else {
                break;
            }
        }
        if let Some(end) = end_idx {
            let header = &content[0..end];
            let body = &content[end..];

            // Split header lines (skip first '---' and last '---')
            let mut lines: Vec<&str> = header.lines().collect();
            if !lines.is_empty() && lines[0].trim() == "---" {
                lines.remove(0);
            }
            if !lines.is_empty() && lines[lines.len() - 1].trim() == "---" {
                lines.pop();
            }

            // Track current and changed values
            let mut cur_license: Option<String> = None;
            let mut cur_license_link: Option<String> = None;

            for l in &lines {
                let trimmed = l.trim_start();
                if let Some(stripped) = trimmed.strip_prefix("license:") {
                    cur_license = Some(stripped.trim().to_string());
                } else if let Some(stripped) = trimmed.strip_prefix("license_link:") {
                    cur_license_link = Some(stripped.trim().to_string());
                }
            }

            // Compute new header lines
            let mut new_header_lines: Vec<String> = Vec::new();
            new_header_lines.push(String::from("---"));

            let mut wrote_license = false;
            let mut wrote_license_link = false;

            for l in &lines {
                let trimmed = l.trim_start();
                if trimmed.starts_with("license:") {
                    // Always set to other
                    new_header_lines.push(String::from("license: other"));
                    wrote_license = true;
                } else if trimmed.starts_with("license_link:") {
                    // Set to HTTPS URL if provided, else keep original
                    if let Some(url) = license_url {
                        new_header_lines.push(format!("license_link: {}", url));
                    } else {
                        new_header_lines.push(l.to_string());
                    }
                    wrote_license_link = true;
                } else {
                    new_header_lines.push(l.to_string());
                }
            }

            if !wrote_license {
                new_header_lines.push(String::from("license: other"));
            }
            if !wrote_license_link {
                if let Some(url) = license_url {
                    new_header_lines.push(format!("license_link: {}", url));
                }
            }
            new_header_lines.push(String::from("---"));

            // Build comments block only if not already present
            let mut comments_block = String::new();
            let has_comment_license = body.contains("KOALAVAULT_ORIG_LICENSE:");
            let has_comment_link = body.contains("KOALAVAULT_ORIG_LICENSE_LINK:");

            if !has_comment_license || !has_comment_link {
                // Compose per-field comments, using __NONE__ when field absent originally
                if !has_comment_license {
                    let orig = cur_license.unwrap_or_else(|| "__NONE__".to_string());
                    comments_block
                        .push_str(&format!("<!-- KOALAVAULT_ORIG_LICENSE: {} -->\n", orig));
                }
                if !has_comment_link {
                    // Only produce comment if we are setting a link or there was one originally
                    if license_url.is_some() || cur_license_link.is_some() {
                        let orig = cur_license_link.unwrap_or_else(|| "__NONE__".to_string());
                        comments_block.push_str(&format!(
                            "<!-- KOALAVAULT_ORIG_LICENSE_LINK: {} -->\n",
                            orig
                        ));
                    }
                }
                if !comments_block.is_empty() {
                    comments_block.push('\n');
                }
            }

            let mut new_content = new_header_lines.join("\n");
            if !new_content.ends_with('\n') {
                new_content.push('\n');
            }
            new_content.push_str(&comments_block);
            new_content.push_str(body);
            return new_content;
        }
        content.to_string()
    }

    /// Remove the inserted compliance block if present (based on start/end markers), preserving other content
    fn remove_compliance_block(&self, content: &str) -> String {
        let start_marker = "<!-- KOALAVAULT_ENCRYPTED_MODEL_START -->";
        let end_marker = "<!-- KOALAVAULT_ENCRYPTED_MODEL_END -->";
        if !content.contains(start_marker) {
            return content.to_string();
        }

        let mut out = String::new();
        let mut skipping = false;

        for line in content.lines() {
            if line.contains(start_marker) {
                skipping = true;
                continue;
            }
            if line.contains(end_marker) {
                skipping = false;
                continue;
            }
            if !skipping {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    /// Restore YAML front matter fields from KOALAVAULT_ORIG_* comments placed after YAML; remove the comments and compliance block
    fn restore_front_matter_from_comments(&self, content: &str) -> String {
        let bytes = content.as_bytes();
        if !bytes.starts_with(b"---\n") {
            return content.to_string();
        }
        // Find end of front matter
        let mut end_idx = None;
        let mut pos = 4;
        while pos < bytes.len() {
            if let Some(nl) = content[pos..].find('\n') {
                let line_start = pos;
                let line_end = pos + nl;
                let line = &content[line_start..line_end];
                if line.trim() == "---" {
                    end_idx = Some(line_end + 1);
                    break;
                }
                pos = line_end + 1;
            } else {
                break;
            }
        }
        if end_idx.is_none() {
            return content.to_string();
        }
        let end = end_idx.unwrap();
        let header = &content[0..end];
        let mut body = content[end..].to_string();

        // Extract and remove comment lines from the start of body
        let mut orig_license: Option<String> = None;
        let mut orig_link: Option<String> = None;
        {
            let mut new_body = String::new();
            let mut at_start = true;
            for line in body.lines() {
                let trimmed = line.trim();
                if at_start && trimmed.starts_with("<!--") && trimmed.ends_with("-->") {
                    if let Some(val) = trimmed.strip_prefix("<!-- KOALAVAULT_ORIG_LICENSE:") {
                        let v = val.trim().trim_end_matches("-->").trim().to_string();
                        orig_license = Some(v);
                        continue;
                    }
                    if let Some(val) = trimmed.strip_prefix("<!-- KOALAVAULT_ORIG_LICENSE_LINK:") {
                        let v = val.trim().trim_end_matches("-->").trim().to_string();
                        orig_link = Some(v);
                        continue;
                    }
                    // Other comment at top, skip
                    continue;
                } else {
                    at_start = false;
                    new_body.push_str(line);
                    new_body.push('\n');
                }
            }
            body = new_body;
        }

        // Rebuild header with restored values
        let mut lines: Vec<&str> = header.lines().collect();
        if !lines.is_empty() && lines[0].trim() == "---" {
            lines.remove(0);
        }
        if !lines.is_empty() && lines[lines.len() - 1].trim() == "---" {
            lines.pop();
        }

        let mut new_header_lines: Vec<String> = Vec::new();
        new_header_lines.push(String::from("---"));

        let mut wrote_license = false;
        let mut wrote_link = false;

        for l in &lines {
            let s = l.trim_start();
            if s.starts_with("license:") {
                wrote_license = true;
                if let Some(orig) = &orig_license {
                    if orig == "__NONE__" {
                        // skip to remove
                        continue;
                    } else {
                        new_header_lines.push(format!("license: {}", orig));
                    }
                } else {
                    // keep as-is
                    new_header_lines.push(l.to_string());
                }
            } else if s.starts_with("license_link:") {
                wrote_link = true;
                if let Some(orig) = &orig_link {
                    if orig == "__NONE__" {
                        continue; // remove
                    } else {
                        new_header_lines.push(format!("license_link: {}", orig));
                    }
                } else {
                    new_header_lines.push(l.to_string());
                }
            } else {
                new_header_lines.push(l.to_string());
            }
        }

        // If fields were not present in header but orig values exist, add them (only if not __NONE__)
        if !wrote_license {
            if let Some(orig) = orig_license {
                if orig != "__NONE__" {
                    new_header_lines.push(format!("license: {}", orig));
                }
            }
        }
        if !wrote_link {
            if let Some(orig) = orig_link {
                if orig != "__NONE__" {
                    new_header_lines.push(format!("license_link: {}", orig));
                }
            }
        }

        new_header_lines.push(String::from("---"));

        let mut new_content = new_header_lines.join("\n");
        if !new_content.ends_with('\n') {
            new_content.push('\n');
        }
        new_content.push_str(&body);
        new_content
    }
}
