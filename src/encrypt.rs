//! Encryption service for koava

use dialoguer::{theme::ColorfulTheme, Confirm};
use std::path::{Path, PathBuf};
use tokio::fs;

use cryptotensors::policy::AccessPolicy;

use crate::config::ConverterConfig;
use crate::error::{ConverterError, Result};
use crate::model::{encrypt_safetensors_file, ModelDirectory, ModelFile};
use crate::client::HttpClient;
use crate::key::KeyService;
use crate::ui::{create_progress_bar, UI};
use crate::{EncryptArgs, RestoreArgs};

/// Backup status
#[derive(Debug, Clone)]
enum BackupStatus {
    NotExists,
    ValidUnencrypted(Vec<ModelFile>),
    Invalid,
}

/// Input file status
#[derive(Debug, Clone)]
enum InputFileStatus {
    NoFiles,
    Encrypted,
    AllUnencrypted(Vec<ModelFile>),
}

/// Output status
#[derive(Debug, PartialEq, Clone)]
enum OutputStatus {
    InPlace,
    Different,
    NotExists,
    HasFiles,
}

/// Action types
#[derive(Debug, Clone, PartialEq)]
enum Action {
    Copy,
    Encrypt,
    Move,
}

/// Operation in the plan
#[derive(Debug, Clone)]
struct Operation {
    action: Action,
    input: PathBuf,
    output: PathBuf,
    file_info: Option<ModelFile>,
}

/// Encryption keys
#[derive(Debug, Clone)]
struct EncryptionKeys {
    user_sign_key: serde_json::Value,
    master_key: serde_json::Value,
}

/// Encryption plan
#[derive(Debug, Clone)]
struct EncryptionPlan {
    backup: Vec<Operation>,
    main: Vec<Operation>,
}

pub struct EncryptService {
    ui: UI,
    config: ConverterConfig,
}

impl EncryptService {
    pub fn new(config: ConverterConfig) -> Self {
        Self {
            ui: UI::new(),
            config,
        }
    }

    pub async fn encrypt(&self, args: EncryptArgs) -> Result<()> {
        self.ui.info(&format!("Scanning: {}", args.model_path.display()));

        let model = ModelDirectory::from_path(&args.model_path).await?;

        let backup_dir = args.model_path.join(".backup");
        let backup_status = self.check_backup_status(&backup_dir).await?;

        if matches!(backup_status, BackupStatus::Invalid) {
            return Err(ConverterError::validation("Backup directory is invalid"));
        }

        let input_status = self.check_input_file_status(&model).await?;
        let output_status = self.check_output_status(&args).await?;

        let plan = self
            .generate_encrypt_plan(&model, &args, backup_status, input_status, output_status)
            .await?;

        let total_operations = plan.backup.len() + plan.main.len();

        if total_operations == 0 {
            self.ui.warning("No operations to perform");
            return Ok(());
        }

        self.display_encryption_plan(&plan.backup, &plan.main);

        if args.dry_run {
            return Ok(());
        }

        self.ui.info("Retrieving encryption keys...");
        let keys = self.get_encryption_keys(&args).await?;

        if let Err(e) = self.execute_encryption_plan(&plan, &args, &keys).await {
            self.ui.error(&format!("Encryption failed: {}", e));

            let is_in_place = args.output.is_none() || args.output.as_ref() == Some(&args.model_path);
            if is_in_place {
                self.ui.info("Tip: Use 'restore' to recover from backup");
            }

            return Err(e);
        }

        if let Some(output_dir) = &args.output {
            if output_dir != &args.model_path {
                self.ui.info("Copying auxiliary files...");
                self.copy_auxiliary_files(&args.model_path, output_dir).await?;
            }
        }

        self.handle_readme_and_license(&args).await?;
        self.ui.success("Encryption completed!");

        Ok(())
    }

    fn infer_model_name(&self, args: &EncryptArgs) -> Result<String> {
        use std::path::Component;

        let basename_from = |p: &Path| -> Option<String> {
            p.components().rev().find_map(|c| match c {
                Component::Normal(s) => s.to_str().map(|s| s.to_string()),
                _ => None,
            })
        };

        if let Some(name) = &args.name {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(ConverterError::Validation("Model name cannot be empty".to_string()));
            }
            return Ok(trimmed.to_string());
        }

        if let Some(output_dir) = &args.output {
            if let Some(base) = basename_from(output_dir).filter(|s| !s.trim().is_empty()) {
                return Ok(base);
            } else {
                return Err(ConverterError::Validation(
                    "Failed to derive model name from --output".to_string(),
                ));
            }
        }

        let canonical_path = args
            .model_path
            .canonicalize()
            .map_err(|e| ConverterError::Validation(format!("Failed to canonicalize: {}", e)))?;
        if let Some(dir_name) = basename_from(&canonical_path) {
            return Ok(dir_name);
        }

        Err(ConverterError::Validation(
            "Failed to derive model name".to_string(),
        ))
    }

    async fn execute_encryption_plan(
        &self,
        plan: &EncryptionPlan,
        args: &EncryptArgs,
        keys: &EncryptionKeys,
    ) -> Result<()> {
        if !plan.backup.is_empty() {
            let backup_dir = args.model_path.join(".backup");
            self.ui.info("Creating backup...");
            fs::create_dir_all(&backup_dir).await?;
        }

        if let Some(output_dir) = &args.output {
            if output_dir != &args.model_path {
                self.ui.info("Creating output directory...");
                fs::create_dir_all(output_dir).await?;
            }
        }

        let total_operations = plan.backup.len() + plan.main.len();
        let progress_bar = create_progress_bar(total_operations as u64, "Processing...");

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

            if let Err(e) = self.execute_operation(operation, keys).await {
                progress_bar.finish_with_message("Failed");
                self.ui.error(&format!("Backup operation {} failed: {}", i + 1, e));
                return Err(e);
            }

            progress_bar.inc(1);
        }

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

            if let Err(e) = self.execute_operation(operation, keys).await {
                progress_bar.finish_with_message("Failed");
                self.ui.error(&format!("Main operation {} failed: {}", i + 1, e));
                return Err(e);
            }

            progress_bar.inc(1);
        }

        progress_bar.finish_with_message("Completed");
        Ok(())
    }

    async fn execute_operation(&self, operation: &Operation, keys: &EncryptionKeys) -> Result<()> {
        match operation.action {
            Action::Move => {
                if let Some(parent) = operation.output.parent() {
                    fs::create_dir_all(parent).await?;
                }
                fs::rename(&operation.input, &operation.output).await?;
            }
            Action::Copy => {
                if let Some(parent) = operation.output.parent() {
                    fs::create_dir_all(parent).await?;
                }
                fs::copy(&operation.input, &operation.output).await?;
            }
            Action::Encrypt => {
                if let Some(parent) = operation.output.parent() {
                    fs::create_dir_all(parent).await?;
                }

                let policy = AccessPolicy::new(None, None);
                encrypt_safetensors_file(
                    &operation.input,
                    &operation.output,
                    &keys.master_key,
                    &keys.user_sign_key,
                    &policy,
                )
                .await?;
            }
        }
        Ok(())
    }

    pub async fn restore(&self, args: RestoreArgs) -> Result<()> {
        let backup_dir = args.model_path.join(".backup");

        let backup_status = self.check_backup_status(&backup_dir).await?;

        match backup_status {
            BackupStatus::NotExists => {
                return Err(ConverterError::validation("No backup found"));
            }
            BackupStatus::Invalid => {
                return Err(ConverterError::validation("Backup is invalid"));
            }
            BackupStatus::ValidUnencrypted(backup_files) => {
                self.ui.info(&format!("Found {} files in backup", backup_files.len()));

                self.ui.info("Removing model files...");
                self.delete_model_files(&args.model_path).await?;

                self.ui.info("Restoring from backup...");
                for backup_file in &backup_files {
                    let target_path = args.model_path.join(&backup_file.name);
                    fs::rename(&backup_file.path, &target_path).await?;
                    self.ui.info(&format!("Restored: {}", backup_file.name));
                }

                self.restore_readme_and_license(&args.model_path, &backup_dir).await?;
                self.ui.success("Restore completed!");
                Ok(())
            }
        }
    }

    async fn check_backup_status(&self, backup_dir: &Path) -> Result<BackupStatus> {
        if !backup_dir.exists() {
            return Ok(BackupStatus::NotExists);
        }

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

        match ModelDirectory::from_path(backup_dir).await {
            Ok(backup_model) => {
                if !backup_model.encrypted_files.is_empty() {
                    return Ok(BackupStatus::Invalid);
                }

                let total_files = backup_model.all_files.len();
                let safetensors_files =
                    backup_model.unencrypted_files.len() + backup_model.encrypted_files.len();

                if total_files != safetensors_files {
                    return Ok(BackupStatus::Invalid);
                }

                Ok(BackupStatus::ValidUnencrypted(
                    backup_model.unencrypted_files.clone(),
                ))
            }
            Err(_) => Ok(BackupStatus::Invalid),
        }
    }

    async fn check_input_file_status(&self, model: &ModelDirectory) -> Result<InputFileStatus> {
        let unencrypted_files = model.get_unencrypted_files();
        let encrypted_files = model.get_encrypted_files();

        let total_files = unencrypted_files.len() + encrypted_files.len();

        if total_files == 0 {
            return Ok(InputFileStatus::NoFiles);
        }

        if encrypted_files.is_empty() {
            Ok(InputFileStatus::AllUnencrypted(unencrypted_files.to_vec()))
        } else {
            Ok(InputFileStatus::Encrypted)
        }
    }

    async fn check_output_status(&self, args: &EncryptArgs) -> Result<OutputStatus> {
        let output_dir = args.output.as_ref().unwrap_or(&args.model_path);

        if output_dir == &args.model_path {
            return Ok(OutputStatus::InPlace);
        }

        if !output_dir.exists() {
            return Ok(OutputStatus::NotExists);
        }

        let mut entries = fs::read_dir(output_dir).await?;
        let mut has_files = false;

        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_file() {
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

    async fn generate_encrypt_plan(
        &self,
        model: &ModelDirectory,
        args: &EncryptArgs,
        backup_status: BackupStatus,
        input_status: InputFileStatus,
        output_status: OutputStatus,
    ) -> Result<EncryptionPlan> {
        let source_result = self
            .get_source_files(model, args, &backup_status, &input_status, &output_status)
            .await?;
        if source_result.is_none() {
            return Ok(EncryptionPlan {
                backup: vec![],
                main: vec![],
            });
        }

        let (source_files, is_in_backup) = source_result.unwrap();
        let is_in_place = matches!(output_status, OutputStatus::InPlace);

        let mut backup_operations = Vec::new();
        let mut main_operations = Vec::new();

        if is_in_place {
            let backup_dir = args.model_path.join(".backup");

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

            main_operations = source_files
                .iter()
                .map(|file| {
                    let input_path = backup_dir.join(&file.name);

                    if self.is_excluded(&file.name, args) {
                        Operation {
                            action: Action::Copy,
                            input: input_path,
                            output: file.path.clone(),
                            file_info: Some(file.clone()),
                        }
                    } else {
                        let output_name = file.name.clone();
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
            let output_dir = args.output.as_ref().unwrap_or(&args.model_path);

            main_operations = source_files
                .iter()
                .map(|file| {
                    let output_name = file.name.clone();
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

    async fn get_source_files(
        &self,
        model: &ModelDirectory,
        args: &EncryptArgs,
        backup_status: &BackupStatus,
        input_status: &InputFileStatus,
        output_status: &OutputStatus,
    ) -> Result<Option<(Vec<ModelFile>, bool)>> {
        let is_in_place = matches!(output_status, OutputStatus::InPlace);

        match input_status {
            InputFileStatus::AllUnencrypted(source_files) => {
                if is_in_place {
                    if let BackupStatus::ValidUnencrypted(_) = backup_status {
                        if args.force {
                            self.ui.info("Overwriting existing backup");
                            Ok(Some((source_files.clone(), false)))
                        } else {
                            self.ui.info("Using existing backup");
                            Ok(Some((source_files.clone(), true)))
                        }
                    } else {
                        Ok(Some((source_files.clone(), false)))
                    }
                } else {
                    Ok(Some((source_files.clone(), false)))
                }
            }
            InputFileStatus::NoFiles | InputFileStatus::Encrypted => {
                if is_in_place {
                    self.handle_backup_dependent_cases(args, backup_status, input_status)
                        .await
                } else {
                    if let BackupStatus::ValidUnencrypted(source_files) = backup_status {
                        self.ui.info("Using backup files");
                        Ok(Some((source_files.clone(), true)))
                    } else {
                        self.ui.error("No valid backup available");
                        Ok(None)
                    }
                }
            }
        }
    }

    async fn handle_backup_dependent_cases(
        &self,
        args: &EncryptArgs,
        backup_status: &BackupStatus,
        input_status: &InputFileStatus,
    ) -> Result<Option<(Vec<ModelFile>, bool)>> {
        self.ui
            .warning("Input contains encrypted files, checking backup...");

        if let BackupStatus::ValidUnencrypted(source_files) = backup_status {
            if args.force {
                self.ui.warning("--force has no effect here");
            }

            if matches!(input_status, InputFileStatus::Encrypted) {
                let proceed = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Re-encrypt from backup?")
                    .default(false)
                    .interact()?;

                if !proceed {
                    self.ui.info("Cancelled");
                    return Ok(None);
                }
            }
            Ok(Some((source_files.clone(), true)))
        } else {
            self.ui.error("No valid backup available");
            Ok(None)
        }
    }

    fn is_excluded(&self, file_name: &str, args: &EncryptArgs) -> bool {
        if let Some(exclude_list) = &args.exclude {
            let excluded_files: Vec<&str> = exclude_list.split(',').map(|s| s.trim()).collect();
            excluded_files.contains(&file_name)
        } else {
            false
        }
    }

    fn display_encryption_plan(&self, backup_operations: &[Operation], main_operations: &[Operation]) {
        self.ui.info("Encryption Plan:");

        let total = backup_operations.len() + main_operations.len();
        self.ui.info(&format!("Total operations: {}", total));

        if !backup_operations.is_empty() {
            self.ui.info("Backup operations:");
            for op in backup_operations {
                if let Some(file) = &op.file_info {
                    self.ui.info(&format!("  - Move {} to backup", file.name));
                }
            }
        }

        if !main_operations.is_empty() {
            self.ui.info("Main operations:");
            for op in main_operations {
                if let Some(file) = &op.file_info {
                    match op.action {
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

    async fn copy_auxiliary_files(&self, input_dir: &Path, output_dir: &Path) -> Result<()> {
        use walkdir::WalkDir;

        for entry in WalkDir::new(input_dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let file_path = entry.path();

                if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                    let ext_lower = ext.to_lowercase();
                    if ext_lower == "safetensors" || ext_lower == "cryptotensors" {
                        continue;
                    }
                }

                let path_str = file_path.to_string_lossy();
                if path_str.contains("/.") {
                    continue;
                }

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

    async fn get_encryption_keys(&self, args: &EncryptArgs) -> Result<EncryptionKeys> {
        let sdk_config = self.config.to_sdk_config();
        let client = HttpClient::new(sdk_config)?;

        if !client.is_authenticated() {
            return Err(ConverterError::Authentication(
                "Authentication required. Run 'koava login' first.".to_string(),
            ));
        }

        let key_service = KeyService::new(&client);

        let sign_key_jwk = key_service
            .request_sign_key()
            .await
            .map_err(|e| e)?;

        let model_name = self.infer_model_name(args)?;
        let enc_key_jwk = key_service
            .request_master_key(&model_name)
            .await
            .map_err(|e| e)?;

        Ok(EncryptionKeys {
            user_sign_key: sign_key_jwk,
            master_key: enc_key_jwk,
        })
    }

    async fn delete_model_files(&self, model_path: &Path) -> Result<()> {
        let mut entries = fs::read_dir(model_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_type = entry.file_type().await?;

            if file_type.is_file() {
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

    async fn handle_readme_and_license(&self, args: &EncryptArgs) -> Result<()> {
        let model_name = self.infer_model_name(args)?;

        let target_dir = if let Some(output_dir) = &args.output {
            output_dir
        } else {
            &args.model_path
        };

        self.handle_readme_file(target_dir, &model_name).await?;
        self.handle_license_file(target_dir).await?;

        Ok(())
    }

    async fn handle_readme_file(&self, target_dir: &Path, model_name: &str) -> Result<()> {
        let target_readme_path = target_dir.join("README.md");
        let compliance_block = crate::templates::README_TEMPLATE;

        if target_readme_path.exists() {
            let existing_content = fs::read_to_string(&target_readme_path).await?;
            if existing_content.contains("<!-- KOALAVAULT_ENCRYPTED_MODEL_START -->") {
                self.ui.info("README already has encryption notice");
                return Ok(());
            }
            let new_content = self.insert_block_after_first_heading(&existing_content, compliance_block);
            fs::write(&target_readme_path, new_content).await?;
            self.ui.info("Updated README.md");
        } else {
            let mut new_readme = String::new();
            new_readme.push_str(&format!("# {}\n\n", model_name));
            new_readme.push_str(compliance_block);
            new_readme.push('\n');
            fs::write(&target_readme_path, new_readme).await?;
            self.ui.info("Created README.md");
        }

        Ok(())
    }

    async fn handle_license_file(&self, model_path: &Path) -> Result<()> {
        let kv_license_path = model_path.join("LICENSE.KOALAVAULT");

        if kv_license_path.exists() {
            let existing = fs::read_to_string(&kv_license_path)
                .await
                .unwrap_or_default();
            if existing.contains("KoalaVault Proprietary License") {
                self.ui.info("KoalaVault license already present");
                return Ok(());
            }
        }

        fs::write(&kv_license_path, crate::templates::LICENSE_TEMPLATE).await?;
        self.ui.info(&format!("Created: {}", kv_license_path.display()));

        Ok(())
    }

    async fn restore_readme_and_license(&self, model_path: &Path, backup_dir: &Path) -> Result<()> {
        let target_readme = model_path.join("README.md");
        if target_readme.exists() {
            if let Ok(current) = fs::read_to_string(&target_readme).await {
                let without_block = self.remove_compliance_block(&current);
                if without_block != current {
                    fs::write(&target_readme, without_block).await?;
                    self.ui.info("Reverted README.md");
                }
            }
        }

        let kv_license_path = model_path.join("LICENSE.KOALAVAULT");
        if kv_license_path.exists() {
            let _ = fs::remove_file(&kv_license_path).await;
            self.ui.info(&format!("Removed: {}", kv_license_path.display()));
        }

        Ok(())
    }

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
}

