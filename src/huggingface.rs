//! HuggingFace CLI integration module

use crate::config::Config;
use crate::error::Result;
use std::path::PathBuf;

/// Status of Hugging Face CLI
#[derive(Debug, Clone)]
pub enum HuggingFaceCliStatus {
    /// CLI not found or not executable
    NotFound,
    /// CLI found but user not logged in
    NotLoggedIn,
    /// CLI found and user logged in with username
    LoggedIn(String),
}

/// Auto-detect Hugging Face CLI executable path
pub async fn detect_huggingface_cli(config: &mut Config) -> Result<Option<PathBuf>> {
    // If already configured, return the configured path
    if let Some(ref path) = config.huggingface_cli_path {
        if path.exists() {
            return Ok(Some(path.clone()));
        }
    }

    // Try to find hf command in PATH
    let possible_names = if cfg!(target_os = "windows") {
        vec!["hf.exe", "hf"]
    } else {
        vec!["hf"]
    };

    for name in possible_names {
        if let Ok(path) = which::which(name) {
            config.huggingface_cli_path = Some(path.clone());
            config.save(&crate::config::default_config_path()).await?;
            return Ok(Some(path));
        }
    }

    Ok(None)
}

/// Check if Hugging Face CLI is available and logged in
pub async fn check_huggingface_cli_status(config: &Config) -> Result<HuggingFaceCliStatus> {
    let cli_path = match &config.huggingface_cli_path {
        Some(path) if path.exists() => path.clone(),
        _ => return Ok(HuggingFaceCliStatus::NotFound),
    };

    if !cli_path.is_file() {
        return Ok(HuggingFaceCliStatus::NotFound);
    }

    let output = tokio::process::Command::new(&cli_path)
        .arg("auth")
        .arg("whoami")
        .output()
        .await;

    match output {
        Ok(result) if result.status.success() => {
            let stdout = String::from_utf8_lossy(&result.stdout).to_string();
            let stderr = String::from_utf8_lossy(&result.stderr).to_string();
            let merged = if !stdout.trim().is_empty() {
                stdout
            } else {
                stderr
            };
            let merged_lower = merged.to_lowercase();

            if merged_lower.contains("not logged in") || merged_lower.contains("not authenticated")
            {
                return Ok(HuggingFaceCliStatus::NotLoggedIn);
            }

            if let Some(username) = parse_hf_whoami_username(&merged) {
                Ok(HuggingFaceCliStatus::LoggedIn(username))
            } else {
                let trimmed = merged.trim();
                if !trimmed.is_empty() && trimmed.len() < 100 {
                    Ok(HuggingFaceCliStatus::LoggedIn(trimmed.to_string()))
                } else {
                    Ok(HuggingFaceCliStatus::NotLoggedIn)
                }
            }
        }
        Ok(_) => Ok(HuggingFaceCliStatus::NotLoggedIn),
        Err(_) => Ok(HuggingFaceCliStatus::NotFound),
    }
}

/// Parse username from various `hf auth whoami` outputs
fn parse_hf_whoami_username(raw: &str) -> Option<String> {
    let cleaned = console::strip_ansi_codes(raw);
    let normalized = cleaned.replace('\r', "");
    let first_line = normalized
        .lines()
        .find(|l| !l.trim().is_empty())?
        .trim()
        .to_string();

    let lower = first_line.to_lowercase();
    if lower.contains("not logged in") {
        return None;
    }

    let mut candidate = first_line.clone();
    if let Some(pos) = lower.find("logged in as") {
        let after = &first_line[pos + "logged in as".len()..];
        candidate = after.trim().to_string();
    }
    if candidate.contains(':') {
        if let Some(idx) = candidate.rfind(':') {
            candidate = candidate[idx + 1..].trim().to_string();
        }
    }

    candidate = candidate.trim_matches('"').trim().to_string();

    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.';
    let mut extracted = String::new();
    for ch in candidate.chars() {
        if allowed(ch) {
            extracted.push(ch);
        } else if !extracted.is_empty() {
            break;
        }
    }

    if extracted.is_empty() {
        None
    } else {
        Some(extracted)
    }
}
