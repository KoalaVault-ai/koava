use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

mod auth;
mod cli;
mod client;
mod config;
mod encrypt;
mod error;
mod file;
mod huggingface;
mod key;
mod model;
mod policy;
mod push;
mod security;
mod store;
mod templates;
mod ui;
mod upload;
mod utils;

#[cfg(test)]
mod tests;
/// Current version of the KoalaVault tool (from Cargo.toml)
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub use client::{ApiResponse, BaseClient, HttpClient, TokenResponse};
pub use config::Config;
pub use error::{KoavaError, Result};
pub use file::{EncryptionConfig, ModelFileService, ModelMetadata};
pub use koalavault_protocol::api::{
    GetModelFileResponse, ModelFilesListResponse, UploadModelFilesRequest,
    UploadModelFilesResponse,
};
pub use key::{KeyService, KeyVault};
pub use model::{encrypt_safetensors_file, format_bytes, ModelDirectory, ModelFile};
pub use store::{StoredToken, TokenStore, TokenStoreConfig};
pub use utils::{CryptoUtils, FileHash, FileHeader, FileInfo};

use cli::CliHandler;

#[derive(Parser)]
#[command(
    name = "koava",
    about = "KoalaVault model converter tool for producers",
    long_about = "KoalaVault Converter - Secure model encryption and management tool

OVERVIEW:
  This tool helps you encrypt Hugging Face safetensors models and manage them on the 
  KoalaVault platform. It provides secure encryption, backup, and cloud storage 
  capabilities for your AI models.

WORKFLOW:
  1. Login with your API key
  2. Create, encrypt and push your model (all-in-one with 'push')
  3. Manage your models (list, remove, restore)

QUICK START:
  koava login <API_KEY>                      # Authenticate with your API key
  koava config setup                        # Configure storage directory and other settings
  koava push <MODEL_PATH>                   # Complete workflow: create + encrypt + upload
  koava list <MODEL_NAME>                   # List files for your model
  koava remove <MODEL_NAME>                 # Delete model from server
  koava restore <MODEL_PATH>                # Restore from local backup
  koava status                              # Check authentication and server status

ADVANCED WORKFLOW (step-by-step):
  koava create <MODEL_NAME> [--description] # Create a new model on the server
  koava encrypt <MODEL_PATH>                # Encrypt model files (auto-backup)
  koava upload <MODEL_PATH>                 # Upload encrypted model to server

COMMANDS:
  login      Authenticate with your KoalaVault API key
  logout     Clear stored authentication credentials
  status     Show authentication status and server connection
  config     Configure storage directory and other settings
  push       Complete workflow: create model, encrypt, and upload to server
  create     Create a new model on the KoalaVault server
  encrypt    Convert safetensors to encrypted KoalaVault format
  upload     Upload encrypted model to KoalaVault server
  list       List files for a model on the server
  remove     Delete model files from the server
  restore    Restore original files from local backup

For more information, visit: https://docs.koalavault.ai/koava",
    version = CURRENT_VERSION,
    author = "KoalaVault Team",
    arg_required_else_help = true
)]
pub struct Cli {
    /// Path to custom configuration file
    #[arg(short, long, global = true, help = "Path to custom configuration file")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    // ── Authentication ──────────────────────────────────────────────────────────
    /// Authenticate with your KoalaVault API key
    Login(LoginArgs),

    /// Clear stored authentication credentials and logout from KoalaVault
    Logout,

    /// Show authentication status and KoalaVault connection
    #[command(aliases = &["st"])]
    Status,

    // ── Core Workflow ───────────────────────────────────────────────────────────
    /// Push model: create model, encrypt, then push to KoalaVault and Hugging Face
    Push(PushArgs),

    /// Create a new model on KoalaVault
    Create(CreateArgs),

    /// Encrypt safetensors files to cryptotensors format (creates automatic backup)
    #[command(aliases = &["enc"])]
    Encrypt(EncryptArgs),

    /// Upload model to KoalaVault
    Upload(UploadArgs),

    // ── Model Management ────────────────────────────────────────────────────────
    /// List files for a model stored on KoalaVault
    #[command(aliases = &["ls"])]
    List(ListArgs),

    /// Delete model files from KoalaVault
    #[command(aliases = &["rm"])]
    Remove(RemoveArgs),

    /// Restore original files from local backup
    Restore(RestoreArgs),

    // ── Configuration ───────────────────────────────────────────────────────────
    /// Configure storage directory, timeout, and other settings
    #[command(aliases = &["cfg"])]
    Config(ConfigArgs),
}

#[derive(Args)]
pub struct EncryptArgs {
    /// Path to the model directory containing safetensors files
    pub model_path: PathBuf,

    /// Model name for encryption key (defaults to directory name)
    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,

    /// Output directory for encrypted files (default: encrypt in-place)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Skip automatic backup creation (NOT recommended - original files will be lost)
    #[arg(long)]
    pub no_backup: bool,

    /// Only encrypt specific files (comma-separated list)
    #[arg(long)]
    pub files: Option<String>,

    /// Exclude specific files from encryption (comma-separated list)
    #[arg(long)]
    pub exclude: Option<String>,

    /// Preview what would be encrypted without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Force encryption even if backup directory exists (overwrites existing backup)
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct UploadArgs {
    /// Path to the encrypted model directory
    pub model_path: PathBuf,

    /// Custom name for the model on server (default: directory name)
    #[arg(short, long)]
    pub name: Option<String>,

    /// Overwrite existing model on server without confirmation
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args)]
pub struct ListArgs {
    /// Model identifier: 'username/modelname' or 'modelname' (default: current user)
    pub model_identifier: String,
}

#[derive(Args)]
pub struct RestoreArgs {
    /// Path to the model directory to restore from backup
    pub model_path: PathBuf,

    /// Restore without confirmation prompt
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Model identifier: 'username/modelname' or 'modelname' (default: current user)
    pub model_identifier: String,

    /// Delete without confirmation prompt
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Show current configuration settings
    Show,
    /// Set KoalaVault endpoint URL
    #[cfg(debug_assertions)]
    SetEndpoint {
        /// KoalaVault endpoint URL (e.g., https://api.example.com)
        url: String,
    },
    /// Set request timeout in seconds
    SetTimeout {
        /// Timeout in seconds (default: 30)
        seconds: u64,
    },
    /// Reset all configuration to default values
    Reset,

    /// Set Hugging Face CLI executable path
    SetHuggingfaceCli {
        /// Path to hf executable (use 'auto' to auto-detect)
        path: String,
    },
}

#[derive(Args)]
pub struct LoginArgs {
    /// Your KoalaVault API key (get it from your dashboard)
    #[cfg(debug_assertions)]
    pub api_key: String,

    #[cfg(not(debug_assertions))]
    #[arg(skip)]
    pub api_key: Option<String>,
}

#[derive(Args)]
pub struct CreateArgs {
    /// Model name (required)
    pub name: String,

    /// Optional model description
    #[arg(short, long)]
    pub description: Option<String>,
}

#[derive(Args)]
pub struct PushArgs {
    /// Path to the model directory containing safetensors files
    ///
    /// This command performs a complete workflow:
    ///   1. Create model on KoalaVault server (if not exists)
    ///   2. Encrypt safetensors files with automatic backup
    ///   3. Upload encrypted files to KoalaVault
    ///   4. Push encrypted files to Hugging Face Hub
    ///
    /// Requires: Authenticated to both KoalaVault and Hugging Face CLI
    pub model_path: PathBuf,

    /// Model name to create on KoalaVault and HuggingFace (defaults to directory name)
    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,

    /// Model description shown on KoalaVault server
    #[arg(short, long)]
    pub description: Option<String>,

    /// Force overwrite: skip confirmations for backup and remote files
    #[arg(long)]
    pub force: bool,

    /// Create public Hugging Face repository (default: private)
    #[arg(long)]
    pub public: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Create CLI handler and execute command
    let mut handler = CliHandler::with_config_path(cli.config);

    if let Err(e) = handler.execute(cli.command).await {
        // Display error message if not already shown
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
