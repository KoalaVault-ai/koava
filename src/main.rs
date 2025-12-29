use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

mod cli;
mod config;
mod encrypt;
mod error;
mod templates;
mod ui;
mod upload;
mod version;

mod auth;
mod client;
mod file;
mod key;
mod model;
mod store;
mod utils;

use cli::CliHandler;
use version::CURRENT_VERSION;

#[derive(Parser)]
#[command(
    name = "koava",
    about = "KoalaVault model converter tool for producers",
    long_about = "KoalaVault Converter - Secure model encryption and management tool

OVERVIEW:
  This tool helps you encrypt Hugging Face safetensors models and manage them on the 
  KoalaVault platform.

WORKFLOW:
  1. Login with your API key
  2. Create, encrypt and push your model
  3. Manage your models (list, remove, restore)

QUICK START:
  koava login                           # Authenticate with your API key
  koava push <MODEL_PATH>               # Complete workflow: create + encrypt + upload
  koava list <MODEL_NAME>               # List files for your model
  koava remove <MODEL_NAME>             # Delete model from server
  koava restore <MODEL_PATH>            # Restore from local backup
  koava status                          # Check authentication and server status",
    version = CURRENT_VERSION,
    author = "KoalaVault Team",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt safetensors files to cryptotensors format
    #[command(aliases = &["enc"])]
    Encrypt(EncryptArgs),

    /// Upload model to KoalaVault
    Upload(UploadArgs),

    /// List files for a model
    #[command(aliases = &["ls"])]
    List(ListArgs),

    /// Restore original files from backup
    Restore(RestoreArgs),

    /// Delete model files from server
    #[command(aliases = &["rm"])]
    Remove(RemoveArgs),

    /// Show authentication status
    #[command(aliases = &["st"])]
    Status,

    /// Configure settings
    #[command(aliases = &["cfg"])]
    Config(ConfigArgs),

    /// Login with API key
    Login(LoginArgs),

    /// Logout
    Logout,

    /// Create a new model
    Create(CreateArgs),

    /// Push model: create + encrypt + upload
    Push(PushArgs),
}

#[derive(Args)]
pub struct EncryptArgs {
    pub model_path: PathBuf,

    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,

    #[arg(short, long)]
    pub output: Option<PathBuf>,

    #[arg(long)]
    pub no_backup: bool,

    #[arg(long)]
    pub files: Option<String>,

    #[arg(long)]
    pub exclude: Option<String>,

    #[arg(long)]
    pub dry_run: bool,

    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct UploadArgs {
    pub model_path: PathBuf,

    #[arg(short, long)]
    pub name: Option<String>,

    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args)]
pub struct ListArgs {
    pub model_identifier: String,
}

#[derive(Args)]
pub struct RestoreArgs {
    pub model_path: PathBuf,

    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args)]
pub struct RemoveArgs {
    pub model_identifier: String,

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
    Show,
    #[cfg(debug_assertions)]
    SetEndpoint { url: String },
    SetTimeout { seconds: u64 },
    SetVerbose { enabled: String },
    Reset,
    SetHuggingfaceCli { path: String },
}

#[derive(Args)]
pub struct LoginArgs {
    #[cfg(debug_assertions)]
    pub api_key: String,

    #[cfg(not(debug_assertions))]
    #[arg(skip)]
    pub api_key: Option<String>,
}

#[derive(Args)]
pub struct CreateArgs {
    pub name: String,

    #[arg(short, long)]
    pub description: Option<String>,
}

#[derive(Args)]
pub struct PushArgs {
    pub model_path: PathBuf,

    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,

    #[arg(short, long)]
    pub description: Option<String>,

    #[arg(long)]
    pub force: bool,

    #[arg(long)]
    pub public: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let log_level = if cli.verbose { "debug" } else { "info" };
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(format!("koava={}", log_level));
    subscriber.init();

    let mut handler = match CliHandler::new(None).await {
        Ok(handler) => handler,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = handler.execute(cli.command).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

