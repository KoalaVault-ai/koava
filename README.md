# Koava - KoalaVault Model Converter

Koava is the official CLI tool for encrypting and managing AI models on the [KoalaVault](https://www.koalavault.ai) platform.

## Features

- 🔐 **Encrypt Models**: Convert safetensors files to encrypted CryptoTensors format
- ☁️ **Upload to KoalaVault**: Push encrypted models to the KoalaVault platform
- 🤗 **Hugging Face Integration**: Automatically create and push to HF repositories
- 🔄 **Backup & Restore**: Automatic backup before encryption with restore capability

## Installation

```bash
# Build from source
cargo build --release

# Or install via pip (when published)
pip install koava
```

## Quick Start

```bash
# 1. Login with your API key
koava login

# 2. Push your model (create + encrypt + upload + HF push)
koava push ./my-model

# 3. Check status
koava status
```

## Commands

| Command | Description |
|---------|-------------|
| `login` | Authenticate with KoalaVault |
| `push` | Complete workflow: create + encrypt + upload |
| `encrypt` | Encrypt safetensors files |
| `upload` | Upload encrypted model |
| `create` | Create model on server |
| `list` | List model files |
| `remove` | Delete model files |
| `restore` | Restore from backup |
| `status` | Show authentication status |
| `config` | Configure settings |
| `logout` | Clear credentials |

## Examples

### Encrypt a Model

```bash
# Encrypt in-place (creates automatic backup)
koava encrypt ./my-model

# Encrypt to a different directory
koava encrypt ./my-model --output ./encrypted-model

# Dry run (preview what would be done)
koava encrypt ./my-model --dry-run
```

### Complete Push Workflow

```bash
# Push with default settings
koava push ./my-model

# Push with custom name and description
koava push ./my-model --name my-model-v2 --description "Updated version"

# Create public HF repository
koava push ./my-model --public
```

### Manage Models

```bash
# List files for a model
koava list my-model

# Remove model files from server
koava remove my-model

# Restore from backup
koava restore ./my-model
```

## Configuration

Configuration is stored in `~/.config/koalavault/config.json`.

```bash
# Show current config
koava config show

# Set timeout
koava config set-timeout 60

# Configure HF CLI path
koava config set-huggingface-cli auto
```

### Custom Configuration File

You can specify a custom configuration file path using the global `--config` or `-c` flag. This is useful for managing multiple configuration profiles.

```bash
# Use a custom config file for a specific command
koava -c ./my-custom-config.json config show

# All commands support this flag
koava --config /path/to/config.json status
```

## Requirements

- Rust 1.80+ (for building)
- Python 3.8+ (for pip installation)
- Hugging Face CLI (`hf`) for push functionality

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) file for details.

## Links

- [KoalaVault Website](https://www.koalavault.ai)
- [Documentation](https://docs.koalavault.ai)
- [Support](mailto:koalavaultx@gmail.com)

