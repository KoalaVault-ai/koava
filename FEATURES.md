# koava CLI Features

## Available Features

### `client` (enabled by default)
- **Purpose**: KoalaVault API integration
- **What it provides**:
  - Model file encryption and conversion
  - Model upload to KoalaVault servers
  - Authentication with KoalaVault API
- **Can be disabled**: No, tool won't be functional without it

### `cert-pinning` (optional, enabled in production builds)
- **Purpose**: Prevent man-in-the-middle (MITM) attacks on API communications
- **How it works**: 
  - Validates the API server's public key against a hardcoded value
  - Release mode: always enforced when enabled
  - Debug mode: only enforced for HTTPS connections
- **Can be disabled**: Yes, falls back to standard system TLS verification
- **Impact when disabled**: Standard TLS without public key pinning

## Feature Dependencies

```
default = ["client"]
├── client
│   ├── safetensors/std
│   └── safetensors/client
└── cert-pinning (optional)
    └── safetensors/cert-pinning
```

## Debug vs Release Behavior (when cert-pinning is enabled)

| Scenario | HTTP Connection | HTTPS Connection |
|----------|----------------|------------------|
| No cert-pinning | Standard TLS | Standard TLS |
| Debug + cert-pinning | Skip validation | Certificate pinning (warnings only) |
| Release + cert-pinning | Upgrade to HTTPS, then validate | Certificate pinning (strict) |

## Build Examples

```bash
# Development (default: client only)
cargo build

# Production (with cert-pinning)
cargo build --release --features cert-pinning
maturin build --release --features cert-pinning
```
