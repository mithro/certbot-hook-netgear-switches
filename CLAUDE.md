# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Certbot deploy hook that uploads Let's Encrypt certificates to Netgear managed switches via their web management interfaces. The script supports multiple switch models with model-specific authentication and upload mechanisms.

## Commands

```bash
# Run the script (uses .venv if present)
uv run ./netgear-updater.py --switch-url http://10.1.5.14 --model GS728TPP \
    --username admin --password secret \
    --cert-file fullchain.pem --key-file privkey.pem

# Install dependencies
uv pip install requests

# Optional: for certificate parsing
uv pip install cryptography
# or
uv pip install pyOpenSSL
```

## Architecture

Single-file Python script (`netgear-updater.py`) with a class hierarchy:

```
NetgearSwitchUpdater (base class)
├── GS728TPPUpdater  - XML API authentication, POST to /wcd
└── S3300Updater     - Form-based login, multipart upload to /http_file_download.html/a1
```

### Adding New Switch Models

1. Create a new class inheriting from `NetgearSwitchUpdater`
2. Implement `login()` and `upload_certificate()` methods
3. Add the model to `create_updater()` factory function
4. Optionally add detection logic to `detect_switch_model()`

### Protocol Notes

- **GS728TPP**: Redirects to `/{session_path}/` on first request. Login via `System.xml?action=login`. Certificate upload via XML POST to `/wcd` with `SSLCryptoCertificateImportList` element.
- **S3300**: Password-only login to `/base/cheetah_login.html`. Combined cert+key upload as multipart form to `/http_file_download.html/a1` with `file_type=6`.

Both protocols disable SSL verification since switches typically have self-signed certificates.
