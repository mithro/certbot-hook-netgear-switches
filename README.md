# certbot-hook-netgear-switches

Certbot deploy hook that uploads Let's Encrypt certificates to Netgear managed switches.

## Overview

This script automates the process of uploading SSL certificates to Netgear managed switches via their web management interface, SNMP, or other available interfaces.

## Status

**Work in Progress** - The script structure is in place but model-specific implementations need to be added.

## Planned Support

- Netgear GS748T and similar managed switches
- Other Netgear managed switch models

## Requirements

- Python 3.6+
- `requests` library

Install dependencies:

```bash
pip install requests
```

## Usage

### As a certbot deploy hook

```bash
certbot renew --deploy-hook "/path/to/netgear-updater.py \
    --switch-url https://switch.example.com \
    --username admin \
    --password 'your-password' \
    --cert-file \$RENEWED_LINEAGE/fullchain.pem \
    --key-file \$RENEWED_LINEAGE/privkey.pem"
```

### Standalone usage

```bash
./netgear-updater.py \
    --switch-url https://switch.example.com \
    --model GS748T \
    --username admin \
    --password 'your-password' \
    --cert-file /etc/letsencrypt/live/switch.example.com/fullchain.pem \
    --key-file /etc/letsencrypt/live/switch.example.com/privkey.pem
```

## Options

| Option | Description |
|--------|-------------|
| `--switch-url` | URL of the switch management interface (required) |
| `--model` | Switch model (auto-detected if not specified) |
| `--username` | Admin username (required) |
| `--password` | Admin password (required) |
| `--cert-file` | Path to certificate PEM file (required) |
| `--key-file` | Path to private key PEM file (required) |
| `--quiet` | Suppress output on success |
| `--debug` | Enable debug output |

## Contributing

Contributions are welcome, especially for adding support for specific Netgear switch models. To add support for a new model:

1. Create a new class inheriting from `NetgearSwitchUpdater`
2. Implement the `login()` and `upload_certificate()` methods
3. Add the model to the `create_updater()` function

## License

Apache License 2.0 - see [LICENSE](LICENSE)
