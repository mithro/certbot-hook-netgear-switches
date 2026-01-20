#!/usr/bin/env python3
"""
Certbot hook for uploading SSL certificates to Netgear managed switches.

This script uploads Let's Encrypt certificates to Netgear managed switches
via their web management interface.

Supported models:
- Netgear GS748T (to be tested)
- Other Netgear managed switches (to be added)

Usage as certbot deploy hook:
    certbot renew --deploy-hook "netgear-updater.py --switch-url https://switch.local ..."

Usage standalone:
    ./netgear-updater.py --switch-url https://switch.local \\
        --username admin --password secret \\
        --cert-file /etc/letsencrypt/live/switch.local/fullchain.pem \\
        --key-file /etc/letsencrypt/live/switch.local/privkey.pem
"""

import argparse
import os
import sys
import requests
import logging
from urllib.parse import urlparse


# Disable SSL warnings for self-signed certs on switches
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


class NetgearSwitchUpdater:
    """Base class for Netgear switch certificate updaters."""

    def __init__(self, switch_url: str, username: str, password: str):
        self.switch_url = switch_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False
        self.logger = logging.getLogger(self.__class__.__name__)

    def login(self) -> bool:
        """Log into the switch web interface."""
        raise NotImplementedError("Subclasses must implement login()")

    def upload_certificate(self, cert_file: str, key_file: str) -> bool:
        """Upload certificate and private key to the switch."""
        raise NotImplementedError("Subclasses must implement upload_certificate()")

    def logout(self) -> None:
        """Log out of the switch web interface."""
        pass  # Optional, not all switches require explicit logout


class NetgearGS748TUpdater(NetgearSwitchUpdater):
    """Certificate updater for Netgear GS748T and similar models."""

    def login(self) -> bool:
        """Log into the GS748T web interface."""
        # TODO: Implement login for GS748T
        # The login mechanism varies by firmware version
        self.logger.warning("GS748T login not yet implemented")
        return False

    def upload_certificate(self, cert_file: str, key_file: str) -> bool:
        """Upload certificate to GS748T."""
        # TODO: Implement certificate upload for GS748T
        self.logger.warning("GS748T certificate upload not yet implemented")
        return False


def detect_switch_model(switch_url: str) -> str:
    """Try to detect the switch model from its web interface."""
    # TODO: Implement model detection
    return "unknown"


def create_updater(switch_url: str, username: str, password: str,
                   model: str = None) -> NetgearSwitchUpdater:
    """Create the appropriate updater for the switch model."""
    if model is None:
        model = detect_switch_model(switch_url)

    if model.upper() in ("GS748T", "GS748TV5"):
        return NetgearGS748TUpdater(switch_url, username, password)

    # Default to base class for unknown models
    raise ValueError(f"Unknown or unsupported switch model: {model}")


def main():
    parser = argparse.ArgumentParser(
        description='Upload SSL certificates to Netgear managed switches'
    )
    parser.add_argument('--switch-url', required=True,
                        help='URL of the switch management interface')
    parser.add_argument('--model',
                        help='Switch model (auto-detected if not specified)')
    parser.add_argument('--username', required=True,
                        help='Switch admin username')
    parser.add_argument('--password', required=True,
                        help='Switch admin password')
    parser.add_argument('--cert-file', required=True,
                        help='Path to certificate PEM file')
    parser.add_argument('--key-file', required=True,
                        help='Path to private key PEM file')
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress output on success')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug output')
    args = parser.parse_args()

    # Set up logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    if args.quiet:
        log_level = logging.WARNING
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    logger = logging.getLogger(__name__)

    # Validate input files
    if not os.path.isfile(args.cert_file):
        logger.error(f"Certificate file not found: {args.cert_file}")
        sys.exit(2)
    if not os.path.isfile(args.key_file):
        logger.error(f"Key file not found: {args.key_file}")
        sys.exit(2)

    try:
        updater = create_updater(
            args.switch_url,
            args.username,
            args.password,
            args.model
        )
    except ValueError as e:
        logger.error(str(e))
        sys.exit(2)

    # Login to switch
    if not updater.login():
        logger.error("Failed to login to switch")
        sys.exit(2)

    # Upload certificate
    if not updater.upload_certificate(args.cert_file, args.key_file):
        logger.error("Failed to upload certificate")
        sys.exit(2)

    updater.logout()

    if not args.quiet:
        logger.info("Certificate uploaded successfully")


if __name__ == "__main__":
    main()
