#!/usr/bin/env python3
"""
Certbot hook for uploading SSL certificates to Netgear managed switches.

This script uploads Let's Encrypt certificates to Netgear managed switches
via their web management interface.

Supported models:
- GS728TPP (ProSafe 24-Port Gigabit Smart Switch with PoE+)
- S3300 series (S3300-28X, S3300-52X, S3300-28X-PoE+, S3300-52X-PoE+)

Usage as certbot deploy hook:
    certbot renew --deploy-hook "netgear-updater.py --switch-url http://switch.local ..."

Usage standalone:
    ./netgear-updater.py --switch-url http://switch.local \\
        --username admin --password secret \\
        --cert-file /etc/letsencrypt/live/switch.local/fullchain.pem \\
        --key-file /etc/letsencrypt/live/switch.local/privkey.pem
"""

# Copyright 2025 Tim Ansell
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import os
import sys
import re
import requests
import logging
from urllib.parse import urlparse, quote
from datetime import datetime


# Disable SSL warnings for self-signed certs on switches
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

REQUEST_TIMEOUT = 10.0


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

    def verify_certificate(self, cert_file: str) -> bool:
        """
        Verify the switch is serving the expected certificate via HTTPS.

        Connects to the switch on port 443 and compares the served certificate's
        fingerprint with the expected certificate.
        """
        import ssl
        import socket
        import hashlib

        # Get expected certificate fingerprint
        try:
            with open(cert_file, 'rb') as f:
                cert_pem = f.read()
            # Extract first certificate from chain (if fullchain)
            cert_pem_str = cert_pem.decode('utf-8')
            if '-----BEGIN CERTIFICATE-----' in cert_pem_str:
                first_cert_start = cert_pem_str.find('-----BEGIN CERTIFICATE-----')
                first_cert_end = cert_pem_str.find('-----END CERTIFICATE-----') + len('-----END CERTIFICATE-----')
                first_cert_pem = cert_pem_str[first_cert_start:first_cert_end].encode('utf-8')
            else:
                first_cert_pem = cert_pem

            # Convert PEM to DER to get fingerprint
            import subprocess
            result = subprocess.run(
                ['openssl', 'x509', '-outform', 'DER'],
                input=first_cert_pem, capture_output=True, timeout=10
            )
            if result.returncode != 0:
                self.logger.error(f"Failed to convert certificate to DER: {result.stderr.decode()}")
                return False
            expected_fingerprint = hashlib.sha256(result.stdout).hexdigest()
            self.logger.debug(f"Expected certificate fingerprint: {expected_fingerprint}")
        except Exception as e:
            self.logger.error(f"Failed to read expected certificate: {e}")
            return False

        # Connect to switch and get served certificate
        try:
            url_parts = urlparse(self.switch_url)
            hostname = url_parts.hostname
            port = 443

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=REQUEST_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    served_fingerprint = hashlib.sha256(cert_der).hexdigest()
                    self.logger.debug(f"Served certificate fingerprint: {served_fingerprint}")

            if served_fingerprint == expected_fingerprint:
                self.logger.info("Certificate verification successful - switch is serving the uploaded certificate")
                return True
            else:
                self.logger.warning(f"Certificate mismatch - switch may need a reboot to activate new certificate")
                self.logger.debug(f"Expected: {expected_fingerprint}")
                self.logger.debug(f"Got: {served_fingerprint}")
                return False

        except Exception as e:
            self.logger.warning(f"Could not verify certificate via HTTPS: {e}")
            self.logger.warning("HTTPS may not be enabled or switch may need a reboot")
            return False


class GS728TPPUpdater(NetgearSwitchUpdater):
    """
    Certificate updater for GS728TPP ProSafe Smart Switch.

    Uses XML-based API for authentication and certificate management.
    Navigation path: Security > Access > HTTPS > Certificate Management
    """

    def __init__(self, switch_url: str, username: str, password: str):
        super().__init__(switch_url, username, password)
        self.session_path = None
        self.base_url = None

    def login(self) -> bool:
        """
        Log into GS728TPP using XML API.

        Flow:
        1. GET / to obtain session path from redirect
        2. GET /System.xml?action=login with credentials
        3. Set required cookies (userStatus, usernme, sessionID)
        """
        self.logger.debug("Starting GS728TPP login")

        # Step 1: Get session path from redirect
        try:
            resp = self.session.get(
                self.switch_url,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT
            )
        except requests.RequestException as e:
            self.logger.error(f"Failed to connect to switch: {e}")
            return False

        location = resp.headers.get('Location', '')
        match = re.search(r'/([a-zA-Z0-9]+)/', location)
        if not match:
            self.logger.error("Failed to extract session path from redirect")
            return False

        self.session_path = match.group(1)
        self.base_url = f"{self.switch_url}/{self.session_path}"
        self.logger.debug(f"Session path: {self.session_path}")

        # Step 2: Login via XML API
        encoded_password = quote(self.password, safe='')
        login_url = f"{self.base_url}/System.xml?action=login&user={self.username}&password={encoded_password}"

        try:
            resp = self.session.get(login_url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            self.logger.error(f"Login request failed: {e}")
            return False

        # Check for successful login
        if '<statusCode>0</statusCode>' not in resp.text:
            self.logger.error("Login failed - invalid credentials or response")
            self.logger.debug(f"Login response: {resp.text}")
            return False

        # Extract sessionID from response header
        session_id = resp.headers.get('sessionID')
        self.logger.debug(f"SessionID from header: {session_id}")

        # Step 3: Set required cookies
        url_parts = urlparse(self.switch_url)
        domain = url_parts.hostname

        self.session.cookies.set('userStatus', 'ok', domain=domain, path='/')
        self.session.cookies.set('usernme', self.username, domain=domain, path='/')
        if session_id:
            self.session.cookies.set('sessionID', session_id, domain=domain, path='/')

        self.logger.debug("Login successful")
        return True

    def upload_certificate(self, cert_file: str, key_file: str) -> bool:
        """
        Upload certificate to GS728TPP via XML API.

        Posts XML to /wcd endpoint with certificate data.
        The switch requires keys in traditional RSA format (PKCS#1).
        """
        if not self.base_url:
            self.logger.error("Not logged in - call login() first")
            return False

        # Read certificate and key files
        with open(cert_file, 'r') as f:
            cert_data = f.read().strip()

        with open(key_file, 'r') as f:
            key_data = f.read().strip()

        # Convert keys to traditional RSA format (PKCS#1) as required by switch
        private_key_rsa, public_key_rsa = self._convert_to_rsa_format(key_data)
        if not private_key_rsa:
            self.logger.error("Failed to convert private key to RSA format")
            return False

        # Build XML payload with all three components
        xml_payload = self._build_cert_xml(cert_data, public_key_rsa, private_key_rsa)
        self.logger.debug(f"XML payload length: {len(xml_payload)}")

        # POST to wcd endpoint
        wcd_url = f"{self.base_url}/wcd"
        headers = {
            'Content-Type': 'application/xml; charset=utf-8',
        }

        try:
            resp = self.session.post(
                wcd_url,
                data=xml_payload,
                headers=headers,
                timeout=REQUEST_TIMEOUT * 2
            )
        except requests.RequestException as e:
            self.logger.error(f"Certificate upload request failed: {e}")
            return False

        self.logger.debug(f"Upload response status: {resp.status_code}")
        self.logger.debug(f"Upload response: {resp.text[:500] if resp.text else 'empty'}")

        if resp.status_code != 200:
            self.logger.error(f"Upload failed with status {resp.status_code}")
            return False

        # Check response for errors
        # The switch returns XML with <statusCode>0</statusCode> for success
        # and non-zero statusCode with <statusString> for errors
        status_match = re.search(r'<statusCode>(\d+)</statusCode>', resp.text)
        if status_match:
            status_code = int(status_match.group(1))
            if status_code != 0:
                status_string_match = re.search(r'<statusString>([^<]*)</statusString>', resp.text)
                status_string = status_string_match.group(1) if status_string_match else "Unknown error"
                self.logger.error(f"Upload failed: {status_string} (statusCode={status_code})")
                return False
        elif '<error>' in resp.text.lower():
            self.logger.error(f"Upload returned error: {resp.text}")
            return False

        return True

    def _convert_to_rsa_format(self, key_pem: str) -> tuple:
        """
        Convert private key to traditional RSA format (PKCS#1) and extract public key.

        Returns (private_key_rsa, public_key_rsa) tuple, or (None, None) on failure.
        """
        import subprocess
        import tempfile

        try:
            # Write key to temp file for openssl
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
                f.write(key_pem)
                key_file = f.name

            try:
                # Convert to traditional RSA private key format
                result = subprocess.run(
                    ['openssl', 'rsa', '-in', key_file, '-traditional'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0:
                    self.logger.error(f"openssl rsa conversion failed: {result.stderr}")
                    return (None, None)
                private_key_rsa = result.stdout.strip()

                # Extract RSA public key
                result = subprocess.run(
                    ['openssl', 'rsa', '-in', key_file, '-RSAPublicKey_out'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0:
                    self.logger.error(f"openssl RSAPublicKey extraction failed: {result.stderr}")
                    return (None, None)
                public_key_rsa = result.stdout.strip()

                return (private_key_rsa, public_key_rsa)

            finally:
                import os
                os.unlink(key_file)

        except Exception as e:
            self.logger.error(f"Key conversion failed: {e}")
            return (None, None)

    def _build_cert_xml(self, certificate: str, public_key: str, private_key: str) -> str:
        """Build XML payload for certificate import."""
        # Escape XML special characters in PEM data
        def escape_xml(s):
            return (s.replace('&', '&amp;')
                     .replace('<', '&lt;')
                     .replace('>', '&gt;')
                     .replace('"', '&quot;')
                     .replace("'", '&apos;'))

        parts = ["<?xml version='1.0' encoding='utf-8'?>"]
        parts.append("<DeviceConfiguration>")
        parts.append('<SSLCryptoCertificateImportList action="set">')
        parts.append("<Entry>")
        parts.append("<instance>1</instance>")
        parts.append(f"<certificate>{escape_xml(certificate)}</certificate>")
        if public_key:
            parts.append(f"<publicKey>{escape_xml(public_key)}</publicKey>")
        parts.append(f"<privateKey>{escape_xml(private_key)}</privateKey>")
        parts.append("</Entry>")
        parts.append("</SSLCryptoCertificateImportList>")
        parts.append("</DeviceConfiguration>")

        return ''.join(parts)


class S3300Updater(NetgearSwitchUpdater):
    """
    Certificate updater for S3300 series switches.

    Uses form-based authentication and multipart file upload.
    Navigation path: Security > Access > HTTPS > SSL Configuration
    """

    def __init__(self, switch_url: str, username: str, password: str):
        super().__init__(switch_url, username, password)
        self.logged_in = False

    def login(self) -> bool:
        """
        Log into S3300 series switch.

        POSTs password to /base/cheetah_login.html
        Note: S3300 uses password-only authentication (no username in form)
        """
        self.logger.debug("Starting S3300 login")

        login_url = f"{self.switch_url}/base/cheetah_login.html"
        login_data = {
            'pwd': self.password
        }

        try:
            resp = self.session.post(
                login_url,
                data=login_data,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True
            )
        except requests.RequestException as e:
            self.logger.error(f"Login request failed: {e}")
            return False

        # Check for successful login by looking for SID cookie or content
        cookies = self.session.cookies.get_dict()
        if 'SID' not in cookies:
            # Some versions may not set SID, check response content
            if 'logout' not in resp.text.lower() and 'menu' not in resp.text.lower():
                self.logger.error("Login failed - no session established")
                return False

        self.logged_in = True
        self.logger.debug("Login successful")
        return True

    def upload_certificate(self, cert_file: str, key_file: str) -> bool:
        """
        Upload certificate to S3300 via multipart form.

        POSTs to /http_file_download.html/a1 with file upload.
        """
        if not self.logged_in:
            self.logger.error("Not logged in - call login() first")
            return False

        # Read certificate and key files
        with open(cert_file, 'rb') as f:
            cert_data = f.read()

        with open(key_file, 'rb') as f:
            key_data = f.read()

        # S3300 expects PEM file with cert + key combined
        combined_pem = cert_data + b'\n' + key_data

        upload_url = f"{self.switch_url}/http_file_download.html/a1"

        # Build multipart form
        files = {
            'file': ('certificate.pem', combined_pem, 'application/octet-stream')
        }

        # File type selector value for SSL Server Certificate PEM
        data = {
            'file_type': '6'  # SSL Server Certificate PEM File
        }

        try:
            resp = self.session.post(
                upload_url,
                files=files,
                data=data,
                timeout=REQUEST_TIMEOUT * 2
            )
        except requests.RequestException as e:
            self.logger.error(f"Certificate upload request failed: {e}")
            return False

        self.logger.debug(f"Upload response status: {resp.status_code}")
        # Force UTF-8 encoding - the switch may return non-standard encoding
        resp.encoding = 'utf-8'
        response_text = resp.text if resp.text else ''
        self.logger.debug(f"Upload response: {response_text[:500] if response_text else 'empty'}")

        if resp.status_code != 200:
            self.logger.error(f"Upload failed with status {resp.status_code}")
            return False

        # Check for success indicators
        if 'error' in response_text.lower() and 'no error' not in response_text.lower():
            self.logger.error(f"Upload returned error: {response_text}")
            return False

        return True


def parse_cert_info(pem_file: str) -> dict:
    """Parse certificate info: expiry date and key type."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec

        with open(pem_file, 'rb') as f:
            cert_data = f.read()

        cert = x509.load_pem_x509_certificate(cert_data)
        valid_until = cert.not_valid_after_utc.replace(tzinfo=None)

        # Determine key type
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_type = "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type = "ECDSA"
        else:
            key_type = "OTHER"

        return {'valid_until': valid_until, 'key_type': key_type}

    except ImportError:
        # Fallback to OpenSSL if cryptography not available
        try:
            from OpenSSL import crypto as c
            with open(pem_file, 'rb') as f:
                cert = c.load_certificate(c.FILETYPE_PEM, f.read())

            valid_until = datetime.strptime(
                cert.get_notAfter().decode('utf8'),
                "%Y%m%d%H%M%SZ"
            )

            key_type_id = cert.get_pubkey().type()
            if key_type_id == c.TYPE_RSA:
                key_type = "RSA"
            elif key_type_id == 408:  # EC key
                key_type = "ECDSA"
            else:
                key_type = "OTHER"

            return {'valid_until': valid_until, 'key_type': key_type}
        except ImportError:
            return None


def detect_switch_model(switch_url: str) -> str:
    """Try to detect the switch model from its web interface."""
    session = requests.Session()
    session.verify = False

    try:
        resp = session.get(switch_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        content = resp.text.lower()

        # Check for GS728TPP indicators
        if 'gs728tpp' in content:
            return 'GS728TPP'

        # Check for S3300 indicators
        if 's3300' in content or 'cheetah' in content:
            return 'S3300'

        # Check redirect patterns
        if resp.history:
            # GS728TPP redirects to /{session_path}/config/authentication_page.htm
            if '/config/authentication_page.htm' in resp.url:
                return 'GS728TPP'
            # S3300 uses /base/ path
            if '/base/' in resp.url:
                return 'S3300'

    except requests.RequestException:
        pass

    return "unknown"


def create_updater(switch_url: str, username: str, password: str,
                   model: str = None) -> NetgearSwitchUpdater:
    """Create the appropriate updater for the switch model."""
    if model is None:
        model = detect_switch_model(switch_url)

    model_upper = model.upper()

    if model_upper == "GS728TPP":
        return GS728TPPUpdater(switch_url, username, password)
    elif model_upper in ("S3300", "S3300-28X", "S3300-52X",
                         "S3300-28X-POE", "S3300-52X-POE", "S3300-52X-POE+"):
        return S3300Updater(switch_url, username, password)

    raise ValueError(f"Unknown or unsupported switch model: {model}")


def main():
    parser = argparse.ArgumentParser(
        description='Upload SSL certificates to Netgear managed switches',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported models:
  GS728TPP     - ProSafe 24-Port Gigabit Smart Switch with PoE+
  S3300        - S3300 series (S3300-28X, S3300-52X, etc.)

Examples:
  %(prog)s --switch-url http://10.1.5.14 --model GS728TPP \\
           --username admin --password secret \\
           --key-file privkey.pem --cert-file fullchain.pem

  %(prog)s --switch-url http://10.1.5.11 --model S3300 \\
           --username admin --password secret \\
           --key-file privkey.pem --cert-file fullchain.pem
"""
    )
    parser.add_argument('--switch-url', required=True,
                        help='URL of the switch management interface')
    parser.add_argument('--model',
                        help='Switch model (auto-detected if not specified)')
    parser.add_argument('--username', default='admin',
                        help='Switch admin username (default: admin)')
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

    # Normalize URL
    if not args.switch_url.startswith('http'):
        args.switch_url = f"http://{args.switch_url}"

    # Parse certificate info if possible
    cert_info = parse_cert_info(args.cert_file)
    if cert_info and not args.quiet:
        logger.info(f"Certificate valid until: {cert_info['valid_until']}")
        logger.info(f"Certificate key type: {cert_info['key_type']}")

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

    if not args.quiet:
        model_name = args.model or type(updater).__name__.replace('Updater', '')
        logger.info(f"Connecting to {model_name} at {args.switch_url}...")

    # Login to switch
    if not updater.login():
        logger.error("Failed to login to switch")
        sys.exit(2)

    if not args.quiet:
        logger.info("Login successful")

    # Upload certificate
    if not args.quiet:
        logger.info("Uploading certificate...")

    if not updater.upload_certificate(args.cert_file, args.key_file):
        logger.error("Failed to upload certificate")
        sys.exit(2)

    updater.logout()

    if not args.quiet:
        logger.info("Certificate uploaded successfully")

    # Verify the certificate is now being served
    if not args.quiet:
        logger.info("Verifying certificate deployment...")
    verified = updater.verify_certificate(args.cert_file)

    if not args.quiet:
        if not verified:
            logger.info("")
            logger.info("NOTE: You may need to:")
            logger.info("  1. Enable HTTPS in the switch configuration")
            logger.info("  2. Reboot the switch for changes to take effect")


if __name__ == "__main__":
    main()
