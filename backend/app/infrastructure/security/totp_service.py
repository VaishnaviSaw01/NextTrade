"""
TOTP (Time-based One-Time Password) Service
============================================

Generates, stores, and verifies per-admin TOTP secrets for the second
factor of the admin login flow.

Previously, the "verify" endpoint accepted any well-formed 6-digit code
without checking it against anything — this module is what makes that
check real. Secrets are encrypted at rest with the same Fernet-based
APIKeyManager used for third-party API keys, and persisted next to them
in data/secure_keys/ (gitignored, never committed).
"""

import json
from pathlib import Path
from typing import Tuple

import pyotp

from app.infrastructure.security.api_key_manager import APIKeyManager
from app.infrastructure.log_system import get_logger

logger = get_logger()

_SECRETS_FILE = Path("data/secure_keys/totp_secrets.json")


class TOTPService:
    """Server-side TOTP secret storage and code verification."""

    def __init__(self):
        self._key_manager = APIKeyManager()

    def has_secret(self, email: str) -> bool:
        """Whether `email` already has a TOTP secret configured."""
        return self._load_all().get(email.lower()) is not None

    def get_or_create_secret(self, email: str) -> Tuple[str, bool]:
        """
        Return (secret, created).

        Reuses the existing secret for `email` if one is already
        configured, so reopening the setup screen doesn't invalidate an
        authenticator app the admin already enrolled. Otherwise generates
        and persists a new one.
        """
        secrets_map = self._load_all()
        key = email.lower()
        encrypted = secrets_map.get(key)
        if encrypted:
            return self._key_manager.decrypt_api_key(encrypted), False

        secret = pyotp.random_base32()
        secrets_map[key] = self._key_manager.encrypt_api_key(secret)
        self._save_all(secrets_map)
        logger.info(f"Generated new TOTP secret for {email}")
        return secret, True

    def verify_code(self, email: str, code: str) -> bool:
        """Check a 6-digit code against the stored secret for `email`."""
        encrypted = self._load_all().get(email.lower())
        if not encrypted:
            logger.warning(f"TOTP verification attempted with no secret configured: {email}")
            return False

        secret = self._key_manager.decrypt_api_key(encrypted)
        # valid_window=1 tolerates +/-30s of clock drift between the
        # server and the admin's authenticator app.
        return pyotp.TOTP(secret).verify(code, valid_window=1)

    def revoke(self, email: str) -> None:
        """Remove a stored secret, e.g. so an admin can re-enroll."""
        secrets_map = self._load_all()
        if secrets_map.pop(email.lower(), None) is not None:
            self._save_all(secrets_map)
            logger.info(f"Revoked TOTP secret for {email}")

    @staticmethod
    def provisioning_uri(email: str, secret: str, issuer: str) -> str:
        """otpauth:// URL for QR-code enrollment in an authenticator app."""
        return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)

    def _load_all(self) -> dict:
        if not _SECRETS_FILE.exists():
            return {}
        try:
            with open(_SECRETS_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load TOTP secrets: {e}")
            return {}

    def _save_all(self, secrets_map: dict) -> None:
        _SECRETS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_SECRETS_FILE, "w") as f:
            json.dump(secrets_map, f, indent=2)
