"""
Secure credential storage using OS keychain.

Provides cross-platform secure storage for sensitive credentials:
- macOS: Keychain
- Windows: Credential Manager
- Linux: Secret Service (GNOME Keyring, KWallet)

Falls back gracefully when keychain is unavailable.
"""

import json
import base64
import logging
from typing import Optional, Union

logger = logging.getLogger(__name__)

SERVICE_NAME = "ClipCascade"

_keyring = None


def _get_keyring():
    """Lazy load keyring module. Returns keyring module or None if unavailable."""
    global _keyring
    if _keyring is None:
        try:
            import keyring
            _keyring = keyring
        except ImportError:
            logger.warning("keyring module not installed - secure storage unavailable")
            _keyring = False
    return _keyring if _keyring else None


class SecureStorage:
    """
    Cross-platform secure credential storage using OS keychain.
    Falls back to returning None when keychain unavailable.
    """

    def __init__(self):
        self._available = self._test_keyring()
        if not self._available:
            logger.warning("Keychain unavailable - credentials will use fallback storage")

    def _test_keyring(self) -> bool:
        """Test if keyring backend is functional."""
        keyring = _get_keyring()
        if not keyring:
            return False
        try:
            backend = keyring.get_keyring()
            backend_name = backend.__class__.__name__.lower()
            if "fail" in backend_name or "null" in backend_name:
                return False
            return True
        except Exception:
            return False

    @property
    def is_available(self) -> bool:
        """Check if secure storage is available."""
        return self._available

    def _set(self, key: str, value: Union[str, dict, bytes]) -> bool:
        """Generic setter for keychain storage."""
        if not self._available or not value:
            return False
        keyring = _get_keyring()
        try:
            if isinstance(value, bytes):
                value = base64.b64encode(value).decode("utf-8")
            elif isinstance(value, dict):
                value = json.dumps(value)
            keyring.set_password(SERVICE_NAME, key, value)
            return True
        except Exception as e:
            logger.error(f"Failed to store {key} in keychain: {e}")
            return False

    def _get(self, key: str, decode_type: Optional[str] = None) -> Optional[Union[str, dict, bytes]]:
        """Generic getter for keychain storage."""
        if not self._available:
            return None
        keyring = _get_keyring()
        try:
            value = keyring.get_password(SERVICE_NAME, key)
            if not value:
                return None
            if decode_type == "bytes":
                return base64.b64decode(value)
            elif decode_type == "dict":
                return json.loads(value)
            return value
        except (json.JSONDecodeError, ValueError, TypeError):
            logger.error(f"Failed to decode {key} from keychain")
            return None
        except Exception:
            return None

    def _delete(self, key: str) -> None:
        """Delete a single key from keychain."""
        if not self._available:
            return
        keyring = _get_keyring()
        try:
            keyring.delete_password(SERVICE_NAME, key)
        except Exception:
            pass

    # Public API - thin wrappers around generic methods
    def set_cookie(self, cookie_dict: dict) -> bool:
        return self._set("session_cookie", cookie_dict)

    def get_cookie(self) -> Optional[dict]:
        return self._get("session_cookie", decode_type="dict")

    def set_csrf_token(self, token: str) -> bool:
        return self._set("csrf_token", token)

    def get_csrf_token(self) -> Optional[str]:
        return self._get("csrf_token")

    def set_encryption_key(self, key_bytes: bytes) -> bool:
        return self._set("encryption_key", key_bytes)

    def get_encryption_key(self) -> Optional[bytes]:
        return self._get("encryption_key", decode_type="bytes")

    def set_saved_password(self, password: str) -> bool:
        return self._set("saved_password", password)

    def get_saved_password(self) -> Optional[str]:
        return self._get("saved_password")

    def clear_all(self) -> None:
        """Remove all stored credentials from keychain."""
        for key in ["session_cookie", "csrf_token", "encryption_key", "saved_password"]:
            self._delete(key)
