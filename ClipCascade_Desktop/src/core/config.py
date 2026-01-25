import base64
import json
import logging
import os
import re
from core.constants import *
from utils.secure_storage import SecureStorage


class Config:
    def __init__(self, file_name=DATA_FILE_NAME):
        self.file_name = file_name
        self.secure_storage = SecureStorage()
        self.data = {
            "cipher_enabled": True,
            "server_url": "http://localhost:8080",
            "websocket_url": "",
            "username": "",
            "hashed_password": None,
            "cookie": None,
            "maxsize": None,
            "hash_rounds": 664937,
            "salt": "",
            "csrf_token": "",
            "notification": True,
            "save_password": False,
            "password": "",
            "max_clipboard_size_local_limit_bytes": None,
            "enable_image_sharing": True,
            "enable_file_sharing": True,
            "default_file_download_location": "",
            "server_mode": "P2S",
            "stun_url": "",
        }

    def save(self):
        """
        Save data to file. Sensitive credentials are stored in OS keychain
        when available, otherwise fall back to DATA file.
        """
        try:
            # Save sensitive fields to keychain if available
            if self.secure_storage.is_available:
                if self.data.get("cookie"):
                    self.secure_storage.set_cookie(self.data["cookie"])
                if self.data.get("csrf_token"):
                    self.secure_storage.set_csrf_token(self.data["csrf_token"])
                if self.data.get("hashed_password"):
                    self.secure_storage.set_encryption_key(self.data["hashed_password"])
                if self.data.get("save_password") and self.data.get("password"):
                    self.secure_storage.set_saved_password(self.data["password"])

            # Prepare data for file storage
            temp = self.data.copy()

            # If keychain is available, clear sensitive fields from JSON file
            if self.secure_storage.is_available:
                temp["cookie"] = None
                temp["csrf_token"] = ""
                temp["hashed_password"] = None
                temp["password"] = ""
            else:
                # Fallback: encode hashed_password for JSON storage
                if temp.get("cipher_enabled") and temp.get("hashed_password"):
                    temp["hashed_password"] = base64.b64encode(
                        temp["hashed_password"]
                    ).decode("utf-8")

            with open(self.file_name, "w") as f:
                json.dump(temp, f, indent=4)
        except Exception as e:
            logging.error(f"Failed to save data: {e}")

    def load(self):
        """
        Load data from file and keychain. Keychain credentials take precedence
        over DATA file when available.
        """
        file_data = None

        # First load from DATA file
        if os.path.isfile(self.file_name):
            try:
                with open(self.file_name, "r") as f:
                    file_data = json.load(f)
                    self.data.update(file_data)
                # Decode hashed_password if present in file (fallback storage)
                if self.data.get("hashed_password") and isinstance(
                    self.data["hashed_password"], str
                ):
                    self.data["hashed_password"] = base64.b64decode(
                        self.data["hashed_password"]
                    )
            except Exception as e:
                logging.error(f"Failed to load data: {e}")
                logging.error(
                    "Try deleting DATA file in the program directory, and re-run the program again"
                )
                return False

        # Load sensitive fields from keychain (takes precedence)
        if self.secure_storage.is_available:
            keychain_cookie = self.secure_storage.get_cookie()
            if keychain_cookie:
                self.data["cookie"] = keychain_cookie

            keychain_csrf = self.secure_storage.get_csrf_token()
            if keychain_csrf:
                self.data["csrf_token"] = keychain_csrf

            keychain_key = self.secure_storage.get_encryption_key()
            if keychain_key:
                self.data["hashed_password"] = keychain_key

            if self.data.get("save_password"):
                keychain_pwd = self.secure_storage.get_saved_password()
                if keychain_pwd:
                    self.data["password"] = keychain_pwd

            # Migrate credentials from DATA file to keychain (one-time)
            if file_data:
                self._migrate_to_keychain(file_data)

        return True

    def _migrate_to_keychain(self, file_data: dict):
        """
        Migrate credentials from DATA file to keychain (one-time migration).
        This handles upgrades from versions that stored credentials in plain JSON.
        """
        if not self.secure_storage.is_available:
            return

        migrated = False

        # Migrate cookie if in DATA file but not in keychain
        if file_data.get("cookie") and not self.secure_storage.get_cookie():
            if self.secure_storage.set_cookie(file_data["cookie"]):
                logging.info("Migrated session cookie to keychain")
                migrated = True

        # Migrate CSRF token
        if file_data.get("csrf_token") and not self.secure_storage.get_csrf_token():
            if self.secure_storage.set_csrf_token(file_data["csrf_token"]):
                migrated = True

        # Migrate hashed_password
        if file_data.get("hashed_password") and not self.secure_storage.get_encryption_key():
            hashed_pwd = file_data["hashed_password"]
            if isinstance(hashed_pwd, str):
                hashed_pwd = base64.b64decode(hashed_pwd)
            if self.secure_storage.set_encryption_key(hashed_pwd):
                migrated = True

        # Migrate saved password
        if file_data.get("password") and not self.secure_storage.get_saved_password():
            if self.secure_storage.set_saved_password(file_data["password"]):
                migrated = True

        # If migration occurred, save to clear sensitive data from DATA file
        if migrated:
            logging.info("Credential migration to keychain complete")
            self.save()

    def clear_credentials(self):
        """
        Clear all credentials from both memory and storage.
        Used during logout to ensure clean state.
        """
        # Clear from memory
        self.data["cookie"] = None
        self.data["csrf_token"] = ""
        self.data["hashed_password"] = None
        self.data["password"] = ""
        self.data["maxsize"] = None

        # Clear from keychain
        if self.secure_storage.is_available:
            self.secure_storage.clear_all()

        # Save to persist the cleared state
        self.save()

    @staticmethod
    def convert_to_websocket_url(input_url: str, endpoint: str = None) -> str:
        if not input_url or not isinstance(input_url, str):
            raise ValueError("Invalid URL provided")

        # Trim whitespace, remove trailing slashes, and convert to lowercase
        input_url = re.sub(r"/+$", "", input_url.strip()).lower()

        # Determine protocol and convert
        if input_url.startswith("https://"):
            ws_url = input_url.replace("https://", "wss://", 1)
        elif input_url.startswith("http://"):
            ws_url = input_url.replace("http://", "ws://", 1)
        else:
            raise ValueError(f"Unsupported protocol in URL: {input_url}")

        if endpoint is not None:
            # Append the WebSocket endpoint and remove any trailing slash
            ws_url += endpoint
            ws_url = re.sub(r"/+$", "", ws_url)

        return ws_url
