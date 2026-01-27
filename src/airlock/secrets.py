"""Airlock Secrets — Encrypted credential storage using TOTP-derived keys.

Secrets are encrypted at rest using a key derived from the TOTP secret.
This means:
- At rest: AES-256 encrypted, unreadable without TOTP secret
- To decrypt: Need access to TOTP secret file
- Consistent with Airlock's security model

Usage:
    secrets = SecretsManager(totp_secret_path)
    
    # Store a secret
    secrets.set("openrouter", "api_key", "sk-or-v1-...")
    
    # Retrieve a secret
    api_key = secrets.get("openrouter", "api_key")
    
    # List services with stored secrets
    services = secrets.list_services()
"""

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


DEFAULT_SECRETS_PATH = Path.home() / ".local" / "share" / "airlock" / "secrets.enc"
DEFAULT_TOTP_SECRET_PATH = Path.home() / ".local" / "share" / "airlock" / "totp_secret"


@dataclass
class SecretsConfig:
    """Configuration for secrets storage."""
    secrets_path: Path = DEFAULT_SECRETS_PATH
    totp_secret_path: Path = DEFAULT_TOTP_SECRET_PATH


class SecretsManager:
    """Encrypted secrets storage using TOTP-derived encryption key."""
    
    def __init__(self, config: SecretsConfig = None):
        self.config = config or SecretsConfig()
        self._fernet: Optional[Fernet] = None
    
    def _get_encryption_key(self) -> bytes:
        """Derive encryption key from TOTP secret using PBKDF2."""
        if not self.config.totp_secret_path.exists():
            raise FileNotFoundError(
                f"TOTP secret not found at {self.config.totp_secret_path}. "
                "Run 'airlock init' first to set up TOTP."
            )
        
        # Read TOTP secret (base32 encoded)
        totp_secret = self.config.totp_secret_path.read_text().strip()
        
        # Use a fixed salt (we're deriving from TOTP secret which is already random)
        # In production, could store a random salt alongside secrets.enc
        salt = b"airlock-secrets-v1"
        
        # Derive a 32-byte key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(totp_secret.encode()))
        
        return key
    
    def _get_fernet(self) -> Fernet:
        """Get or create Fernet instance."""
        if self._fernet is None:
            key = self._get_encryption_key()
            self._fernet = Fernet(key)
        return self._fernet
    
    def _load_secrets(self) -> dict:
        """Load and decrypt secrets from disk."""
        if not self.config.secrets_path.exists():
            return {}
        
        encrypted_data = self.config.secrets_path.read_bytes()
        decrypted_data = self._get_fernet().decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    
    def _save_secrets(self, secrets: dict) -> None:
        """Encrypt and save secrets to disk."""
        self.config.secrets_path.parent.mkdir(parents=True, exist_ok=True)
        
        json_data = json.dumps(secrets, indent=2).encode()
        encrypted_data = self._get_fernet().encrypt(json_data)
        
        # Write with restricted permissions (owner read/write only)
        self.config.secrets_path.write_bytes(encrypted_data)
        self.config.secrets_path.chmod(0o600)
    
    def set(self, service: str, key: str, value: str) -> None:
        """Store an encrypted secret.
        
        Args:
            service: Service name (e.g., "openrouter", "github")
            key: Secret key name (e.g., "api_key", "token")
            value: Secret value to store
        """
        secrets = self._load_secrets()
        
        if service not in secrets:
            secrets[service] = {}
        
        secrets[service][key] = value
        self._save_secrets(secrets)
    
    def get(self, service: str, key: str, default: str = None) -> Optional[str]:
        """Retrieve a decrypted secret.
        
        Args:
            service: Service name
            key: Secret key name
            default: Default value if not found
        
        Returns:
            Decrypted secret value or default
        """
        secrets = self._load_secrets()
        return secrets.get(service, {}).get(key, default)
    
    def delete(self, service: str, key: str = None) -> bool:
        """Delete a secret or entire service.
        
        Args:
            service: Service name
            key: Secret key name (if None, deletes entire service)
        
        Returns:
            True if something was deleted
        """
        secrets = self._load_secrets()
        
        if service not in secrets:
            return False
        
        if key is None:
            del secrets[service]
        elif key in secrets[service]:
            del secrets[service][key]
            if not secrets[service]:  # Clean up empty service
                del secrets[service]
        else:
            return False
        
        self._save_secrets(secrets)
        return True
    
    def list_services(self) -> list[str]:
        """List all services with stored secrets."""
        secrets = self._load_secrets()
        return list(secrets.keys())
    
    def list_keys(self, service: str) -> list[str]:
        """List all keys for a service."""
        secrets = self._load_secrets()
        return list(secrets.get(service, {}).keys())
    
    def has(self, service: str, key: str = None) -> bool:
        """Check if a secret exists.
        
        Args:
            service: Service name
            key: Secret key name (if None, checks if service exists)
        """
        secrets = self._load_secrets()
        
        if key is None:
            return service in secrets
        
        return key in secrets.get(service, {})


# Convenience functions for common use
def get_secret(service: str, key: str, default: str = None) -> Optional[str]:
    """Quick access to a secret."""
    return SecretsManager().get(service, key, default)


def set_secret(service: str, key: str, value: str) -> None:
    """Quick store of a secret."""
    SecretsManager().set(service, key, value)
