"""Airlock Secrets — Encrypted credential storage with passphrase-based security.

Secrets are encrypted at rest using a key derived from a passphrase you know.
The passphrase is NEVER stored on disk — you provide it when decryption is needed.

Security model:
- At rest: AES-256 encrypted, unreadable without passphrase
- Attacker with file access: Cannot decrypt (passphrase not on disk)
- To decrypt: Passphrase required every time

Usage:
    # Store a secret (requires passphrase)
    secrets = SecretsManager()
    secrets.set("openrouter", "api_key", "sk-or-v1-...", passphrase="your-passphrase")
    
    # Retrieve a secret (requires passphrase)
    api_key = secrets.get("openrouter", "api_key", passphrase="your-passphrase")
    
    # Quick access functions
    api_key = get_secret("openrouter", "api_key", passphrase="your-passphrase")
"""

import base64
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


DEFAULT_SECRETS_PATH = Path.home() / ".local" / "share" / "airlock" / "secrets.enc"
DEFAULT_SALT_PATH = Path.home() / ".local" / "share" / "airlock" / "secrets.salt"

# Legacy path - will be removed after migration
LEGACY_TOTP_SECRET_PATH = Path.home() / ".local" / "share" / "airlock" / "totp_secret"


@dataclass
class SecretsConfig:
    """Configuration for secrets storage."""
    secrets_path: Path = field(default_factory=lambda: DEFAULT_SECRETS_PATH)
    salt_path: Path = field(default_factory=lambda: DEFAULT_SALT_PATH)


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive encryption key from passphrase using PBKDF2.
    
    Args:
        passphrase: User's passphrase (never stored)
        salt: Random salt (stored alongside encrypted data)
        
    Returns:
        Fernet-compatible encryption key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,  # OWASP 2023+ recommendation
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def _get_or_create_salt(salt_path: Path) -> bytes:
    """Get existing salt or create new one.
    
    Salt is stored on disk - this is safe because:
    - Salt doesn't help decrypt without the passphrase
    - Salt prevents rainbow table attacks
    """
    if salt_path.exists():
        return salt_path.read_bytes()
    
    # Generate new random salt
    salt = os.urandom(32)
    salt_path.parent.mkdir(parents=True, exist_ok=True)
    salt_path.write_bytes(salt)
    salt_path.chmod(0o600)
    return salt


class SecretsManager:
    """Encrypted secrets storage using passphrase-derived encryption key.
    
    The passphrase is NEVER stored. You must provide it for every operation.
    """
    
    def __init__(self, config: SecretsConfig = None):
        self.config = config or SecretsConfig()
        self._salt: Optional[bytes] = None
    
    def _get_salt(self) -> bytes:
        """Get the salt for key derivation."""
        if self._salt is None:
            self._salt = _get_or_create_salt(self.config.salt_path)
        return self._salt
    
    def _get_fernet(self, passphrase: str) -> Fernet:
        """Get Fernet instance for given passphrase."""
        key = _derive_key(passphrase, self._get_salt())
        return Fernet(key)
    
    def _load_secrets(self, passphrase: str) -> dict:
        """Load and decrypt secrets from disk.
        
        Args:
            passphrase: Decryption passphrase
            
        Returns:
            Decrypted secrets dict
            
        Raises:
            InvalidToken: If passphrase is wrong
            FileNotFoundError: If no secrets file exists
        """
        if not self.config.secrets_path.exists():
            return {}
        
        encrypted_data = self.config.secrets_path.read_bytes()
        fernet = self._get_fernet(passphrase)
        
        try:
            decrypted_data = fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except InvalidToken:
            raise ValueError("Invalid passphrase — cannot decrypt secrets")
    
    def _save_secrets(self, secrets: dict, passphrase: str) -> None:
        """Encrypt and save secrets to disk.
        
        Args:
            secrets: Secrets dict to save
            passphrase: Encryption passphrase
        """
        self.config.secrets_path.parent.mkdir(parents=True, exist_ok=True)
        
        json_data = json.dumps(secrets, indent=2).encode()
        fernet = self._get_fernet(passphrase)
        encrypted_data = fernet.encrypt(json_data)
        
        # Atomic write with restricted permissions
        temp_path = self.config.secrets_path.with_suffix('.tmp')
        temp_path.write_bytes(encrypted_data)
        temp_path.chmod(0o600)
        temp_path.rename(self.config.secrets_path)
    
    def set(self, service: str, key: str, value: str, *, passphrase: str) -> None:
        """Store an encrypted secret.
        
        Args:
            service: Service name (e.g., "openrouter", "github")
            key: Secret key name (e.g., "api_key", "token")
            value: Secret value to store
            passphrase: Encryption passphrase (required)
        """
        try:
            secrets = self._load_secrets(passphrase)
        except ValueError:
            # Wrong passphrase for existing secrets
            raise
        except FileNotFoundError:
            secrets = {}
        
        if service not in secrets:
            secrets[service] = {}
        
        secrets[service][key] = value
        self._save_secrets(secrets, passphrase)
    
    def get(self, service: str, key: str, *, passphrase: str, default: str = None) -> Optional[str]:
        """Retrieve a decrypted secret.
        
        Args:
            service: Service name
            key: Secret key name
            passphrase: Decryption passphrase (required)
            default: Default value if not found
        
        Returns:
            Decrypted secret value or default
            
        Raises:
            ValueError: If passphrase is wrong
        """
        secrets = self._load_secrets(passphrase)
        return secrets.get(service, {}).get(key, default)
    
    def delete(self, service: str, key: str = None, *, passphrase: str) -> bool:
        """Delete a secret or entire service.
        
        Args:
            service: Service name
            key: Secret key name (if None, deletes entire service)
            passphrase: Decryption passphrase (required)
        
        Returns:
            True if something was deleted
        """
        secrets = self._load_secrets(passphrase)
        
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
        
        self._save_secrets(secrets, passphrase)
        return True
    
    def list_services(self, *, passphrase: str) -> list[str]:
        """List all services with stored secrets.
        
        Args:
            passphrase: Decryption passphrase (required)
        """
        secrets = self._load_secrets(passphrase)
        return list(secrets.keys())
    
    def list_keys(self, service: str, *, passphrase: str) -> list[str]:
        """List all keys for a service.
        
        Args:
            service: Service name
            passphrase: Decryption passphrase (required)
        """
        secrets = self._load_secrets(passphrase)
        return list(secrets.get(service, {}).keys())
    
    def has(self, service: str, key: str = None, *, passphrase: str) -> bool:
        """Check if a secret exists.
        
        Args:
            service: Service name
            key: Secret key name (if None, checks if service exists)
            passphrase: Decryption passphrase (required)
        """
        secrets = self._load_secrets(passphrase)
        
        if key is None:
            return service in secrets
        
        return key in secrets.get(service, {})
    
    def verify_passphrase(self, passphrase: str) -> bool:
        """Check if passphrase is correct.
        
        Args:
            passphrase: Passphrase to verify
            
        Returns:
            True if passphrase can decrypt secrets
        """
        try:
            self._load_secrets(passphrase)
            return True
        except (ValueError, FileNotFoundError):
            return False
    
    def change_passphrase(self, old_passphrase: str, new_passphrase: str) -> None:
        """Change the encryption passphrase.
        
        Decrypts with old passphrase, re-encrypts with new one.
        
        Args:
            old_passphrase: Current passphrase
            new_passphrase: New passphrase to use
        """
        # Load with old passphrase
        secrets = self._load_secrets(old_passphrase)
        
        # Generate new salt for new passphrase
        new_salt = os.urandom(32)
        self.config.salt_path.write_bytes(new_salt)
        self.config.salt_path.chmod(0o600)
        self._salt = new_salt
        
        # Save with new passphrase
        self._save_secrets(secrets, new_passphrase)


# Convenience functions for common use
def get_secret(service: str, key: str, *, passphrase: str, default: str = None) -> Optional[str]:
    """Quick access to a secret.
    
    Args:
        service: Service name
        key: Secret key name
        passphrase: Decryption passphrase (required)
        default: Default value if not found
    """
    return SecretsManager().get(service, key, passphrase=passphrase, default=default)


def set_secret(service: str, key: str, value: str, *, passphrase: str) -> None:
    """Quick store of a secret.
    
    Args:
        service: Service name
        key: Secret key name
        value: Secret value
        passphrase: Encryption passphrase (required)
    """
    SecretsManager().set(service, key, value, passphrase=passphrase)


def migrate_from_totp(totp_passphrase: str, new_passphrase: str) -> bool:
    """Migrate secrets from legacy TOTP-based encryption to passphrase-based.
    
    Args:
        totp_passphrase: The TOTP secret (for decrypting old secrets)
        new_passphrase: New passphrase to encrypt with
        
    Returns:
        True if migration succeeded
    """
    # Load old secrets with TOTP-derived key
    old_secrets_path = DEFAULT_SECRETS_PATH
    if not old_secrets_path.exists():
        return False
    
    # Derive old key from TOTP secret
    old_salt = b"airlock-secrets-v1"  # Legacy fixed salt
    old_kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=old_salt,
        iterations=100_000,  # Legacy iteration count
    )
    old_key = base64.urlsafe_b64encode(old_kdf.derive(totp_passphrase.encode()))
    old_fernet = Fernet(old_key)
    
    # Decrypt old secrets
    encrypted_data = old_secrets_path.read_bytes()
    try:
        decrypted_data = old_fernet.decrypt(encrypted_data)
        secrets = json.loads(decrypted_data.decode())
    except InvalidToken:
        raise ValueError("Invalid TOTP secret — cannot decrypt old secrets")
    
    # Backup old file
    backup_path = old_secrets_path.with_suffix('.enc.backup')
    old_secrets_path.rename(backup_path)
    
    # Create new salt and save with new passphrase
    manager = SecretsManager()
    manager._save_secrets(secrets, new_passphrase)
    
    return True
