"""Airlock Secrets Daemon — Holds decryption key in memory.

Security model:
- Passphrase entered via terminal → derives key → held in memory
- Never stored on disk, never transmitted over chat
- TOTP verification required for each secret access
- Key cleared on daemon stop or timeout

Usage:
    # Terminal: unlock the daemon
    airlock unlock
    
    # Code: get secret with TOTP verification
    secret = get_secret_with_totp("openrouter", "api_key", totp_code="482916")
"""

import asyncio
import base64
import json
import os
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from airlock.totp_verifier import TOTPGenerator

# Paths
DEFAULT_SOCKET_PATH = Path.home() / ".local" / "run" / "airlock" / "secrets.sock"
DEFAULT_SECRETS_PATH = Path.home() / ".local" / "share" / "airlock" / "secrets.enc"
DEFAULT_SALT_PATH = Path.home() / ".local" / "share" / "airlock" / "secrets.salt"
DEFAULT_TOTP_SECRET_PATH = Path.home() / ".local" / "share" / "airlock" / "totp_secret"


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive encryption key from passphrase."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


class SecretsDaemon:
    """Daemon that holds secrets decryption key in memory."""
    
    def __init__(
        self,
        socket_path: Path = DEFAULT_SOCKET_PATH,
        secrets_path: Path = DEFAULT_SECRETS_PATH,
        salt_path: Path = DEFAULT_SALT_PATH,
        totp_secret_path: Path = DEFAULT_TOTP_SECRET_PATH,
        key_timeout_minutes: int = 480,  # 8 hours default
    ):
        self.socket_path = socket_path
        self.secrets_path = secrets_path
        self.salt_path = salt_path
        self.totp_secret_path = totp_secret_path
        self.key_timeout_minutes = key_timeout_minutes
        
        self._key: Optional[bytes] = None
        self._key_set_at: Optional[float] = None
        self._totp: Optional[TOTPGenerator] = None
        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._lock = threading.Lock()
    
    def _load_totp(self) -> TOTPGenerator:
        """Load TOTP generator from secret file."""
        if self._totp is None:
            if not self.totp_secret_path.exists():
                raise FileNotFoundError(f"TOTP secret not found: {self.totp_secret_path}")
            totp_secret = self.totp_secret_path.read_text().strip()
            self._totp = TOTPGenerator.from_base32(totp_secret)
        return self._totp
    
    def _load_salt(self) -> bytes:
        """Load salt for key derivation."""
        if not self.salt_path.exists():
            raise FileNotFoundError(f"Salt file not found: {self.salt_path}")
        return self.salt_path.read_bytes()
    
    def _check_key_timeout(self) -> bool:
        """Check if key has timed out."""
        if self._key is None or self._key_set_at is None:
            return True
        
        elapsed_minutes = (time.time() - self._key_set_at) / 60
        if elapsed_minutes > self.key_timeout_minutes:
            self._key = None
            self._key_set_at = None
            return True
        return False
    
    def is_unlocked(self) -> bool:
        """Check if daemon has a valid key."""
        with self._lock:
            if self._check_key_timeout():
                return False
            return self._key is not None
    
    def unlock(self, passphrase: str) -> bool:
        """Unlock with passphrase - verify it can decrypt secrets."""
        try:
            salt = self._load_salt()
            key = _derive_key(passphrase, salt)
            
            # Verify key can decrypt secrets
            if self.secrets_path.exists():
                fernet = Fernet(key)
                encrypted = self.secrets_path.read_bytes()
                fernet.decrypt(encrypted)  # Will raise InvalidToken if wrong
            
            with self._lock:
                self._key = key
                self._key_set_at = time.time()
            
            return True
        except (InvalidToken, Exception):
            return False
    
    def lock(self) -> None:
        """Clear the key from memory."""
        with self._lock:
            self._key = None
            self._key_set_at = None
    
    def get_secret(self, service: str, key: str, totp_code: str) -> Optional[str]:
        """Get a secret with TOTP verification.
        
        Args:
            service: Service name
            key: Secret key
            totp_code: TOTP code for verification
            
        Returns:
            Secret value or None if verification fails
        """
        # Verify TOTP first
        totp = self._load_totp()
        if not totp.verify(totp_code):
            return None
        
        # Check key is available
        with self._lock:
            if self._check_key_timeout():
                return None
            if self._key is None:
                return None
            
            # Decrypt secrets
            try:
                fernet = Fernet(self._key)
                encrypted = self.secrets_path.read_bytes()
                decrypted = fernet.decrypt(encrypted)
                secrets = json.loads(decrypted.decode())
                return secrets.get(service, {}).get(key)
            except Exception:
                return None
    
    def _handle_client(self, conn: socket.socket) -> None:
        """Handle a client connection."""
        try:
            # Read message length (4 bytes)
            length_data = conn.recv(4)
            if not length_data:
                return
            
            length = struct.unpack(">I", length_data)[0]
            if length > 1024 * 1024:  # 1MB max
                conn.sendall(b'{"error": "Message too large"}')
                return
            
            # Read message
            data = b""
            while len(data) < length:
                chunk = conn.recv(min(4096, length - len(data)))
                if not chunk:
                    break
                data += chunk
            
            request = json.loads(data.decode())
            response = self._process_request(request)
            
            # Send response
            response_data = json.dumps(response).encode()
            conn.sendall(struct.pack(">I", len(response_data)))
            conn.sendall(response_data)
            
        except Exception as e:
            try:
                error_response = json.dumps({"error": str(e)}).encode()
                conn.sendall(struct.pack(">I", len(error_response)))
                conn.sendall(error_response)
            except:
                pass
        finally:
            conn.close()
    
    def _process_request(self, request: dict) -> dict:
        """Process a request."""
        action = request.get("action")
        
        if action == "status":
            return {
                "unlocked": self.is_unlocked(),
                "timeout_minutes": self.key_timeout_minutes,
            }
        
        elif action == "unlock":
            passphrase = request.get("passphrase")
            if not passphrase:
                return {"error": "Passphrase required"}
            
            if self.unlock(passphrase):
                return {"success": True}
            else:
                return {"error": "Invalid passphrase"}
        
        elif action == "lock":
            self.lock()
            return {"success": True}
        
        elif action == "get_secret":
            service = request.get("service")
            key = request.get("key")
            totp_code = request.get("totp_code")
            
            if not all([service, key, totp_code]):
                return {"error": "service, key, and totp_code required"}
            
            if not self.is_unlocked():
                return {"error": "Daemon is locked. Run 'airlock unlock' first."}
            
            secret = self.get_secret(service, key, totp_code)
            if secret is None:
                return {"error": "Invalid TOTP code or secret not found"}
            
            return {"secret": secret}
        
        else:
            return {"error": f"Unknown action: {action}"}
    
    def start(self) -> None:
        """Start the daemon server."""
        # Ensure socket directory exists
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Remove old socket if exists
        if self.socket_path.exists():
            self.socket_path.unlink()
        
        # Create socket
        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(str(self.socket_path))
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)  # For clean shutdown
        
        # Set permissions (owner only)
        self.socket_path.chmod(0o600)
        
        self._running = True
        
        while self._running:
            try:
                conn, _ = self._server_socket.accept()
                # Handle in thread for concurrent access
                thread = threading.Thread(target=self._handle_client, args=(conn,))
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    print(f"Socket error: {e}")
    
    def stop(self) -> None:
        """Stop the daemon."""
        self._running = False
        self.lock()  # Clear key
        
        if self._server_socket:
            self._server_socket.close()
        
        if self.socket_path.exists():
            self.socket_path.unlink()


class SecretsClient:
    """Client for communicating with the secrets daemon."""
    
    def __init__(self, socket_path: Path = DEFAULT_SOCKET_PATH):
        self.socket_path = socket_path
    
    def _send_request(self, request: dict) -> dict:
        """Send a request to the daemon."""
        if not self.socket_path.exists():
            return {"error": "Secrets daemon not running. Start with 'airlock start'"}
        
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(str(self.socket_path))
            sock.settimeout(30)
            
            # Send request
            data = json.dumps(request).encode()
            sock.sendall(struct.pack(">I", len(data)))
            sock.sendall(data)
            
            # Read response
            length_data = sock.recv(4)
            length = struct.unpack(">I", length_data)[0]
            
            response_data = b""
            while len(response_data) < length:
                chunk = sock.recv(min(4096, length - len(response_data)))
                if not chunk:
                    break
                response_data += chunk
            
            return json.loads(response_data.decode())
            
        except Exception as e:
            return {"error": str(e)}
        finally:
            sock.close()
    
    def status(self) -> dict:
        """Get daemon status."""
        return self._send_request({"action": "status"})
    
    def unlock(self, passphrase: str) -> dict:
        """Unlock the daemon."""
        return self._send_request({"action": "unlock", "passphrase": passphrase})
    
    def lock(self) -> dict:
        """Lock the daemon."""
        return self._send_request({"action": "lock"})
    
    def get_secret(self, service: str, key: str, totp_code: str) -> dict:
        """Get a secret with TOTP verification."""
        return self._send_request({
            "action": "get_secret",
            "service": service,
            "key": key,
            "totp_code": totp_code,
        })


# Convenience function for scripts
def get_secret_with_totp(
    service: str,
    key: str,
    totp_code: str,
    socket_path: Path = DEFAULT_SOCKET_PATH,
) -> Optional[str]:
    """Get a secret with TOTP verification.
    
    Args:
        service: Service name (e.g., "openrouter")
        key: Secret key (e.g., "api_key")
        totp_code: Current TOTP code
        socket_path: Path to daemon socket
        
    Returns:
        Secret value or None if verification fails or daemon locked
    """
    client = SecretsClient(socket_path)
    result = client.get_secret(service, key, totp_code)
    
    if "error" in result:
        return None
    
    return result.get("secret")
