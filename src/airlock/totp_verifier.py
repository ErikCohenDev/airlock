"""TOTP Verifier Daemon — Core security component of Airlock.

This daemon:
- Owns the TOTP secret (inaccessible to other users)
- Listens on a Unix socket for access requests
- Sends notifications asking for TOTP approval
- Validates TOTP codes and issues time-limited tokens
- Runs as isolated user 'airlock-totp'
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import time
from base64 import b32decode, b32encode
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TOTPConfig:
    """TOTP configuration."""
    issuer: str = "Airlock"
    account: str = "agent"
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"
    secret_path: Path = field(default_factory=lambda: Path("/var/lib/airlock-totp/secret"))
    socket_path: Path = field(default_factory=lambda: Path("/run/airlock/totp.sock"))
    token_ttl_minutes: int = 60
    max_token_ttl_minutes: int = 480
    # Allow codes from 1 period before/after to handle clock drift
    allowed_drift: int = 1


@dataclass
class PendingRequest:
    """Access request awaiting TOTP approval."""
    request_id: str
    services: list[str]
    reason: str
    ttl_minutes: int
    created_at: datetime
    expires_at: datetime  # Request expires if not approved
    
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc).replace(tzinfo=None) > self.expires_at


@dataclass  
class IssuedToken:
    """Token issued after TOTP verification."""
    token_id: str
    request_id: str
    services: list[str]
    issued_at: datetime
    expires_at: datetime
    
    def is_valid(self) -> bool:
        return datetime.now(timezone.utc).replace(tzinfo=None) < self.expires_at
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "request_id": self.request_id,
            "services": self.services,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }


class TOTPGenerator:
    """RFC 6238 TOTP implementation."""
    
    def __init__(self, secret: bytes, digits: int = 6, period: int = 30):
        self.secret = secret
        self.digits = digits
        self.period = period
    
    @classmethod
    def generate_secret(cls, length: int = 20) -> bytes:
        """Generate a cryptographically secure random secret."""
        return secrets.token_bytes(length)
    
    @classmethod
    def from_base32(cls, secret_b32: str, **kwargs) -> "TOTPGenerator":
        """Create from base32-encoded secret."""
        # Remove spaces and convert to uppercase for flexibility
        secret_b32 = secret_b32.replace(" ", "").upper()
        # Pad if necessary
        padding = 8 - (len(secret_b32) % 8)
        if padding != 8:
            secret_b32 += "=" * padding
        return cls(b32decode(secret_b32), **kwargs)
    
    def get_secret_base32(self) -> str:
        """Get base32-encoded secret (for QR codes)."""
        return b32encode(self.secret).decode().rstrip("=")
    
    def _hotp(self, counter: int) -> str:
        """Generate HOTP code for counter value."""
        counter_bytes = struct.pack(">Q", counter)
        hmac_hash = hmac.new(self.secret, counter_bytes, "sha1").digest()
        
        # Dynamic truncation
        offset = hmac_hash[-1] & 0x0F
        truncated = struct.unpack(">I", hmac_hash[offset:offset + 4])[0]
        truncated &= 0x7FFFFFFF
        
        code = truncated % (10 ** self.digits)
        return str(code).zfill(self.digits)
    
    def generate(self, timestamp: float | None = None) -> str:
        """Generate TOTP code for current (or given) time."""
        if timestamp is None:
            timestamp = time.time()
        counter = int(timestamp) // self.period
        return self._hotp(counter)
    
    def verify(self, code: str, timestamp: float | None = None, drift: int = 1) -> bool:
        """Verify TOTP code, allowing for clock drift.
        
        Args:
            code: The TOTP code to verify
            timestamp: Unix timestamp (defaults to now)
            drift: Number of periods before/after to accept
        
        Returns:
            True if code is valid
        """
        if timestamp is None:
            timestamp = time.time()
        
        code = code.strip()
        if len(code) != self.digits:
            return False
        
        counter = int(timestamp) // self.period
        
        for offset in range(-drift, drift + 1):
            expected = self._hotp(counter + offset)
            if hmac.compare_digest(code, expected):
                return True
        
        return False
    
    def get_uri(self, issuer: str, account: str) -> str:
        """Generate otpauth:// URI for QR code."""
        secret_b32 = self.get_secret_base32()
        return (
            f"otpauth://totp/{issuer}:{account}"
            f"?secret={secret_b32}"
            f"&issuer={issuer}"
            f"&digits={self.digits}"
            f"&period={self.period}"
        )


class NotificationProvider:
    """Base class for notification providers."""
    
    async def send_approval_request(
        self,
        request_id: str,
        services: list[str],
        reason: str,
    ) -> None:
        """Send notification asking for TOTP approval."""
        raise NotImplementedError
    
    async def send_token_issued(self, token_id: str, expires_at: datetime) -> None:
        """Notify that token was issued."""
        raise NotImplementedError


class ConsoleNotificationProvider(NotificationProvider):
    """Debug notification provider that prints to console."""
    
    async def send_approval_request(
        self,
        request_id: str,
        services: list[str],
        reason: str,
    ) -> None:
        print(f"\n{'='*50}")
        print("ACCESS REQUEST")
        print(f"{'='*50}")
        print(f"Request ID: {request_id}")
        print(f"Services:   {', '.join(services)}")
        print(f"Reason:     {reason}")
        print(f"{'='*50}")
        print("Enter TOTP code to approve")
        print(f"{'='*50}\n")
    
    async def send_token_issued(self, token_id: str, expires_at: datetime) -> None:
        print(f"\nAccess granted. Token expires at {expires_at.isoformat()}\n")


class TelegramNotificationProvider(NotificationProvider):
    """Telegram notification provider."""
    
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self._base_url = f"https://api.telegram.org/bot{bot_token}"
    
    async def _send_message(self, text: str) -> None:
        """Send a Telegram message."""
        import aiohttp
        
        url = f"{self._base_url}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to send Telegram message: {await resp.text()}")
    
    async def send_approval_request(
        self,
        request_id: str,
        services: list[str],
        reason: str,
    ) -> None:
        text = (
            f"*Airlock Access Request*\n\n"
            f"Services: `{', '.join(services)}`\n"
            f"Reason: {reason}\n\n"
            f"Reply with your TOTP code to approve."
        )
        await self._send_message(text)
    
    async def send_token_issued(self, token_id: str, expires_at: datetime) -> None:
        text = f"Access granted. Expires at {expires_at.strftime('%H:%M:%S')}."
        await self._send_message(text)


class TOTPVerifier:
    """TOTP Verifier Daemon.
    
    Handles access requests, TOTP verification, and token issuance.
    Communicates via Unix socket.
    """
    
    def __init__(
        self,
        config: TOTPConfig,
        notification_provider: NotificationProvider | None = None,
    ):
        self.config = config
        self.notification = notification_provider or ConsoleNotificationProvider()
        self._totp: TOTPGenerator | None = None
        self._pending_requests: dict[str, PendingRequest] = {}
        self._issued_tokens: dict[str, IssuedToken] = {}
        self._server: asyncio.Server | None = None
    
    def _load_or_create_secret(self) -> TOTPGenerator:
        """Load existing secret or create new one."""
        secret_path = self.config.secret_path
        
        if secret_path.exists():
            secret_b32 = secret_path.read_text().strip()
            logger.info("Loaded existing TOTP secret")
            return TOTPGenerator.from_base32(
                secret_b32,
                digits=self.config.digits,
                period=self.config.period,
            )
        
        # Generate new secret
        totp = TOTPGenerator(
            TOTPGenerator.generate_secret(),
            digits=self.config.digits,
            period=self.config.period,
        )
        
        # Ensure directory exists with proper permissions
        secret_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(secret_path.parent, 0o700)
        
        # Write secret
        secret_path.write_text(totp.get_secret_base32())
        os.chmod(secret_path, 0o600)
        
        logger.info(f"Generated new TOTP secret at {secret_path}")
        return totp
    
    def get_setup_uri(self) -> str:
        """Get otpauth:// URI for setting up authenticator app."""
        if self._totp is None:
            self._totp = self._load_or_create_secret()
        return self._totp.get_uri(self.config.issuer, self.config.account)
    
    def _generate_id(self, prefix: str = "") -> str:
        """Generate a unique ID."""
        random_part = secrets.token_hex(8)
        return f"{prefix}{random_part}"
    
    async def request_access(
        self,
        services: list[str],
        reason: str,
        ttl_minutes: int | None = None,
    ) -> str:
        """Create a new access request.
        
        Returns:
            Request ID to use when submitting TOTP code
        """
        ttl = min(
            ttl_minutes or self.config.token_ttl_minutes,
            self.config.max_token_ttl_minutes,
        )
        
        request = PendingRequest(
            request_id=self._generate_id("req_"),
            services=services,
            reason=reason,
            ttl_minutes=ttl,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5),  # 5 min to respond
        )
        
        self._pending_requests[request.request_id] = request
        
        # Send notification
        await self.notification.send_approval_request(
            request.request_id,
            services,
            reason,
        )
        
        logger.info(f"Created access request {request.request_id} for {services}")
        return request.request_id
    
    async def verify_and_issue_token(
        self,
        request_id: str,
        totp_code: str,
    ) -> IssuedToken | None:
        """Verify TOTP and issue token if valid.
        
        Returns:
            IssuedToken if successful, None if verification failed
        """
        request = self._pending_requests.get(request_id)
        
        if request is None:
            logger.warning(f"Unknown request ID: {request_id}")
            return None
        
        if request.is_expired():
            logger.warning(f"Request {request_id} has expired")
            del self._pending_requests[request_id]
            return None
        
        # Verify TOTP
        if self._totp is None:
            self._totp = self._load_or_create_secret()
        
        if not self._totp.verify(totp_code, drift=self.config.allowed_drift):
            logger.warning(f"Invalid TOTP code for request {request_id}")
            return None
        
        # Issue token
        token = IssuedToken(
            token_id=self._generate_id("tok_"),
            request_id=request_id,
            services=request.services,
            issued_at=datetime.now(timezone.utc).replace(tzinfo=None),
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=request.ttl_minutes),
        )
        
        self._issued_tokens[token.token_id] = token
        del self._pending_requests[request_id]
        
        # Notify
        await self.notification.send_token_issued(token.token_id, token.expires_at)
        
        logger.info(f"Issued token {token.token_id} for request {request_id}")
        return token
    
    def validate_token(self, token_id: str, service: str) -> bool:
        """Check if a token is valid for a given service."""
        token = self._issued_tokens.get(token_id)
        if token is None:
            return False
        if not token.is_valid():
            return False
        if service not in token.services:
            return False
        return True
    
    def revoke_token(self, token_id: str) -> bool:
        """Revoke a token."""
        if token_id in self._issued_tokens:
            del self._issued_tokens[token_id]
            logger.info(f"Revoked token {token_id}")
            return True
        return False
    
    def _cleanup_expired(self) -> None:
        """Remove expired requests and tokens."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        
        expired_requests = [
            rid for rid, req in self._pending_requests.items()
            if req.is_expired()
        ]
        for rid in expired_requests:
            del self._pending_requests[rid]
        
        expired_tokens = [
            tid for tid, tok in self._issued_tokens.items()
            if not tok.is_valid()
        ]
        for tid in expired_tokens:
            del self._issued_tokens[tid]
    
    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a client connection on the Unix socket."""
        try:
            data = await reader.read(4096)
            if not data:
                return
            
            try:
                request = json.loads(data.decode())
            except json.JSONDecodeError:
                response = {"error": "Invalid JSON"}
                writer.write(json.dumps(response).encode())
                await writer.drain()
                return
            
            action = request.get("action")
            response: dict[str, Any]
            
            if action == "request_access":
                request_id = await self.request_access(
                    services=request.get("services", []),
                    reason=request.get("reason", ""),
                    ttl_minutes=request.get("ttl_minutes"),
                )
                response = {"request_id": request_id}
            
            elif action == "verify":
                token = await self.verify_and_issue_token(
                    request_id=request.get("request_id", ""),
                    totp_code=request.get("totp_code", ""),
                )
                if token:
                    response = {"token": token.to_dict()}
                else:
                    response = {"error": "Verification failed"}
            
            elif action == "validate":
                valid = self.validate_token(
                    token_id=request.get("token_id", ""),
                    service=request.get("service", ""),
                )
                response = {"valid": valid}
            
            elif action == "revoke":
                revoked = self.revoke_token(request.get("token_id", ""))
                response = {"revoked": revoked}
            
            elif action == "ping":
                response = {"status": "ok"}
            
            else:
                response = {"error": f"Unknown action: {action}"}
            
            writer.write(json.dumps(response).encode())
            await writer.drain()
        
        except Exception as e:
            logger.exception("Error handling client")
            try:
                writer.write(json.dumps({"error": str(e)}).encode())
                await writer.drain()
            except Exception:
                pass
        
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def start(self) -> None:
        """Start the TOTP verifier daemon."""
        # Load/create secret
        self._totp = self._load_or_create_secret()
        
        # Ensure socket directory exists
        socket_path = self.config.socket_path
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Remove stale socket
        if socket_path.exists():
            socket_path.unlink()
        
        # Start server
        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=str(socket_path),
        )
        
        # Set socket permissions (allow gateway user to connect)
        os.chmod(socket_path, 0o660)
        
        logger.info(f"TOTP verifier listening on {socket_path}")
        
        # Periodic cleanup task
        async def cleanup_loop():
            while True:
                await asyncio.sleep(60)
                self._cleanup_expired()
        
        asyncio.create_task(cleanup_loop())
        
        async with self._server:
            await self._server.serve_forever()
    
    async def stop(self) -> None:
        """Stop the daemon."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()


async def main():
    """Run the TOTP verifier daemon."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Airlock TOTP Verifier Daemon")
    parser.add_argument(
        "--socket",
        default="/run/airlock/totp.sock",
        help="Unix socket path",
    )
    parser.add_argument(
        "--secret-path",
        default="/var/lib/airlock-totp/secret",
        help="Path to TOTP secret file",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    
    config = TOTPConfig(
        socket_path=Path(args.socket),
        secret_path=Path(args.secret_path),
    )
    
    verifier = TOTPVerifier(config)
    
    try:
        await verifier.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        await verifier.stop()


if __name__ == "__main__":
    asyncio.run(main())
