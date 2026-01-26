"""SAG Client — Interface for AI agents to request access."""

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from airlock.models import Token, AccessRequest


class SAGClient:
    """Client for AI agents to request and use access tokens.
    
    Usage:
        async with SAGClient() as sag:
            token = await sag.request_access(
                services=["gmail"],
                reason="Check for urgent emails"
            )
            messages = await sag.execute(
                service="gmail",
                operation="list_messages",
                params={"limit": 10}
            )
    """
    
    GATEWAY_SOCKET = "/run/sag/gateway.sock"
    TOTP_SOCKET = "/run/sag/totp.sock"
    
    def __init__(self, socket_path: str | None = None):
        self.socket_path = socket_path or self.GATEWAY_SOCKET
        self._token: Token | None = None
        self._connected = False
    
    async def __aenter__(self) -> "SAGClient":
        await self.connect()
        return self
    
    async def __aexit__(self, *args: Any) -> None:
        await self.close()
    
    async def connect(self) -> None:
        """Connect to the SAG gateway."""
        # TODO: Implement Unix socket connection
        self._connected = True
    
    async def close(self) -> None:
        """Close connection and revoke token if active."""
        if self._token and self._token.is_valid:
            await self.revoke_token()
        self._connected = False
    
    async def request_access(
        self,
        services: list[str],
        reason: str,
        ttl_minutes: int = 60,
    ) -> Token:
        """Request access to services. Sends notification for TOTP approval.
        
        This will:
        1. Send a notification to the user (Telegram, etc.)
        2. Wait for them to reply with a TOTP code
        3. Verify the code and issue a token
        4. Return the token for subsequent operations
        
        Args:
            services: List of service names to access (e.g., ["gmail", "calendar"])
            reason: Human-readable reason for access (shown in notification)
            ttl_minutes: How long the token should be valid
            
        Returns:
            Token object if approved
            
        Raises:
            AccessDeniedError: If TOTP verification fails or times out
        """
        # TODO: Implement actual socket communication
        # For now, this is a stub
        
        request = AccessRequest(
            id=f"req_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            requested_at=datetime.utcnow(),
            services=services,
            reason=reason,
            ttl_minutes=ttl_minutes,
        )
        
        # This would:
        # 1. Send request to TOTP verifier
        # 2. Verifier sends Telegram notification
        # 3. Wait for TOTP code response
        # 4. Verify and issue token
        
        raise NotImplementedError("SAG gateway not yet implemented")
    
    async def execute(
        self,
        service: str,
        operation: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Execute a read operation on a service.
        
        Args:
            service: Service name (e.g., "gmail")
            operation: Operation name (e.g., "list_messages")
            params: Operation parameters
            
        Returns:
            Operation result (varies by operation)
            
        Raises:
            InvalidTokenError: If token is expired or invalid
            PermissionDeniedError: If operation not allowed
        """
        if not self._token or not self._token.is_valid:
            raise RuntimeError("No valid token. Call request_access() first.")
        
        if not self._token.can_access(service):
            raise PermissionError(f"Token does not grant access to {service}")
        
        # TODO: Implement actual socket communication
        raise NotImplementedError("SAG gateway not yet implemented")
    
    async def revoke_token(self) -> None:
        """Explicitly revoke the current token."""
        if self._token:
            # TODO: Send revoke request to gateway
            self._token = None


class SAGClientSync:
    """Synchronous wrapper for SAGClient."""
    
    def __init__(self, socket_path: str | None = None):
        self._async_client = SAGClient(socket_path)
    
    def __enter__(self) -> "SAGClientSync":
        asyncio.get_event_loop().run_until_complete(self._async_client.connect())
        return self
    
    def __exit__(self, *args: Any) -> None:
        asyncio.get_event_loop().run_until_complete(self._async_client.close())
    
    def request_access(
        self,
        services: list[str],
        reason: str,
        ttl_minutes: int = 60,
    ) -> Token:
        return asyncio.get_event_loop().run_until_complete(
            self._async_client.request_access(services, reason, ttl_minutes)
        )
    
    def execute(
        self,
        service: str,
        operation: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        return asyncio.get_event_loop().run_until_complete(
            self._async_client.execute(service, operation, params)
        )
