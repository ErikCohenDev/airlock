"""Airlock Client — Interface for AI agents to request access."""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any


class AirlockError(Exception):
    """Base exception for Airlock errors."""
    pass


class AccessDeniedError(AirlockError):
    """Access was denied (TOTP failed or timed out)."""
    pass


class InvalidTokenError(AirlockError):
    """Token is invalid or expired."""
    pass


class ServiceError(AirlockError):
    """Error from a service connector."""
    pass


class AirlockClient:
    """Client for AI agents to request and use access tokens.
    
    Usage:
        async with AirlockClient() as airlock:
            # Request access (sends notification, waits for TOTP)
            await airlock.request_access(
                services=["gmail"],
                reason="Check for urgent emails"
            )
            
            # Execute operations
            messages = await airlock.execute(
                service="gmail",
                operation="list_messages",
                params={"limit": 10}
            )
            
        # Token auto-revoked on exit
    """
    
    GATEWAY_SOCKET = "/run/airlock/gateway.sock"
    
    def __init__(self, socket_path: str | Path | None = None):
        self.socket_path = Path(socket_path or self.GATEWAY_SOCKET)
        self._token: dict[str, Any] | None = None
        self._request_id: str | None = None
    
    async def __aenter__(self) -> "AirlockClient":
        return self
    
    async def __aexit__(self, *args: Any) -> None:
        await self.close()
    
    async def _send(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send a request to the gateway."""
        reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        
        try:
            writer.write(json.dumps(request).encode())
            await writer.drain()
            
            data = await reader.read(8192)
            response = json.loads(data.decode())
            
            if "error" in response:
                raise AirlockError(response["error"])
            
            return response
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def close(self) -> None:
        """Close connection and revoke token if active."""
        if self._token:
            await self.revoke_token()
    
    async def ping(self) -> dict[str, Any]:
        """Check gateway status."""
        return await self._send({"action": "ping"})
    
    async def list_services(self) -> dict[str, Any]:
        """List available services and operations."""
        response = await self._send({"action": "list_services"})
        return response.get("services", {})
    
    async def request_access(
        self,
        services: list[str],
        reason: str,
        ttl_minutes: int = 60,
        totp_code: str | None = None,
        wait_for_approval: bool = True,
        timeout: float = 300,
    ) -> dict[str, Any]:
        """Request access to services.
        
        This will:
        1. Send a notification to the user asking for TOTP approval
        2. If wait_for_approval=True and totp_code not provided, poll for approval
        3. Return the token on success
        
        Args:
            services: List of service names to access
            reason: Human-readable reason (shown in notification)
            ttl_minutes: How long the token should be valid
            totp_code: If provided, verify immediately (skip waiting)
            wait_for_approval: If True, block until approved/denied/timeout
            timeout: Seconds to wait for approval
            
        Returns:
            Token dict with token_id, services, expires_at
            
        Raises:
            AccessDeniedError: If TOTP verification fails or times out
        """
        # Step 1: Create access request
        response = await self._send({
            "action": "request_access",
            "services": services,
            "reason": reason,
            "ttl_minutes": ttl_minutes,
        })
        
        self._request_id = response["request_id"]
        
        # Step 2: Verify TOTP
        if totp_code:
            # Immediate verification
            return await self.verify(totp_code)
        
        if not wait_for_approval:
            # Return request_id, caller will verify later
            return {"request_id": self._request_id, "status": "pending"}
        
        # Step 3: Wait for user to provide TOTP via notification response
        # In a real implementation, this would poll or use webhooks
        # For now, raise to indicate manual verification needed
        raise NotImplementedError(
            f"Awaiting TOTP approval. Request ID: {self._request_id}\n"
            "Call client.verify(totp_code) with the code from your authenticator."
        )
    
    async def verify(self, totp_code: str) -> dict[str, Any]:
        """Verify TOTP code and get access token.
        
        Args:
            totp_code: 6-digit TOTP code from authenticator app
            
        Returns:
            Token dict
            
        Raises:
            AccessDeniedError: If verification fails
        """
        if not self._request_id:
            raise AirlockError("No pending access request. Call request_access first.")
        
        try:
            response = await self._send({
                "action": "verify",
                "request_id": self._request_id,
                "totp_code": totp_code,
            })
        except AirlockError as e:
            raise AccessDeniedError(str(e)) from e
        
        self._token = response["token"]
        self._request_id = None
        return self._token
    
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
            Operation result
            
        Raises:
            InvalidTokenError: If token is expired or invalid
            ServiceError: If operation fails
        """
        if not self._token:
            raise InvalidTokenError("No valid token. Call request_access and verify first.")
        
        try:
            response = await self._send({
                "action": "execute",
                "token_id": self._token["token_id"],
                "service": service,
                "operation": operation,
                "params": params or {},
            })
        except AirlockError as e:
            if "token" in str(e).lower():
                raise InvalidTokenError(str(e)) from e
            raise ServiceError(str(e)) from e
        
        return response.get("result")
    
    async def revoke_token(self) -> bool:
        """Explicitly revoke the current token."""
        if not self._token:
            return False
        
        try:
            response = await self._send({
                "action": "revoke",
                "token_id": self._token["token_id"],
            })
            self._token = None
            return response.get("revoked", False)
        except Exception:
            self._token = None
            return False
    
    @property
    def token(self) -> dict[str, Any] | None:
        """Current access token, if any."""
        return self._token
    
    @property
    def has_valid_token(self) -> bool:
        """Check if we have a token (doesn't verify with server)."""
        if not self._token:
            return False
        
        # Check local expiry
        expires_at = self._token.get("expires_at")
        if expires_at:
            from datetime import timezone
            exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > exp:
                return False
        
        return True


class AirlockClientSync:
    """Synchronous wrapper for AirlockClient."""
    
    def __init__(self, socket_path: str | Path | None = None):
        self._async_client = AirlockClient(socket_path)
        self._loop: asyncio.AbstractEventLoop | None = None
    
    def _get_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
        return self._loop
    
    def __enter__(self) -> "AirlockClientSync":
        return self
    
    def __exit__(self, *args: Any) -> None:
        self._get_loop().run_until_complete(self._async_client.close())
    
    def ping(self) -> dict[str, Any]:
        return self._get_loop().run_until_complete(self._async_client.ping())
    
    def list_services(self) -> dict[str, Any]:
        return self._get_loop().run_until_complete(self._async_client.list_services())
    
    def request_access(
        self,
        services: list[str],
        reason: str,
        ttl_minutes: int = 60,
        totp_code: str | None = None,
    ) -> dict[str, Any]:
        return self._get_loop().run_until_complete(
            self._async_client.request_access(
                services, reason, ttl_minutes, totp_code, wait_for_approval=False
            )
        )
    
    def verify(self, totp_code: str) -> dict[str, Any]:
        return self._get_loop().run_until_complete(self._async_client.verify(totp_code))
    
    def execute(
        self,
        service: str,
        operation: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        return self._get_loop().run_until_complete(
            self._async_client.execute(service, operation, params)
        )
    
    def revoke_token(self) -> bool:
        return self._get_loop().run_until_complete(self._async_client.revoke_token())
    
    @property
    def token(self) -> dict[str, Any] | None:
        return self._async_client.token
    
    @property
    def has_valid_token(self) -> bool:
        return self._async_client.has_valid_token
