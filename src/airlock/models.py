"""Core data models for Airlock."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Permission(str, Enum):
    """Access permission levels."""
    READ = "read"
    WRITE = "write"  # Future


class TokenStatus(str, Enum):
    """Token lifecycle status."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Token(BaseModel):
    """Access token issued after TOTP verification."""
    id: str = Field(description="Unique token identifier")
    issued_at: datetime
    expires_at: datetime
    services: list[str] = Field(description="Services this token can access")
    permissions: list[Permission] = Field(default=[Permission.READ])
    status: TokenStatus = TokenStatus.ACTIVE
    request_reason: str | None = Field(default=None, description="Why access was requested")
    audit_id: str = Field(description="Links to audit trail")
    
    @property
    def is_valid(self) -> bool:
        """Check if token is currently valid."""
        return (
            self.status == TokenStatus.ACTIVE 
            and datetime.utcnow() < self.expires_at
        )
    
    def can_access(self, service: str) -> bool:
        """Check if token grants access to a service."""
        return self.is_valid and service in self.services


class AccessRequest(BaseModel):
    """Request for access to services."""
    id: str
    requested_at: datetime
    services: list[str]
    reason: str
    ttl_minutes: int = 60
    status: str = "pending"  # pending, approved, denied, expired
    token_id: str | None = None


class AuditEntry(BaseModel):
    """Audit log entry."""
    id: str
    timestamp: datetime
    event: str  # token_requested, totp_verified, operation, token_expired, etc.
    token_id: str | None = None
    service: str | None = None
    operation: str | None = None
    params: dict[str, Any] | None = None
    result: str | None = None  # success, error
    error_message: str | None = None
    data: dict[str, Any] | None = None


class ServiceCredentials(BaseModel):
    """Credentials for a service (stored encrypted)."""
    service: str
    type: str  # imap, oauth, api_key, etc.
    config: dict[str, Any]  # Service-specific config (host, port, etc.)
    # Note: Actual secrets stored separately in encrypted storage


class GatewayConfig(BaseModel):
    """Configuration for Airlock gateway."""
    totp_issuer: str = "Airlock"
    totp_digits: int = 6
    totp_period: int = 30
    default_token_ttl_minutes: int = 60
    max_token_ttl_minutes: int = 480
    notification_provider: str = "telegram"
    notification_config: dict[str, Any] = {}
    default_permissions: list[Permission] = [Permission.READ]
