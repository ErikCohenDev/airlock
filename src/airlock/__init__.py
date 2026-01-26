"""Airlock — Secure Access Gateway for AI Agents."""

from airlock.client import (
    AccessDeniedError,
    AirlockClient,
    AirlockClientSync,
    AirlockError,
    InvalidTokenError,
    ServiceError,
)
from airlock.gateway import (
    AccessGateway,
    AuditLogger,
    GatewayConfig,
    ServiceConnector,
    TOTPVerifierClient,
)
from airlock.models import (
    AccessRequest,
    AuditEntry,
    Permission,
    ServiceCredentials,
    Token,
    TokenStatus,
)
from airlock.totp_verifier import (
    IssuedToken,
    TOTPConfig,
    TOTPGenerator,
    TOTPVerifier,
)

__all__ = [
    # Client
    "AirlockClient",
    "AirlockClientSync",
    "AirlockError",
    "AccessDeniedError",
    "InvalidTokenError",
    "ServiceError",
    # Gateway
    "AccessGateway",
    "AuditLogger",
    "GatewayConfig",
    "ServiceConnector",
    "TOTPVerifierClient",
    # Models
    "AccessRequest",
    "AuditEntry",
    "Permission",
    "ServiceCredentials",
    "Token",
    "TokenStatus",
    # TOTP
    "IssuedToken",
    "TOTPConfig",
    "TOTPGenerator",
    "TOTPVerifier",
]

__version__ = "0.1.0"
