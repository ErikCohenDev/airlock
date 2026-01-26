"""Airlock — Secure Access Gateway for AI Agents."""

from airlock.client import AirlockClient, AirlockClientSync
from airlock.models import (
    AccessRequest,
    AuditEntry,
    GatewayConfig,
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
    "AirlockClient",
    "AirlockClientSync",
    "AccessRequest",
    "AuditEntry",
    "GatewayConfig",
    "IssuedToken",
    "Permission",
    "ServiceCredentials",
    "Token",
    "TokenStatus",
    "TOTPConfig",
    "TOTPGenerator",
    "TOTPVerifier",
]

__version__ = "0.1.0"
