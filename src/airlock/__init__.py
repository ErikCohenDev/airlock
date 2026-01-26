"""SAG — Secure Access Gateway for AI Agents.

Human-in-the-loop access control for AI agents.
Your assistant asks, you approve with TOTP, access auto-expires.
"""

__version__ = "0.1.0"

from airlock.client import SAGClient
from airlock.models import Token, AccessRequest, AuditEntry

__all__ = ["SAGClient", "Token", "AccessRequest", "AuditEntry"]
