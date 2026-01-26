"""Tests for TOTP Verifier daemon."""

import asyncio
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from airlock.totp_verifier import (
    ConsoleNotificationProvider,
    IssuedToken,
    PendingRequest,
    TOTPConfig,
    TOTPGenerator,
    TOTPVerifier,
)


class TestPendingRequest:
    """Test PendingRequest model."""
    
    def test_not_expired_when_fresh(self):
        req = PendingRequest(
            request_id="req_test",
            services=["gmail"],
            reason="test",
            ttl_minutes=60,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5),
        )
        assert not req.is_expired()
    
    def test_expired_when_past(self):
        req = PendingRequest(
            request_id="req_test",
            services=["gmail"],
            reason="test",
            ttl_minutes=60,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=10),
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=5),
        )
        assert req.is_expired()


class TestIssuedToken:
    """Test IssuedToken model."""
    
    def test_valid_when_not_expired(self):
        token = IssuedToken(
            token_id="tok_test",
            request_id="req_test",
            services=["gmail"],
            issued_at=datetime.now(timezone.utc).replace(tzinfo=None),
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=60),
        )
        assert token.is_valid()
    
    def test_invalid_when_expired(self):
        token = IssuedToken(
            token_id="tok_test",
            request_id="req_test",
            services=["gmail"],
            issued_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=120),
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=60),
        )
        assert not token.is_valid()
    
    def test_to_dict(self):
        token = IssuedToken(
            token_id="tok_test",
            request_id="req_test",
            services=["gmail", "calendar"],
            issued_at=datetime.now(timezone.utc).replace(tzinfo=None),
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=60),
        )
        d = token.to_dict()
        assert d["token_id"] == "tok_test"
        assert d["services"] == ["gmail", "calendar"]
        assert "issued_at" in d
        assert "expires_at" in d


class TestTOTPVerifier:
    """Test TOTP Verifier daemon logic."""
    
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)
    
    @pytest.fixture
    def verifier(self, temp_dir):
        config = TOTPConfig(
            secret_path=temp_dir / "secret",
            socket_path=temp_dir / "totp.sock",
        )
        return TOTPVerifier(config, ConsoleNotificationProvider())
    
    def test_generates_secret_on_first_load(self, verifier, temp_dir):
        """Secret file is created on first access."""
        assert not (temp_dir / "secret").exists()
        uri = verifier.get_setup_uri()
        assert (temp_dir / "secret").exists()
        assert "otpauth://totp/" in uri
    
    def test_loads_existing_secret(self, verifier, temp_dir):
        """Existing secret is loaded, not overwritten."""
        # Create a known secret
        secret = TOTPGenerator.generate_secret()
        totp = TOTPGenerator(secret)
        (temp_dir / "secret").parent.mkdir(parents=True, exist_ok=True)
        (temp_dir / "secret").write_text(totp.get_secret_base32())
        
        # Load it
        uri = verifier.get_setup_uri()
        assert totp.get_secret_base32() in uri
    
    @pytest.mark.asyncio
    async def test_request_access_creates_pending(self, verifier):
        """request_access creates a pending request."""
        request_id = await verifier.request_access(
            services=["gmail"],
            reason="test access",
            ttl_minutes=30,
        )
        
        assert request_id.startswith("req_")
        assert request_id in verifier._pending_requests
        
        req = verifier._pending_requests[request_id]
        assert req.services == ["gmail"]
        assert req.reason == "test access"
        assert req.ttl_minutes == 30
    
    @pytest.mark.asyncio
    async def test_verify_issues_token(self, verifier):
        """Valid TOTP code issues a token."""
        # Initialize TOTP
        verifier.get_setup_uri()
        
        # Create request
        request_id = await verifier.request_access(
            services=["gmail"],
            reason="test",
        )
        
        # Get valid code
        code = verifier._totp.generate()
        
        # Verify
        token = await verifier.verify_and_issue_token(request_id, code)
        
        assert token is not None
        assert token.token_id.startswith("tok_")
        assert token.services == ["gmail"]
        assert token.is_valid()
        
        # Request should be consumed
        assert request_id not in verifier._pending_requests
        
        # Token should be stored
        assert token.token_id in verifier._issued_tokens
    
    @pytest.mark.asyncio
    async def test_verify_rejects_wrong_code(self, verifier):
        """Wrong TOTP code is rejected."""
        verifier.get_setup_uri()
        
        request_id = await verifier.request_access(
            services=["gmail"],
            reason="test",
        )
        
        token = await verifier.verify_and_issue_token(request_id, "000000")
        
        assert token is None
        # Request should still be pending (can retry)
        assert request_id in verifier._pending_requests
    
    @pytest.mark.asyncio
    async def test_verify_rejects_unknown_request(self, verifier):
        """Unknown request ID is rejected."""
        verifier.get_setup_uri()
        
        token = await verifier.verify_and_issue_token("req_nonexistent", "123456")
        assert token is None
    
    def test_validate_token_for_service(self, verifier):
        """validate_token checks service access."""
        token = IssuedToken(
            token_id="tok_test",
            request_id="req_test",
            services=["gmail"],
            issued_at=datetime.now(timezone.utc).replace(tzinfo=None),
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=60),
        )
        verifier._issued_tokens[token.token_id] = token
        
        assert verifier.validate_token("tok_test", "gmail")
        assert not verifier.validate_token("tok_test", "calendar")
        assert not verifier.validate_token("tok_nonexistent", "gmail")
    
    def test_revoke_token(self, verifier):
        """revoke_token removes the token."""
        token = IssuedToken(
            token_id="tok_test",
            request_id="req_test",
            services=["gmail"],
            issued_at=datetime.now(timezone.utc).replace(tzinfo=None),
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=60),
        )
        verifier._issued_tokens[token.token_id] = token
        
        assert verifier.revoke_token("tok_test")
        assert "tok_test" not in verifier._issued_tokens
        assert not verifier.revoke_token("tok_test")  # Already gone
    
    def test_ttl_capped_at_max(self, verifier):
        """Token TTL is capped at max_token_ttl_minutes."""
        verifier.config.max_token_ttl_minutes = 120
        
        # Request with TTL exceeding max
        asyncio.run(verifier.request_access(
            services=["gmail"],
            reason="test",
            ttl_minutes=999,
        ))
        
        # Check the stored request has capped TTL
        req = list(verifier._pending_requests.values())[0]
        assert req.ttl_minutes == 120
