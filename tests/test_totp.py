"""Tests for TOTP implementation."""

import time
from airlock.totp_verifier import TOTPGenerator


class TestTOTPGenerator:
    """Test RFC 6238 TOTP implementation."""
    
    def test_generate_secret(self):
        """Secret generation produces 20 bytes."""
        secret = TOTPGenerator.generate_secret()
        assert len(secret) == 20
    
    def test_secret_is_random(self):
        """Each generated secret is unique."""
        secrets = [TOTPGenerator.generate_secret() for _ in range(10)]
        assert len(set(secrets)) == 10
    
    def test_base32_roundtrip(self):
        """Secret survives base32 encode/decode."""
        totp = TOTPGenerator(TOTPGenerator.generate_secret())
        b32 = totp.get_secret_base32()
        totp2 = TOTPGenerator.from_base32(b32)
        assert totp.secret == totp2.secret
    
    def test_code_length(self):
        """Generated codes have correct length."""
        totp = TOTPGenerator(TOTPGenerator.generate_secret(), digits=6)
        code = totp.generate()
        assert len(code) == 6
        assert code.isdigit()
    
    def test_code_is_deterministic(self):
        """Same secret + timestamp = same code."""
        secret = TOTPGenerator.generate_secret()
        totp1 = TOTPGenerator(secret)
        totp2 = TOTPGenerator(secret)
        
        timestamp = time.time()
        assert totp1.generate(timestamp) == totp2.generate(timestamp)
    
    def test_code_changes_with_time(self):
        """Code changes between periods."""
        totp = TOTPGenerator(TOTPGenerator.generate_secret(), period=30)
        
        # Two codes 60 seconds apart should differ
        code1 = totp.generate(1000000)
        code2 = totp.generate(1000060)
        assert code1 != code2
    
    def test_verify_correct_code(self):
        """Correct code verifies."""
        totp = TOTPGenerator(TOTPGenerator.generate_secret())
        timestamp = time.time()
        code = totp.generate(timestamp)
        assert totp.verify(code, timestamp)
    
    def test_verify_wrong_code(self):
        """Wrong code fails."""
        totp = TOTPGenerator(TOTPGenerator.generate_secret())
        assert not totp.verify("000000")
        assert not totp.verify("123456")
    
    def test_verify_with_drift(self):
        """Code from adjacent period verifies with drift."""
        totp = TOTPGenerator(TOTPGenerator.generate_secret(), period=30)
        timestamp = 1000000
        
        # Code from previous period
        prev_code = totp.generate(timestamp - 30)
        assert totp.verify(prev_code, timestamp, drift=1)
        
        # Code from next period
        next_code = totp.generate(timestamp + 30)
        assert totp.verify(next_code, timestamp, drift=1)
    
    def test_verify_outside_drift(self):
        """Code outside drift window fails."""
        totp = TOTPGenerator(TOTPGenerator.generate_secret(), period=30)
        timestamp = 1000000
        
        # Code from 2 periods ago
        old_code = totp.generate(timestamp - 60)
        assert not totp.verify(old_code, timestamp, drift=1)
    
    def test_uri_format(self):
        """otpauth:// URI has correct format."""
        totp = TOTPGenerator(TOTPGenerator.generate_secret())
        uri = totp.get_uri("Airlock", "test@example.com")
        
        assert uri.startswith("otpauth://totp/Airlock:test@example.com")
        assert "secret=" in uri
        assert "issuer=Airlock" in uri
        assert "digits=6" in uri
        assert "period=30" in uri
    
    def test_rfc6238_test_vector(self):
        """Verify against RFC 6238 test vectors."""
        # RFC 6238 test secret (ASCII "12345678901234567890")
        secret = b"12345678901234567890"
        totp = TOTPGenerator(secret, digits=8, period=30)
        
        # Test vectors from RFC 6238
        # Time = 59 (counter = 1)
        assert totp.generate(59) == "94287082"
        
        # Time = 1111111109 (counter = 37037036)
        assert totp.generate(1111111109) == "07081804"
        
        # Time = 1234567890 (counter = 41152263)
        assert totp.generate(1234567890) == "89005924"
