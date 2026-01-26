"""Tests for Gmail connector."""

import email
from datetime import datetime

import pytest

from airlock.connectors.gmail import (
    GmailConfig,
    GmailConnector,
    decode_header,
    get_text_content,
    parse_email_address,
)


class TestDecodeHeader:
    """Test RFC 2047 header decoding."""
    
    def test_plain_ascii(self):
        assert decode_header("Hello World") == "Hello World"
    
    def test_empty(self):
        assert decode_header(None) == ""
        assert decode_header("") == ""
    
    def test_utf8_encoded(self):
        # =?UTF-8?B?...?= is base64 encoded UTF-8
        encoded = "=?UTF-8?B?SGVsbG8gV29ybGQ=?="  # "Hello World"
        assert decode_header(encoded) == "Hello World"
    
    def test_quoted_printable(self):
        encoded = "=?UTF-8?Q?Hello_World?="
        assert decode_header(encoded) == "Hello World"


class TestParseEmailAddress:
    """Test email address parsing."""
    
    def test_name_and_email(self):
        name, addr = parse_email_address("John Doe <john@example.com>")
        assert name == "John Doe"
        assert addr == "john@example.com"
    
    def test_email_only(self):
        name, addr = parse_email_address("john@example.com")
        assert name == ""
        assert addr == "john@example.com"
    
    def test_empty(self):
        name, addr = parse_email_address(None)
        assert name == ""
        assert addr == ""
    
    def test_quoted_name(self):
        name, addr = parse_email_address('"Doe, John" <john@example.com>')
        assert name == "Doe, John"
        assert addr == "john@example.com"


class TestGetTextContent:
    """Test email body extraction."""
    
    def test_plain_text_simple(self):
        msg = email.message_from_string(
            "Content-Type: text/plain\n\nHello World"
        )
        assert get_text_content(msg) == "Hello World"
    
    def test_multipart(self):
        raw = """\
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary"

--boundary
Content-Type: text/plain

Plain text body
--boundary
Content-Type: text/html

<html><body>HTML body</body></html>
--boundary--
"""
        msg = email.message_from_string(raw)
        
        plain = get_text_content(msg, "text/plain")
        assert "Plain text body" in plain
        
        html = get_text_content(msg, "text/html")
        assert "HTML body" in html


class TestGmailConnector:
    """Test Gmail connector logic (no actual IMAP)."""
    
    @pytest.fixture
    def config(self):
        return GmailConfig(
            email="test@gmail.com",
            app_password="test_password",
        )
    
    @pytest.fixture
    def connector(self, config):
        return GmailConnector(config)
    
    def test_service_name(self, connector):
        assert connector.service_name == "gmail"
    
    def test_list_operations(self, connector):
        ops = connector.list_operations()
        assert "list_folders" in ops
        assert "list_messages" in ops
        assert "get_message" in ops
        assert "search" in ops
        assert "count_unread" in ops
        
        # Verify no write operations
        assert "send_message" not in ops
        assert "delete_message" not in ops
        assert "move_message" not in ops
    
    def test_parse_message(self, connector):
        raw = b"""\
From: John Doe <john@example.com>
To: Jane <jane@example.com>
Subject: Test Subject
Date: Mon, 26 Jan 2026 10:00:00 -0500
Content-Type: text/plain

This is the message body.
"""
        msg = connector._parse_message("123", raw, fetch_body=True)
        
        assert msg.uid == "123"
        assert msg.subject == "Test Subject"
        assert msg.from_addr == "john@example.com"
        assert msg.from_name == "John Doe"
        assert msg.to_addr == "jane@example.com"
        assert msg.date is not None
        assert msg.body_text == "This is the message body.\n"
    
    def test_parse_message_no_body(self, connector):
        raw = b"""\
From: sender@example.com
Subject: Quick test
Date: Mon, 26 Jan 2026 10:00:00 -0500

Body content here.
"""
        msg = connector._parse_message("456", raw, fetch_body=False)
        
        assert msg.uid == "456"
        assert msg.subject == "Quick test"
        # When fetch_body=False, body_text should be None
        assert msg.body_text is None
        # But snippet should still be populated
        assert "Body content" in msg.snippet
    
    def test_to_dict(self, connector):
        raw = b"""\
From: Test <test@example.com>
To: dest@example.com
Subject: Dict Test
Date: Mon, 26 Jan 2026 10:00:00 -0500
Content-Type: text/plain

Body.
"""
        msg = connector._parse_message("789", raw, fetch_body=True)
        d = msg.to_dict()
        
        assert d["uid"] == "789"
        assert d["subject"] == "Dict Test"
        assert d["from"]["email"] == "test@example.com"
        assert d["from"]["name"] == "Test"
        assert d["to"] == "dest@example.com"
        assert "date" in d
        assert "snippet" in d
        assert "body_text" in d


class TestGmailConnectorReadOnly:
    """Verify connector doesn't expose write operations."""
    
    def test_no_write_methods(self):
        """Connector should not have methods for modifying email."""
        connector = GmailConnector(GmailConfig("x", "y"))
        
        # These should not exist
        assert not hasattr(connector, "send_message")
        assert not hasattr(connector, "delete_message")
        assert not hasattr(connector, "move_message")
        assert not hasattr(connector, "mark_read")
        assert not hasattr(connector, "mark_unread")
        assert not hasattr(connector, "_send_message")
        assert not hasattr(connector, "_delete_message")
    
    @pytest.mark.asyncio
    async def test_execute_rejects_unknown(self):
        """Execute should reject unknown operations."""
        connector = GmailConnector(GmailConfig("x", "y"))
        
        with pytest.raises(ValueError, match="Unknown operation"):
            await connector.execute("send_message", {})
        
        with pytest.raises(ValueError, match="Unknown operation"):
            await connector.execute("delete", {})
