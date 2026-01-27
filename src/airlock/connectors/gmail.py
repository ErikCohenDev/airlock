"""Gmail Connector — Read-only IMAP access to Gmail.

Supports:
- list_folders: List available mailbox folders
- list_messages: List messages (subject, from, date)
- get_message: Get full message content
- search: Search messages

Does NOT support (by design):
- send_message
- delete_message
- move_message
- mark_read/unread
"""

import email
import email.header
import email.message
import email.utils
import imaplib
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class GmailConfig:
    """Gmail IMAP configuration."""
    email: str
    app_password: str
    imap_host: str = "imap.gmail.com"
    imap_port: int = 993


@dataclass
class EmailMessage:
    """Simplified email message."""
    uid: str
    subject: str
    from_addr: str
    from_name: str
    to_addr: str
    date: datetime | None
    snippet: str
    body_text: str | None = None
    body_html: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "subject": self.subject,
            "from": {"email": self.from_addr, "name": self.from_name},
            "to": self.to_addr,
            "date": self.date.isoformat() if self.date else None,
            "snippet": self.snippet,
            "body_text": self.body_text,
            "body_html": self.body_html,
        }


def decode_header(header_value: str | None) -> str:
    """Decode RFC 2047 encoded header."""
    if not header_value:
        return ""
    
    decoded_parts = []
    for part, charset in email.header.decode_header(header_value):
        if isinstance(part, bytes):
            charset = charset or "utf-8"
            try:
                decoded_parts.append(part.decode(charset, errors="replace"))
            except (LookupError, UnicodeDecodeError):
                decoded_parts.append(part.decode("utf-8", errors="replace"))
        else:
            decoded_parts.append(part)
    
    return " ".join(decoded_parts)


def parse_email_address(addr: str | None) -> tuple[str, str]:
    """Parse email address into (name, email)."""
    if not addr:
        return ("", "")
    
    name, email_addr = email.utils.parseaddr(addr)
    return (decode_header(name), email_addr)


def get_text_content(msg: email.message.Message, content_type: str = "text/plain") -> str | None:
    """Extract text content from email message."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == content_type:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        return payload.decode(charset, errors="replace")
                    except (LookupError, UnicodeDecodeError):
                        return payload.decode("utf-8", errors="replace")
        return None
    else:
        if msg.get_content_type() == content_type:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                try:
                    return payload.decode(charset, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    return payload.decode("utf-8", errors="replace")
        return None


class GmailConnector:
    """Read-only Gmail IMAP connector."""
    
    OPERATIONS = [
        "list_folders",
        "list_messages", 
        "get_message",
        "search",
        "count_unread",
    ]
    
    def __init__(self, config: GmailConfig):
        self.config = config
        self._imap: imaplib.IMAP4_SSL | None = None
    
    @property
    def service_name(self) -> str:
        return "gmail"
    
    def list_operations(self) -> list[str]:
        return self.OPERATIONS.copy()
    
    def _connect(self) -> imaplib.IMAP4_SSL:
        """Establish IMAP connection."""
        if self._imap is None:
            self._imap = imaplib.IMAP4_SSL(self.config.imap_host, self.config.imap_port)
            self._imap.login(self.config.email, self.config.app_password)
            logger.debug(f"Connected to Gmail as {self.config.email}")
        return self._imap
    
    def _disconnect(self) -> None:
        """Close IMAP connection."""
        if self._imap:
            try:
                self._imap.close()
                self._imap.logout()
            except Exception:
                pass
            self._imap = None
    
    def _parse_message(self, uid: str, data: bytes, fetch_body: bool = False) -> EmailMessage:
        """Parse raw email data into EmailMessage."""
        msg = email.message_from_bytes(data)
        
        subject = decode_header(msg.get("Subject"))
        from_name, from_addr = parse_email_address(msg.get("From"))
        _, to_addr = parse_email_address(msg.get("To"))
        
        date_str = msg.get("Date")
        date = None
        if date_str:
            try:
                date_tuple = email.utils.parsedate_to_datetime(date_str)
                date = date_tuple
            except Exception:
                pass
        
        # Get snippet from plain text body
        body_text = get_text_content(msg, "text/plain")
        snippet = ""
        if body_text:
            # Clean up and truncate for snippet
            snippet = re.sub(r'\s+', ' ', body_text).strip()[:200]
        
        body_html = None
        if fetch_body:
            body_html = get_text_content(msg, "text/html")
        
        return EmailMessage(
            uid=uid,
            subject=subject,
            from_addr=from_addr,
            from_name=from_name,
            to_addr=to_addr,
            date=date,
            snippet=snippet,
            body_text=body_text if fetch_body else None,
            body_html=body_html,
        )
    
    async def execute(self, operation: str, params: dict[str, Any]) -> Any:
        """Execute a read-only operation."""
        if operation == "list_folders":
            return await self._list_folders()
        elif operation == "list_messages":
            return await self._list_messages(**params)
        elif operation == "get_message":
            return await self._get_message(**params)
        elif operation == "search":
            return await self._search(**params)
        elif operation == "count_unread":
            return await self._count_unread(**params)
        else:
            raise ValueError(f"Unknown operation: {operation}")
    
    async def _list_folders(self) -> list[dict[str, Any]]:
        """List available mailbox folders."""
        imap = self._connect()
        
        status, data = imap.list()
        if status != "OK":
            raise RuntimeError("Failed to list folders")
        
        folders = []
        for item in data:
            if isinstance(item, bytes):
                # Parse folder info: (\\Flags) "/" "Folder Name"
                match = re.match(rb'\(([^)]*)\) "([^"]*)" "?([^"]*)"?', item)
                if match:
                    flags = match.group(1).decode()
                    delimiter = match.group(2).decode()
                    name = match.group(3).decode()
                    folders.append({
                        "name": name,
                        "flags": flags.split(),
                        "delimiter": delimiter,
                    })
        
        return folders
    
    async def _list_messages(
        self,
        folder: str = "INBOX",
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List messages in a folder."""
        imap = self._connect()
        
        status, _ = imap.select(folder, readonly=True)
        if status != "OK":
            raise RuntimeError(f"Failed to select folder: {folder}")
        
        # Search for all messages
        status, data = imap.search(None, "ALL")
        if status != "OK":
            raise RuntimeError("Failed to search messages")
        
        uids = data[0].split()
        
        # Apply offset and limit (newest first)
        uids = list(reversed(uids))
        uids = uids[offset:offset + limit]
        
        if not uids:
            return []
        
        messages = []
        for uid in uids:
            uid_str = uid.decode() if isinstance(uid, bytes) else uid
            status, data = imap.fetch(uid, "(RFC822.HEADER)")
            if status == "OK" and data[0]:
                raw = data[0][1] if isinstance(data[0], tuple) else data[0]
                if raw:
                    msg = self._parse_message(uid_str, raw, fetch_body=False)
                    messages.append(msg.to_dict())
        
        return messages
    
    async def _get_message(self, uid: str, folder: str = "INBOX") -> dict[str, Any] | None:
        """Get full message by UID (or message sequence number)."""
        imap = self._connect()
        
        status, _ = imap.select(folder, readonly=True)
        if status != "OK":
            raise RuntimeError(f"Failed to select folder: {folder}")
        
        # Try BODY[] first (works better with some IMAP servers like iCloud)
        uid_bytes = uid.encode() if isinstance(uid, str) else uid
        status, data = imap.fetch(uid_bytes, "(BODY[])")
        if status != "OK" or not data or not data[0]:
            # Fallback to RFC822
            status, data = imap.fetch(uid_bytes, "(RFC822)")
            if status != "OK" or not data or not data[0]:
                return None
        
        # Handle different response formats
        raw = None
        if isinstance(data[0], tuple) and len(data[0]) > 1:
            raw = data[0][1]
        elif isinstance(data[0], bytes):
            # Some servers return just the content
            raw = data[0]
        
        if not raw:
            return None
        
        msg = self._parse_message(uid, raw, fetch_body=True)
        return msg.to_dict()
    
    async def _search(
        self,
        query: str,
        folder: str = "INBOX",
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search messages.
        
        query can be:
        - A simple term: searches subject and body
        - IMAP search syntax: FROM "someone", SUBJECT "topic", etc.
        """
        imap = self._connect()
        
        status, _ = imap.select(folder, readonly=True)
        if status != "OK":
            raise RuntimeError(f"Failed to select folder: {folder}")
        
        # Determine if query is IMAP syntax or simple text
        imap_keywords = ["FROM", "TO", "SUBJECT", "BODY", "TEXT", "SINCE", "BEFORE", "ON"]
        is_imap_syntax = any(query.upper().startswith(kw) for kw in imap_keywords)
        
        if is_imap_syntax:
            search_criteria = query
        else:
            # Simple text search - search in subject and body
            search_criteria = f'OR SUBJECT "{query}" BODY "{query}"'
        
        status, data = imap.search(None, search_criteria)
        if status != "OK":
            raise RuntimeError("Search failed")
        
        uids = data[0].split()
        uids = list(reversed(uids))[:limit]
        
        messages = []
        for uid in uids:
            uid_str = uid.decode() if isinstance(uid, bytes) else uid
            status, data = imap.fetch(uid, "(RFC822.HEADER)")
            if status == "OK" and data[0]:
                raw = data[0][1] if isinstance(data[0], tuple) else data[0]
                if raw:
                    msg = self._parse_message(uid_str, raw, fetch_body=False)
                    messages.append(msg.to_dict())
        
        return messages
    
    async def _count_unread(self, folder: str = "INBOX") -> int:
        """Count unread messages in folder."""
        imap = self._connect()
        
        status, _ = imap.select(folder, readonly=True)
        if status != "OK":
            raise RuntimeError(f"Failed to select folder: {folder}")
        
        status, data = imap.search(None, "UNSEEN")
        if status != "OK":
            raise RuntimeError("Failed to count unread")
        
        uids = data[0].split()
        return len(uids)
    
    def __del__(self):
        self._disconnect()
