# Secure Access Gateway (SAG)

> **Status:** Design Draft v0.1
> **Author:** Bobby (with Erik)
> **Created:** 2026-01-26

## 1. Overview

A secure, audited system for Bobby to access Erik's personal services (email, calendar, etc.) with:
- TOTP-based authentication (6-digit rotating code)
- Time-limited tokens
- Read-only permissions (initially)
- Full audit trail
- Isolated security boundaries

## 2. Goals & Constraints

### Goals
- Erik controls all access via TOTP on his phone
- Bobby cannot access services without valid TOTP
- All access is logged and auditable
- Read-only by default (non-destructive)
- Token expiration limits blast radius
- Defense in depth (multiple security layers)

### Constraints
- TOTP secret must be inaccessible to Bobby's processes
- Credentials (app passwords) must be isolated from Bobby
- System must work when Erik is remote (Telegram)
- Minimal dependencies (runs on Erik's Linux box)
- Must not require Erik to be physically present after TOTP approval

### Non-Goals (v1)
- Write operations (send email, create events)
- Multi-user support
- High availability
- Mobile app

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Erik's Machine                                │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                    User: bcohen (Bobby's context)                  │ │
│  │                                                                    │ │
│  │   ┌──────────────┐      ┌──────────────┐      ┌───────────────┐   │ │
│  │   │   Bobby      │      │  SAG Client  │      │  Audit Log    │   │ │
│  │   │  (Clawdbot)  │─────►│  Library     │─────►│  (append-only)│   │ │
│  │   └──────────────┘      └──────────────┘      └───────────────┘   │ │
│  │                               │                                    │ │
│  └───────────────────────────────┼────────────────────────────────────┘ │
│                                  │ Unix Socket                          │
│                                  │ /run/sag/gateway.sock                │
│  ┌───────────────────────────────┼────────────────────────────────────┐ │
│  │              User: sag-gateway (isolated)                          │ │
│  │                                                                    │ │
│  │   ┌──────────────────────────────────────────────────────────────┐ │ │
│  │   │                    Access Gateway                            │ │ │
│  │   │  - Validates tokens                                          │ │ │
│  │   │  - Enforces read-only                                        │ │ │
│  │   │  - Routes to service connectors                              │ │ │
│  │   │  - Logs all operations                                       │ │ │
│  │   └──────────────────────────────────────────────────────────────┘ │ │
│  │                               │                                    │ │
│  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐               │ │
│  │   │   Gmail     │  │  Calendar   │  │   iCloud    │  ...          │ │
│  │   │  Connector  │  │  Connector  │  │  Connector  │               │ │
│  │   └─────────────┘  └─────────────┘  └─────────────┘               │ │
│  │         │                │                │                        │ │
│  │         └────────────────┼────────────────┘                        │ │
│  │                          │                                         │ │
│  │   ┌──────────────────────▼───────────────────────────────────────┐ │ │
│  │   │              Credentials Store (encrypted)                   │ │ │
│  │   │              /var/lib/sag/credentials.age                    │ │ │
│  │   │              (owned by sag-gateway, mode 600)                │ │ │
│  │   └──────────────────────────────────────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │              User: sag-totp (isolated, no shell)                   │ │
│  │                                                                    │ │
│  │   ┌──────────────────────────────────────────────────────────────┐ │ │
│  │   │                   TOTP Verifier                              │ │ │
│  │   │  - Listens on /run/sag/totp.sock                             │ │ │
│  │   │  - Validates TOTP codes                                      │ │ │
│  │   │  - Issues tokens to Gateway                                  │ │ │
│  │   │  - Owns TOTP secret (inaccessible to other users)            │ │ │
│  │   └──────────────────────────────────────────────────────────────┘ │ │
│  │                                                                    │ │
│  │   ┌──────────────────────────────────────────────────────────────┐ │ │
│  │   │              TOTP Secret                                     │ │ │
│  │   │              /var/lib/sag-totp/secret (mode 600)             │ │ │
│  │   └──────────────────────────────────────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 4. Components

### 4.1 TOTP Verifier

**Purpose:** Validate TOTP codes and issue access tokens.

**User:** `sag-totp` (dedicated system user, no shell, no login)

**Interface:** Unix socket `/run/sag/totp.sock`

**Files:**
| Path | Mode | Description |
|------|------|-------------|
| `/var/lib/sag-totp/secret` | 0600 | TOTP secret (base32) |
| `/var/lib/sag-totp/tokens.db` | 0600 | Active tokens (SQLite) |
| `/run/sag/totp.sock` | 0660 | Socket (group: sag) |

**Operations:**

```
verify_totp(code: str, requested_services: list[str], ttl_minutes: int) 
  → { token: str, expires_at: datetime, services: list[str] }

revoke_token(token: str) → { success: bool }

list_active_tokens() → list[Token]  # For audit
```

### 4.2 Access Gateway

**Purpose:** Accept tokens, enforce permissions, route to service connectors.

**User:** `sag-gateway`

**Interface:** Unix socket `/run/sag/gateway.sock`

**Files:**
| Path | Mode | Description |
|------|------|-------------|
| `/var/lib/sag/credentials.age` | 0600 | Encrypted credentials |
| `/var/lib/sag/key.txt` | 0600 | age key for credentials |
| `/var/lib/sag/audit.log` | 0640 | Audit log (append-only) |
| `/run/sag/gateway.sock` | 0660 | Socket (group: sag) |

**Operations:**

```
execute(token: str, service: str, operation: str, params: dict) 
  → { success: bool, data: any, error: str? }
```

### 4.3 Service Connectors

Modular connectors for each service. All implement read-only operations only (v1).

#### Gmail Connector

```python
class GmailConnector:
    # Read operations (allowed)
    def list_messages(folder: str, limit: int, query: str?) → list[MessageSummary]
    def get_message(message_id: str) → Message
    def search(query: str, limit: int) → list[MessageSummary]
    def list_folders() → list[Folder]
    def get_unread_count() → int
    
    # Write operations (blocked in v1)
    # def send_message(...) → BLOCKED
    # def delete_message(...) → BLOCKED
    # def move_message(...) → BLOCKED
```

#### Calendar Connector

```python
class CalendarConnector:
    # Read operations (allowed)
    def list_events(start: datetime, end: datetime) → list[Event]
    def get_event(event_id: str) → Event
    def list_calendars() → list[Calendar]
    
    # Write operations (blocked in v1)
    # def create_event(...) → BLOCKED
    # def update_event(...) → BLOCKED
    # def delete_event(...) → BLOCKED
```

#### iCloud Connector

```python
class iCloudConnector:
    # Read operations (allowed)
    def list_messages(folder: str, limit: int) → list[MessageSummary]
    def get_message(message_id: str) → Message
    def get_unread_count() → int
    
    # Write operations (blocked in v1)
    # def send_message(...) → BLOCKED
```

### 4.4 SAG Client Library

**Purpose:** Simple interface for Bobby to request access and execute operations.

```python
from sag import SAGClient

async with SAGClient() as sag:
    # Request access (sends Telegram message to Erik)
    token = await sag.request_access(
        services=["gmail"],
        reason="Check for urgent emails",
        ttl_minutes=60
    )
    # Erik enters TOTP code via Telegram
    # Token is now valid
    
    # Execute read operation
    unread = await sag.execute(
        token=token,
        service="gmail",
        operation="get_unread_count"
    )
    
    messages = await sag.execute(
        token=token,
        service="gmail",
        operation="list_messages",
        params={"folder": "INBOX", "limit": 10, "query": "is:unread"}
    )
    
# Token auto-revoked when context exits (or on expiry)
```

## 5. Data Models

### 5.1 Token

```sql
CREATE TABLE tokens (
    id TEXT PRIMARY KEY,              -- UUID
    issued_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    services TEXT NOT NULL,           -- JSON array
    permissions TEXT NOT NULL,        -- JSON array (["read"] for v1)
    revoked_at DATETIME,
    revoked_reason TEXT,
    request_reason TEXT,              -- Why Bobby requested access
    audit_id TEXT NOT NULL            -- Links to audit entries
);
```

### 5.2 Credentials

```json
{
  "version": 1,
  "services": {
    "gmail": {
      "type": "imap",
      "host": "imap.gmail.com",
      "port": 993,
      "user": "cohenpts@gmail.com",
      "app_password": "xxxx xxxx xxxx xxxx"
    },
    "icloud": {
      "type": "imap", 
      "host": "imap.mail.me.com",
      "port": 993,
      "user": "hello@erikcohen.dev",
      "app_password": "xxxx-xxxx-xxxx-xxxx"
    },
    "google_calendar": {
      "type": "caldav",
      "url": "https://www.googleapis.com/calendar/v3",
      "credentials_file": "google_oauth.json"
    }
  }
}
```

### 5.3 Audit Entry

```json
{
  "id": "audit_abc123",
  "timestamp": "2026-01-26T15:32:01Z",
  "token_id": "tok_xyz789",
  "service": "gmail",
  "operation": "list_messages",
  "params": {"folder": "INBOX", "limit": 10},
  "result": "success",
  "records_returned": 10,
  "duration_ms": 245
}
```

## 6. Security Boundaries

### 6.1 User Isolation

| User | Can Access | Cannot Access |
|------|-----------|---------------|
| `bcohen` (Bobby) | SAG Client, Gateway socket | TOTP secret, credentials |
| `sag-gateway` | Credentials, Gateway socket | TOTP secret |
| `sag-totp` | TOTP secret, Token DB | Credentials |

### 6.2 File Permissions

```
/var/lib/sag-totp/
├── secret              (sag-totp:sag-totp, 0600)
└── tokens.db           (sag-totp:sag-totp, 0600)

/var/lib/sag/
├── credentials.age     (sag-gateway:sag-gateway, 0600)
├── key.txt             (sag-gateway:sag-gateway, 0600)
└── audit.log           (sag-gateway:sag, 0640)

/run/sag/
├── totp.sock           (sag-totp:sag, 0660)
└── gateway.sock        (sag-gateway:sag, 0660)
```

### 6.3 Attack Surface Analysis

| Attack Vector | Mitigation |
|---------------|-----------|
| Bobby reads TOTP secret | File owned by sag-totp, mode 0600 |
| Bobby reads credentials | File owned by sag-gateway, mode 0600 |
| Bobby forges token | Tokens signed by sag-totp, verified by gateway |
| Bobby brute-forces TOTP | Rate limiting (5 attempts/min), 30-sec rotation |
| Stolen token | Time-limited (60 min default), can be revoked |
| Replay attack | Tokens are single-use per time window |
| Man-in-middle (local) | Unix sockets, not network |

## 7. Flows

### 7.1 Initial Setup

```
Erik (terminal):
1. sudo useradd -r -s /usr/sbin/nologin sag-totp
2. sudo useradd -r -s /usr/sbin/nologin sag-gateway
3. sudo groupadd sag
4. sudo usermod -aG sag bcohen
5. sudo usermod -aG sag sag-gateway
6. Run setup script (generates TOTP secret, shows QR code)
7. Erik scans QR code with Google Authenticator
8. Erik enters credentials (encrypted to credentials.age)
9. Start systemd services
```

### 7.2 Access Request Flow

```
Bobby                    SAG Client           TOTP Verifier        Gateway
  │                          │                      │                  │
  ├─ request_access() ──────►│                      │                  │
  │                          ├── notify Erik ──────►│ (Telegram)       │
  │                          │   "Bobby wants       │                  │
  │                          │    Gmail access"     │                  │
  │                          │                      │                  │
  │                          │◄── Erik replies ─────┤                  │
  │                          │    "284719"          │                  │
  │                          │                      │                  │
  │                          ├── verify_totp() ────►│                  │
  │                          │    code="284719"     │                  │
  │                          │                      │                  │
  │                          │◄── token ────────────┤                  │
  │                          │    {id, expires_at}  │                  │
  │                          │                      │                  │
  │◄─ token ─────────────────┤                      │                  │
  │                          │                      │                  │
  ├─ execute(token, op) ────►│                      │                  │
  │                          ├── execute() ────────────────────────────►│
  │                          │                      │                  │
  │                          │◄── result ──────────────────────────────┤
  │◄─ result ────────────────┤                      │                  │
  │                          │                      │                  │
```

### 7.3 Token Lifecycle

```
Created ──► Active ──┬──► Expired (TTL reached)
                     │
                     ├──► Revoked (manual)
                     │
                     └──► Revoked (context exit)
```

## 8. Implementation Plan

### Phase 1: Foundation (2-3 hours)
- [ ] Create system users and groups
- [ ] Set up directory structure with permissions
- [ ] Implement TOTP Verifier daemon
- [ ] Generate TOTP secret, display QR code
- [ ] Basic token issuance

### Phase 2: Gateway (2-3 hours)
- [ ] Implement Access Gateway daemon
- [ ] Token validation
- [ ] Audit logging
- [ ] Permission enforcement (read-only)

### Phase 3: Connectors (2-3 hours)
- [ ] Gmail connector (IMAP)
- [ ] iCloud connector (IMAP)
- [ ] Calendar connector (CalDAV or API)

### Phase 4: Client Library (1-2 hours)
- [ ] SAG Client for Bobby
- [ ] Telegram integration for TOTP prompt
- [ ] Auto-revoke on context exit

### Phase 5: Hardening (1-2 hours)
- [ ] Rate limiting
- [ ] systemd service files
- [ ] Log rotation
- [ ] Integration tests

## 9. Future Enhancements (v2+)

- [ ] Write operations with additional confirmation
- [ ] Per-operation permissions (not just per-service)
- [ ] Token delegation (Bobby requests, Erik can grant subset)
- [ ] Hardware key support (YubiKey)
- [ ] Web dashboard for audit review
- [ ] Mobile app for approvals

## 10. Open Questions

1. **Token storage:** SQLite vs file-based?
2. **TOTP library:** pyotp vs custom?
3. **IPC format:** JSON over Unix socket vs gRPC vs msgpack?
4. **Calendar:** CalDAV vs Google Calendar API?
5. **Audit retention:** How long to keep logs?

---

## Appendix A: Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Language | Python 3.11+ | Fast dev, good libraries |
| TOTP | pyotp | Standard, well-tested |
| IPC | Unix sockets + JSON | Simple, no dependencies |
| Credentials encryption | age | Modern, simple |
| Token storage | SQLite | ACID, single file, no server |
| Audit log | JSON Lines (append-only) | Simple, greppable |
| Process management | systemd | Standard, reliable |

## Appendix B: Example Audit Log

```jsonl
{"id":"a001","ts":"2026-01-26T15:30:00Z","event":"token_requested","token_id":"tok_abc","services":["gmail"],"reason":"Check urgent emails"}
{"id":"a002","ts":"2026-01-26T15:30:15Z","event":"totp_verified","token_id":"tok_abc","success":true}
{"id":"a003","ts":"2026-01-26T15:30:16Z","event":"token_issued","token_id":"tok_abc","expires_at":"2026-01-26T16:30:16Z"}
{"id":"a004","ts":"2026-01-26T15:30:20Z","event":"operation","token_id":"tok_abc","service":"gmail","op":"get_unread_count","result":"success","data":{"count":3}}
{"id":"a005","ts":"2026-01-26T15:30:25Z","event":"operation","token_id":"tok_abc","service":"gmail","op":"list_messages","params":{"limit":10},"result":"success","data":{"count":10}}
{"id":"a006","ts":"2026-01-26T15:35:00Z","event":"token_revoked","token_id":"tok_abc","reason":"context_exit"}
```
