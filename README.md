# 🚀 Airlock — Secure Access Gateway for AI Agents

> Human-in-the-loop access control for AI agents. Your assistant asks, you approve with TOTP, access auto-expires.

## The Problem

AI agents need access to your personal services — email, calendar, APIs. Current options:

| Approach | Risk |
|----------|------|
| Share credentials directly | Agent has full access, prompt injection can leak them |
| OAuth tokens | Still full access once granted, no per-request approval |
| API keys in env | Same as above |

**What's missing:** A way to grant *temporary, read-only, audited* access that requires *your explicit approval* for each session.

## The Solution

Airlock sits between your AI agent and your personal services:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  AI Agent   │────►│     Airlock     │────►│   Gmail     │     │    You      │
│  (Claude,   │     │  Gateway    │     │  Calendar   │     │  (Telegram) │
│   etc.)     │     │             │◄────│   etc.      │     │             │
└─────────────┘     └──────┬──────┘     └─────────────┘     └──────┬──────┘
                           │                                       │
                           │  "Bobby wants to check your email"    │
                           │  "Reply with TOTP code to approve"    │
                           └───────────────────────────────────────┘
                                            │
                                      You: "284719"
                                            │
                                   ┌────────▼────────┐
                                   │ TOTP Verified   │
                                   │ Token issued    │
                                   │ Expires in 60m  │
                                   │ Read-only       │
                                   └─────────────────┘
```

## Features

- **🔐 TOTP Approval** — 6-digit code from your authenticator app required for each access session
- **⏱️ Auto-Expire** — Tokens expire after configurable time (default: 60 minutes)
- **📖 Read-Only by Default** — Agents can read but not send, delete, or modify
- **📋 Full Audit Trail** — Every access logged with timestamp, operation, and result
- **🔒 Credential Isolation** — Secrets stored in isolated system user, inaccessible to agent
- **📱 Mobile Approval** — Approve via Telegram, Signal, or any mesairlocking platform
- **🏠 Self-Hosted** — Your data stays on your machine

## Security Model

```
┌────────────────────────────────────────────────────────────────┐
│                        Your Machine                            │
│                                                                │
│  ┌──────────────────┐    ┌──────────────────────────────────┐ │
│  │ AI Agent         │    │ airlock-gateway (isolated user)      │ │
│  │ (runs as you)    │    │ - Owns credentials               │ │
│  │                  │    │ - Validates tokens               │ │
│  │ ❌ Cannot read:  │    │ - Enforces read-only             │ │
│  │   - TOTP secret  │    │ - Logs everything                │ │
│  │   - Credentials  │    └──────────────────────────────────┘ │
│  └──────────────────┘                                          │
│                          ┌──────────────────────────────────┐  │
│                          │ airlock-totp (isolated user)         │  │
│                          │ - Owns TOTP secret               │  │
│                          │ - Issues tokens                  │  │
│                          │ - Cannot access credentials      │  │
│                          └──────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

Linux user isolation means the agent **literally cannot** read secrets — it's not policy, it's permissions.

## Quick Start

### 1. Install

```bash
# Clone and build
git clone https://github.com/ErikCohenDev/airlock.git
cd airlock
./install.sh
```

### 2. Setup TOTP

```bash
# Generates secret, shows QR code for your authenticator app
airlock setup totp
```

### 3. Add Credentials

```bash
# Add Gmail (app password)
airlock credentials add gmail
```

### 4. Use with Your Agent

```python
from airlock import AirlockClient

async with AirlockClient() as airlock:
    # This sends you a Telegram mesairlocke asking for TOTP
    token = await airlock.request_access(
        services=["gmail"],
        reason="Check for urgent emails"
    )
    
    # After you reply with TOTP code...
    mesairlockes = await airlock.gmail.list_mesairlockes(limit=10)
    
# Token auto-revoked when done
```

## Supported Services (v1)

| Service | Read | Write |
|---------|------|-------|
| Gmail (IMAP) | ✅ List, search, read | ❌ Send, delete |
| Google Calendar | ✅ List events | ❌ Create, modify |
| iCloud Mail | ✅ List, read | ❌ Send, delete |

More coming: GitHub, Slack, Notion, etc.

## Configuration

```yaml
# ~/.config/airlock/config.yaml
totp:
  issuer: "Airlock"
  digits: 6
  period: 30

tokens:
  default_ttl_minutes: 60
  max_ttl_minutes: 480

notifications:
  provider: telegram
  chat_id: "123456789"

permissions:
  default: read
  # Future: per-service overrides
```

## Audit Log

Every access is logged:

```jsonl
{"ts":"2026-01-26T15:30:00Z","event":"access_requested","services":["gmail"],"reason":"Check urgent emails"}
{"ts":"2026-01-26T15:30:15Z","event":"totp_verified","token_id":"tok_abc123"}
{"ts":"2026-01-26T15:30:20Z","event":"operation","service":"gmail","op":"list_mesairlockes","count":10}
{"ts":"2026-01-26T16:30:00Z","event":"token_expired","token_id":"tok_abc123"}
```

Review anytime:

```bash
airlock audit today
airlock audit --service gmail --last 7d
```

## Roadmap

- [x] Design & architecture
- [ ] TOTP verifier daemon
- [ ] Access gateway daemon
- [ ] Gmail connector (read-only)
- [ ] Telegram notifications
- [ ] CLI tool
- [ ] Calendar connector
- [ ] Write permissions (with extra confirmation)
- [ ] Web dashboard for audit
- [ ] Gap/DeepSecure integration

## How It Compares

| Feature | Airlock | Gap | DeepSecure | Raw OAuth |
|---------|-----|-----|------------|-----------|
| Human approval per session | ✅ TOTP | ❌ | ❌ | ❌ |
| Credential isolation | ✅ | ✅ | ✅ | ❌ |
| Read-only enforcement | ✅ | ❌ | ⚠️ | ❌ |
| Auto-expire tokens | ✅ | ⚠️ | ✅ | ❌ |
| Mobile approval flow | ✅ | ❌ | ❌ | ❌ |
| Self-hosted | ✅ | ✅ | ✅ | N/A |
| Complexity | Low | Low | High | N/A |

## Philosophy

1. **Defense in depth** — Multiple layers, not one big wall
2. **Least privilege** — Read-only default, explicit upgrades
3. **Human in the loop** — You approve, not the agent
4. **Audit everything** — Full visibility into what happened
5. **Simple > Complex** — One machine, no cloud, no Kubernetes

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Erik Cohen](https://erikcohen.dev) — because I needed it for my own AI assistant.
