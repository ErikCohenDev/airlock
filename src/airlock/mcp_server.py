"""Airlock MCP Server — Model Context Protocol interface for AI agents.

Exposes email operations as MCP tools with TOTP-gated access.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
import yaml

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("airlock.mcp")

# Paths (match CLI defaults)
DEFAULT_CONFIG_DIR = Path.home() / ".config" / "airlock"
DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "airlock"
TOKEN_CACHE_PATH = DEFAULT_DATA_DIR / "token_cache.json"


def load_config() -> dict:
    """Load Airlock config."""
    config_path = DEFAULT_CONFIG_DIR / "config.yaml"
    if config_path.exists():
        return yaml.safe_load(config_path.read_text()) or {}
    return {}


def get_cached_token() -> dict | None:
    """Get cached TOTP token if still valid."""
    if not TOKEN_CACHE_PATH.exists():
        return None
    
    try:
        cache = json.loads(TOKEN_CACHE_PATH.read_text())
        expires_at = datetime.fromisoformat(cache["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) < expires_at:
            return cache
    except Exception:
        pass
    
    return None


def get_token_remaining_minutes() -> int | None:
    """Get remaining minutes on cached token."""
    cached = get_cached_token()
    if not cached:
        return None
    
    expires = datetime.fromisoformat(cached["expires_at"].replace("Z", "+00:00"))
    remaining = int((expires - datetime.now(timezone.utc)).total_seconds() / 60)
    return max(0, remaining)


def get_connector(service: str):
    """Get connector instance for a service."""
    config = load_config()
    credentials = config.get("credentials", {})
    
    if service not in credentials:
        raise ValueError(f"Service '{service}' not configured. Run: airlock credentials add {service}")
    
    cred = credentials[service]
    
    if service == "gmail":
        from airlock.connectors.gmail import GmailConnector, GmailConfig
        return GmailConnector(GmailConfig(
            email=cred["email"],
            app_password=cred["app_password"],
        ))
    elif service == "icloud":
        from airlock.connectors.icloud import ICloudConnector, ICloudConfig
        return ICloudConnector(ICloudConfig(
            email=cred["email"],
            app_password=cred["app_password"],
        ))
    elif service == "calendar":
        from airlock.connectors.calendar import CalendarConnector, CalendarConfig
        return CalendarConnector(CalendarConfig(
            credentials_path=Path(cred["credentials_path"]),
            token_path=Path(cred["token_path"]),
        ))
    else:
        raise ValueError(f"Unknown service: {service}")


def get_available_services() -> list[str]:
    """Get list of configured services."""
    config = load_config()
    return list(config.get("credentials", {}).keys())


# Create MCP server
server = Server("airlock")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available Airlock tools."""
    services = get_available_services()
    service_list = ", ".join(services) if services else "none configured"
    
    return [
        Tool(
            name="airlock_status",
            description="Check Airlock access status — whether you have an active TOTP session and which services are available.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="airlock_list_emails",
            description=f"List recent emails from a configured mail service. Requires active TOTP session. Available services: {service_list}",
            inputSchema={
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Mail service to use (gmail, icloud)",
                        "enum": ["gmail", "icloud"],
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum emails to return (default: 10)",
                        "default": 10,
                    },
                    "folder": {
                        "type": "string",
                        "description": "Mail folder (default: INBOX)",
                        "default": "INBOX",
                    },
                },
                "required": ["service"],
            },
        ),
        Tool(
            name="airlock_search_emails",
            description=f"Search emails with a query. Requires active TOTP session. Available services: {service_list}",
            inputSchema={
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Mail service to use (gmail, icloud)",
                        "enum": ["gmail", "icloud"],
                    },
                    "query": {
                        "type": "string",
                        "description": "Search query (e.g., 'from:someone@example.com', 'subject:meeting')",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum emails to return (default: 10)",
                        "default": 10,
                    },
                },
                "required": ["service", "query"],
            },
        ),
        Tool(
            name="airlock_get_email",
            description=f"Get full email content by message ID. Requires active TOTP session. Available services: {service_list}",
            inputSchema={
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Mail service to use (gmail, icloud)",
                        "enum": ["gmail", "icloud"],
                    },
                    "message_id": {
                        "type": "string",
                        "description": "Email message ID (from list_emails or search_emails)",
                    },
                },
                "required": ["service", "message_id"],
            },
        ),
        Tool(
            name="airlock_count_unread",
            description=f"Count unread emails. Requires active TOTP session. Available services: {service_list}",
            inputSchema={
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Mail service to use (gmail, icloud)",
                        "enum": ["gmail", "icloud"],
                    },
                    "folder": {
                        "type": "string",
                        "description": "Mail folder (default: INBOX)",
                        "default": "INBOX",
                    },
                },
                "required": ["service"],
            },
        ),
        # Calendar tools
        Tool(
            name="airlock_calendar_today",
            description="Get today's calendar events. Requires active TOTP session and calendar configured.",
            inputSchema={
                "type": "object",
                "properties": {
                    "calendar_id": {
                        "type": "string",
                        "description": "Calendar ID (default: primary)",
                        "default": "primary",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="airlock_calendar_upcoming",
            description="Get upcoming calendar events (next N hours/days). Requires active TOTP session.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "integer",
                        "description": "Number of hours to look ahead (default: 24)",
                        "default": 24,
                    },
                    "days": {
                        "type": "integer",
                        "description": "Number of days to look ahead (overrides hours if set)",
                    },
                    "calendar_id": {
                        "type": "string",
                        "description": "Calendar ID (default: primary)",
                        "default": "primary",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="airlock_calendar_search",
            description="Search calendar events by query. Requires active TOTP session.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (e.g., 'meeting', 'dentist')",
                    },
                    "days": {
                        "type": "integer",
                        "description": "Days to search ahead (default: 30)",
                        "default": 30,
                    },
                    "calendar_id": {
                        "type": "string",
                        "description": "Calendar ID (default: primary)",
                        "default": "primary",
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="airlock_calendar_list",
            description="List available calendars. Requires active TOTP session.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="airlock_calendar_event",
            description="Get details of a specific calendar event by ID. Requires active TOTP session.",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_id": {
                        "type": "string",
                        "description": "Event ID (from calendar_today or calendar_upcoming)",
                    },
                    "calendar_id": {
                        "type": "string",
                        "description": "Calendar ID (default: primary)",
                        "default": "primary",
                    },
                },
                "required": ["event_id"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    
    if name == "airlock_status":
        return await handle_status()
    
    # All other tools require TOTP session
    cached = get_cached_token()
    if not cached:
        services = get_available_services()
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": "access_denied",
                "message": "No active TOTP session. Ask the user to approve access by running: airlock run <service> list_messages",
                "available_services": services,
                "hint": "The user needs to enter their TOTP code to grant you temporary access.",
            }, indent=2),
        )]
    
    remaining = get_token_remaining_minutes()
    
    try:
        if name == "airlock_list_emails":
            return await handle_list_emails(arguments, remaining)
        elif name == "airlock_search_emails":
            return await handle_search_emails(arguments, remaining)
        elif name == "airlock_get_email":
            return await handle_get_email(arguments, remaining)
        elif name == "airlock_count_unread":
            return await handle_count_unread(arguments, remaining)
        # Calendar tools
        elif name == "airlock_calendar_today":
            return await handle_calendar_today(arguments, remaining)
        elif name == "airlock_calendar_upcoming":
            return await handle_calendar_upcoming(arguments, remaining)
        elif name == "airlock_calendar_search":
            return await handle_calendar_search(arguments, remaining)
        elif name == "airlock_calendar_list":
            return await handle_calendar_list(arguments, remaining)
        elif name == "airlock_calendar_event":
            return await handle_calendar_event(arguments, remaining)
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        logger.exception(f"Error in {name}")
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": "operation_failed",
                "message": str(e),
            }, indent=2),
        )]


async def handle_status() -> list[TextContent]:
    """Handle airlock_status tool."""
    services = get_available_services()
    cached = get_cached_token()
    
    if cached:
        remaining = get_token_remaining_minutes()
        status = {
            "status": "active",
            "session_remaining_minutes": remaining,
            "available_services": services,
            "message": f"TOTP session active. {remaining} minutes remaining.",
        }
    else:
        status = {
            "status": "no_session",
            "available_services": services,
            "message": "No active TOTP session. User must approve access first.",
            "hint": "Ask the user to run: airlock run <service> list_messages",
        }
    
    return [TextContent(type="text", text=json.dumps(status, indent=2))]


async def handle_list_emails(args: dict, remaining: int) -> list[TextContent]:
    """Handle airlock_list_emails tool."""
    service = args["service"]
    limit = args.get("limit", 10)
    folder = args.get("folder", "INBOX")
    
    connector = get_connector(service)
    result = await connector.execute("list_messages", {"limit": limit, "folder": folder})
    
    return [TextContent(
        type="text",
        text=json.dumps({
            "success": True,
            "service": service,
            "session_remaining_minutes": remaining,
            "count": len(result),
            "emails": result,
        }, indent=2, default=str),
    )]


async def handle_search_emails(args: dict, remaining: int) -> list[TextContent]:
    """Handle airlock_search_emails tool."""
    service = args["service"]
    query = args["query"]
    limit = args.get("limit", 10)
    
    connector = get_connector(service)
    result = await connector.execute("search", {"query": query, "limit": limit})
    
    return [TextContent(
        type="text",
        text=json.dumps({
            "success": True,
            "service": service,
            "session_remaining_minutes": remaining,
            "query": query,
            "count": len(result),
            "emails": result,
        }, indent=2, default=str),
    )]


async def handle_get_email(args: dict, remaining: int) -> list[TextContent]:
    """Handle airlock_get_email tool."""
    service = args["service"]
    message_id = args["message_id"]
    
    connector = get_connector(service)
    result = await connector.execute("get_message", {"message_id": message_id})
    
    return [TextContent(
        type="text",
        text=json.dumps({
            "success": True,
            "service": service,
            "session_remaining_minutes": remaining,
            "email": result,
        }, indent=2, default=str),
    )]


async def handle_count_unread(args: dict, remaining: int) -> list[TextContent]:
    """Handle airlock_count_unread tool."""
    service = args["service"]
    folder = args.get("folder", "INBOX")
    
    connector = get_connector(service)
    result = await connector.execute("count_unread", {"folder": folder})
    
    return [TextContent(
        type="text",
        text=json.dumps({
            "success": True,
            "service": service,
            "session_remaining_minutes": remaining,
            "unread_count": result,
        }, indent=2, default=str),
    )]


async def handle_calendar_today(args: dict, remaining: int) -> list[TextContent]:
    """Handle airlock_calendar_today tool."""
    calendar_id = args.get("calendar_id", "primary")
    
    connector = get_connector("calendar")
    result = await connector.execute("today", {"calendar_id": calendar_id})
    
    return [TextContent(
        type="text",
        text=json.dumps({
            "success": True,
            "service": "calendar",
            "session_remaining_minutes": remaining,
            "date": datetime.now().strftime("%Y-%m-%d"),
            "count": len(result),
            "events": result,
        }, indent=2, default=str),
    )]


async def handle_calendar_upcoming(args: dict, remaining: int) -> list[TextContent]:
    """Handle airlock_calendar_upcoming tool."""
    hours = args.get("hours", 24)
    days = args.get("days")
    calendar_id = args.get("calendar_id", "primary")
    
    connector = get_connector("calendar")
    result = await connector.execute("upcoming", {
        "hours": hours,
        "days": days,
        "calendar_id": calendar_id,
    })
    
    return [TextContent(
        type="text",
        text=json.dumps({
            "success": True,
            "service": "calendar",
            "session_remaining_minutes": remaining,
            "looking_ahead": f"{days} days" if days else f"{hours} hours",
            "count": len(result),
            "events": result,
        }, indent=2, default=str),
    )]


async def handle_calendar_search(args: dict, remaining: int) -> list[TextContent]:
    """Handle airlock_calendar_search tool."""
    query = args["query"]
    days = args.get("days", 30)
    calendar_id = args.get("calendar_id", "primary")
    
    connector = get_connector("calendar")
    
    # Set time range for search
    from datetime import timedelta
    time_max = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    
    result = await connector.execute("search", {
        "query": query,
        "calendar_id": calendar_id,
        "time_max": time_max,
    })
    
    return [TextContent(
        type="text",
        text=json.dumps({
            "success": True,
            "service": "calendar",
            "session_remaining_minutes": remaining,
            "query": query,
            "count": len(result),
            "events": result,
        }, indent=2, default=str),
    )]


async def handle_calendar_list(args: dict, remaining: int) -> list[TextContent]:
    """Handle airlock_calendar_list tool."""
    connector = get_connector("calendar")
    result = await connector.execute("list_calendars", {})
    
    return [TextContent(
        type="text",
        text=json.dumps({
            "success": True,
            "service": "calendar",
            "session_remaining_minutes": remaining,
            "count": len(result),
            "calendars": result,
        }, indent=2, default=str),
    )]


async def handle_calendar_event(args: dict, remaining: int) -> list[TextContent]:
    """Handle airlock_calendar_event tool."""
    event_id = args["event_id"]
    calendar_id = args.get("calendar_id", "primary")
    
    connector = get_connector("calendar")
    result = await connector.execute("get_event", {
        "event_id": event_id,
        "calendar_id": calendar_id,
    })
    
    return [TextContent(
        type="text",
        text=json.dumps({
            "success": True,
            "service": "calendar",
            "session_remaining_minutes": remaining,
            "event": result,
        }, indent=2, default=str),
    )]


async def async_main():
    """Run the MCP server (async)."""
    logger.info("Starting Airlock MCP server...")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main():
    """Entry point for the MCP server."""
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
