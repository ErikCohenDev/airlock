"""Google Calendar Connector — Read-only access to Google Calendar.

Uses OAuth2 for authentication (required by Google Calendar API).
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Read-only scope
SCOPES = ["https://www.googleapis.com/auth/calendar.readonly"]

DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "airlock"


@dataclass
class CalendarConfig:
    """Google Calendar configuration."""
    credentials_path: Path = field(default_factory=lambda: DEFAULT_DATA_DIR / "calendar_credentials.json")
    token_path: Path = field(default_factory=lambda: DEFAULT_DATA_DIR / "calendar_token.json")


class CalendarConnector:
    """Read-only Google Calendar connector."""
    
    def __init__(self, config: CalendarConfig | None = None):
        self.config = config or CalendarConfig()
        self._service = None
    
    @property
    def service_name(self) -> str:
        return "calendar"
    
    def _get_credentials(self) -> Credentials:
        """Get or refresh OAuth credentials."""
        creds = None
        
        # Load existing token
        if self.config.token_path.exists():
            creds = Credentials.from_authorized_user_file(
                str(self.config.token_path), SCOPES
            )
        
        # Refresh or get new credentials
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not self.config.credentials_path.exists():
                    raise ValueError(
                        f"OAuth credentials not found at {self.config.credentials_path}. "
                        "Download from Google Cloud Console and run: airlock credentials add calendar"
                    )
                
                flow = InstalledAppFlow.from_client_secrets_file(
                    str(self.config.credentials_path), SCOPES
                )
                creds = flow.run_local_server(port=0)
            
            # Save the token
            self.config.token_path.parent.mkdir(parents=True, exist_ok=True)
            self.config.token_path.write_text(creds.to_json())
        
        return creds
    
    def _get_service(self):
        """Get or create Calendar API service."""
        if self._service is None:
            creds = self._get_credentials()
            self._service = build("calendar", "v3", credentials=creds)
        return self._service
    
    async def execute(self, operation: str, params: dict[str, Any]) -> Any:
        """Execute a calendar operation."""
        if operation == "list_events":
            return await self._list_events(params)
        elif operation == "get_event":
            return await self._get_event(params)
        elif operation == "list_calendars":
            return await self._list_calendars(params)
        elif operation == "today":
            return await self._today(params)
        elif operation == "upcoming":
            return await self._upcoming(params)
        elif operation == "search":
            return await self._search(params)
        else:
            raise ValueError(f"Unknown operation: {operation}")
    
    async def _list_calendars(self, params: dict) -> list[dict]:
        """List available calendars."""
        service = self._get_service()
        result = service.calendarList().list().execute()
        
        calendars = []
        for cal in result.get("items", []):
            calendars.append({
                "id": cal["id"],
                "name": cal.get("summary", ""),
                "primary": cal.get("primary", False),
                "access_role": cal.get("accessRole", ""),
                "color": cal.get("backgroundColor", ""),
            })
        
        return calendars
    
    async def _list_events(self, params: dict) -> list[dict]:
        """List events within a time range."""
        service = self._get_service()
        
        calendar_id = params.get("calendar_id", "primary")
        time_min = params.get("time_min")
        time_max = params.get("time_max")
        limit = params.get("limit", 50)
        
        # Default: next 7 days
        if not time_min:
            time_min = datetime.now(timezone.utc).isoformat()
        if not time_max:
            time_max = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        
        result = service.events().list(
            calendarId=calendar_id,
            timeMin=time_min,
            timeMax=time_max,
            maxResults=limit,
            singleEvents=True,
            orderBy="startTime",
        ).execute()
        
        return [self._format_event(e) for e in result.get("items", [])]
    
    async def _today(self, params: dict) -> list[dict]:
        """Get today's events."""
        now = datetime.now(timezone.utc)
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_day = start_of_day + timedelta(days=1)
        
        return await self._list_events({
            "calendar_id": params.get("calendar_id", "primary"),
            "time_min": start_of_day.isoformat(),
            "time_max": end_of_day.isoformat(),
            "limit": params.get("limit", 50),
        })
    
    async def _upcoming(self, params: dict) -> list[dict]:
        """Get upcoming events (next N hours or days)."""
        hours = params.get("hours", 24)
        days = params.get("days")
        
        if days:
            hours = days * 24
        
        now = datetime.now(timezone.utc)
        end = now + timedelta(hours=hours)
        
        return await self._list_events({
            "calendar_id": params.get("calendar_id", "primary"),
            "time_min": now.isoformat(),
            "time_max": end.isoformat(),
            "limit": params.get("limit", 50),
        })
    
    async def _search(self, params: dict) -> list[dict]:
        """Search events by query."""
        service = self._get_service()
        
        query = params.get("query", "")
        calendar_id = params.get("calendar_id", "primary")
        limit = params.get("limit", 20)
        
        # Search in next 30 days by default
        time_min = params.get("time_min", datetime.now(timezone.utc).isoformat())
        time_max = params.get("time_max", (datetime.now(timezone.utc) + timedelta(days=30)).isoformat())
        
        result = service.events().list(
            calendarId=calendar_id,
            timeMin=time_min,
            timeMax=time_max,
            maxResults=limit,
            singleEvents=True,
            orderBy="startTime",
            q=query,
        ).execute()
        
        return [self._format_event(e) for e in result.get("items", [])]
    
    async def _get_event(self, params: dict) -> dict:
        """Get a single event by ID."""
        service = self._get_service()
        
        calendar_id = params.get("calendar_id", "primary")
        event_id = params["event_id"]
        
        event = service.events().get(
            calendarId=calendar_id,
            eventId=event_id,
        ).execute()
        
        return self._format_event(event, include_full=True)
    
    def _format_event(self, event: dict, include_full: bool = False) -> dict:
        """Format an event for output."""
        start = event.get("start", {})
        end = event.get("end", {})
        
        # Handle all-day vs timed events
        start_time = start.get("dateTime") or start.get("date")
        end_time = end.get("dateTime") or end.get("date")
        is_all_day = "date" in start and "dateTime" not in start
        
        formatted = {
            "id": event.get("id"),
            "summary": event.get("summary", "(No title)"),
            "start": start_time,
            "end": end_time,
            "all_day": is_all_day,
            "location": event.get("location"),
            "status": event.get("status"),
        }
        
        # Add attendees summary
        attendees = event.get("attendees", [])
        if attendees:
            formatted["attendees_count"] = len(attendees)
            formatted["attendees"] = [
                {
                    "email": a.get("email"),
                    "name": a.get("displayName"),
                    "response": a.get("responseStatus"),
                    "organizer": a.get("organizer", False),
                }
                for a in attendees[:10]  # Limit to 10
            ]
        
        # Include full details if requested
        if include_full:
            formatted["description"] = event.get("description")
            formatted["html_link"] = event.get("htmlLink")
            formatted["hangout_link"] = event.get("hangoutLink")
            formatted["conference_data"] = event.get("conferenceData")
            formatted["recurrence"] = event.get("recurrence")
            formatted["creator"] = event.get("creator")
            formatted["organizer"] = event.get("organizer")
        
        return formatted
