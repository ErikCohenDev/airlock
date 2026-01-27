"""iCloud Mail Connector — Read-only IMAP access to iCloud Mail.

Same capabilities as Gmail connector, different server settings.
"""

from dataclasses import dataclass
from typing import Any

from airlock.connectors.gmail import GmailConnector


@dataclass
class ICloudConfig:
    """iCloud IMAP configuration."""
    email: str  # @icloud.com, @me.com, or @mac.com
    app_password: str
    imap_host: str = "imap.mail.me.com"
    imap_port: int = 993


class ICloudConnector(GmailConnector):
    """Read-only iCloud Mail connector.
    
    Inherits all functionality from GmailConnector,
    just uses different default server settings.
    """
    
    def __init__(self, config: ICloudConfig):
        # Convert to parent's config format
        from airlock.connectors.gmail import GmailConfig
        gmail_config = GmailConfig(
            email=config.email,
            app_password=config.app_password,
            imap_host=config.imap_host,
            imap_port=config.imap_port,
        )
        super().__init__(gmail_config)
        self._service_name = "icloud"
    
    @property
    def service_name(self) -> str:
        return self._service_name
