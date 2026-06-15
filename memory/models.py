"""Finding types written to the shared blackboard by any agent."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class FindingType(str, Enum):
    """All categories of information an agent can record."""

    # Network layer
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    NETWORK_MAP = "network_map"

    # DNS layer
    SUBDOMAIN = "subdomain"
    DNS_RECORD = "dns_record"
    ZONE_XFER = "zone_transfer"

    # Web layer
    WEB_TECH = "web_tech"
    ENDPOINT = "endpoint"
    WEB_FINDING = "web_finding"

    # OSINT layer
    EMAIL = "email"
    CREDENTIAL = "credential"
    EXPOSURE = "exposure"
    ORG_INFO = "org_info"

    # Meta
    NOTE = "note"
    SUMMARY = "summary"


@dataclass
class Finding:
    """A single piece of intelligence written to the blackboard."""

    type: FindingType
    source_agent: str
    data: dict[str, Any]
    id: int = 0
    ts: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    # Deduplication key — if set, store silently drops exact-same-key duplicates.
    # Format convention: "<type>:<value>", e.g. "subdomain:mail.example.com"
    dedup_key: str = ""
    # Set to True by ValidationAgent after noise filtering.
    # Rich findings (WEB_TECH, SERVICE) are auto-confirmed on insert.
    confirmed: bool = False

    def __str__(self) -> str:
        return f"[{self.type.value}] {self.data} (from {self.source_agent})"


@dataclass
class Task:
    """A goal assigned to an agent by the orchestrator."""

    goal: str
    context: dict[str, Any] = field(default_factory=dict)
    id: str = ""
