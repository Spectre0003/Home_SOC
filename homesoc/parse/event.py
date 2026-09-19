"""
The normalized event schema.

Every parser (Stage 2 passes 2b, 2c) produces a list of these. Every
detector (pass 2d) consumes them, and never touches a raw log line
directly. That boundary is the point of this stage — v1.0's regexes for
"is this a failed login" were duplicated across the analyzer and the
correlator; from here on they exist once, inside the parser.

Field names loosely follow Elastic Common Schema (ECS), grouped the way
ECS groups them (``event.category``, ``user.name``, ``source.ip``) via
nested dataclasses, since Python attributes can't contain dots. The
vocabulary is intentionally familiar rather than invented, so it reads
the same way to anyone who has looked at ECS, Sigma, or most SIEM
tooling before.

This module defines the schema only. It does no parsing and touches no
files.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# =============================================
# VOCABULARY
# =============================================
#
# Not enforced — a parser can write any string into these fields, and
# nothing here rejects an unrecognised one. Enforcing a closed set
# belongs to the Stage 4 rule schema, which is where a wrong value would
# actually matter (a rule silently never matching). Listed here as the
# vocabulary parsers should use, so two parsers do not invent two names
# for the same thing.
# =============================================

PLATFORM_LINUX = "linux"
PLATFORM_WINDOWS = "windows"

CATEGORY_AUTHENTICATION = "authentication"

ACTION_SSH_LOGIN = "ssh_login"
ACTION_SUDO_AUTH = "sudo_auth"
ACTION_WINDOWS_LOGON = "windows_logon"

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"


# =============================================
# NESTED GROUPS
# =============================================


@dataclass(frozen=True)
class EventInfo:
    """The ``event.*`` group: what kind of thing happened."""

    category: str
    action: str
    outcome: str


@dataclass(frozen=True)
class UserInfo:
    """The ``user.*`` group. ``name`` is None when no account could be determined."""

    name: Optional[str] = None


@dataclass(frozen=True)
class SourceInfo:
    """The ``source.*`` group. ``ip`` is None for a local, non-network logon."""

    ip: Optional[str] = None


# =============================================
# EVENT ID
# =============================================


def compute_event_id(raw: str) -> str:
    """
    Content-addressed identifier for a raw log entry.

    Deliberately a hash of *content only* — not the source filename, not
    a line offset. Collection re-copies the whole auth log on every run
    (roadmap defect D1), so the same physical log line exists in several
    ``auth_*.log`` files under different names. Hashing on content alone
    means every copy of that line produces the same ID, which is what
    makes it possible to recognise "already seen this" across
    overlapping collections rather than only within one file.

    A real collision — two distinct events with byte-identical raw text
    — is not impossible, but sshd includes a PID and port per connection
    and Windows events carry a RecordId, so two genuinely different
    authentication attempts essentially never produce the same raw
    string. This is a reasonable trade, not a guarantee.
    """

    return hashlib.sha256(raw.strip().encode("utf-8")).hexdigest()


# =============================================
# EVENT
# =============================================


@dataclass(frozen=True)
class Event:
    """
    One normalized authentication event.

    Construct with :meth:`Event.create`, not the bare constructor — the
    constructor exists mainly for :meth:`from_dict` to rebuild an event
    that was already fully formed (event_id computed, timestamp already
    UTC) when it was serialized.
    """

    event_id: str
    timestamp: datetime
    platform: str
    event: EventInfo
    user: UserInfo = field(default_factory=UserInfo)
    source: SourceInfo = field(default_factory=SourceInfo)
    host: Optional[str] = None
    logon_type: Optional[int] = None
    status: Optional[str] = None
    sub_status: Optional[str] = None
    raw: str = ""

    # -----------------------------------------
    # Construction
    # -----------------------------------------

    @classmethod
    def create(
        cls,
        *,
        timestamp: datetime,
        platform: str,
        category: str,
        action: str,
        outcome: str,
        raw: str,
        user: Optional[str] = None,
        source_ip: Optional[str] = None,
        host: Optional[str] = None,
        logon_type: Optional[int] = None,
        status: Optional[str] = None,
        sub_status: Optional[str] = None,
    ) -> "Event":
        """
        Build a new event from parsed fields.

        *timestamp* must be timezone-aware; it is converted to UTC. A
        naive datetime is rejected rather than assumed, because a parser
        silently treating an unlabelled time as UTC is exactly the kind
        of bug that only shows up once an event crosses a timezone
        boundary — which is what happened to the Windows side in v1.0.

        *status* and *sub_status* are the raw Windows failure codes
        (e.g. ``"0xC000006A"``) on a 4625 event — left as opaque strings
        rather than decoded to a human label here. A wrong-password
        code and a no-such-account code are the difference between a
        password spray and username enumeration, which is worth
        capturing now even though nothing reads it until later.
        """

        if timestamp.tzinfo is None:
            raise ValueError(
                "Event.create() requires a timezone-aware timestamp; "
                "convert to UTC (or attach the source's tzinfo) in the "
                "parser before constructing the event"
            )

        return cls(
            event_id=compute_event_id(raw),
            timestamp=timestamp.astimezone(timezone.utc),
            platform=platform,
            event=EventInfo(category=category, action=action, outcome=outcome),
            user=UserInfo(name=user),
            source=SourceInfo(ip=source_ip),
            host=host,
            logon_type=logon_type,
            status=status,
            sub_status=sub_status,
            raw=raw,
        )

    # -----------------------------------------
    # Convenience
    # -----------------------------------------

    @property
    def is_failure(self) -> bool:
        return self.event.outcome == OUTCOME_FAILURE

    @property
    def is_success(self) -> bool:
        return self.event.outcome == OUTCOME_SUCCESS

    @property
    def known_user(self) -> bool:
        return self.user.name is not None

    @property
    def known_source_ip(self) -> bool:
        return self.source.ip is not None

    # -----------------------------------------
    # Serialization
    # -----------------------------------------

    def to_dict(self) -> dict:
        """Nested-dict form, matching ECS grouping, for JSON output."""

        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "platform": self.platform,
            "host": self.host,
            "event": {
                "category": self.event.category,
                "action": self.event.action,
                "outcome": self.event.outcome,
            },
            "user": {"name": self.user.name},
            "source": {"ip": self.source.ip},
            "logon_type": self.logon_type,
            "status": self.status,
            "sub_status": self.sub_status,
            "raw": self.raw,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "Event":
        """Rebuild an event from :meth:`to_dict` output."""

        event_data = data.get("event") or {}
        user_data = data.get("user") or {}
        source_data = data.get("source") or {}

        return cls(
            event_id=data["event_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            platform=data["platform"],
            event=EventInfo(
                category=event_data.get("category", ""),
                action=event_data.get("action", ""),
                outcome=event_data.get("outcome", ""),
            ),
            user=UserInfo(name=user_data.get("name")),
            source=SourceInfo(ip=source_data.get("ip")),
            host=data.get("host"),
            logon_type=data.get("logon_type"),
            status=data.get("status"),
            sub_status=data.get("sub_status"),
            raw=data.get("raw", ""),
        )

    @classmethod
    def from_json(cls, text: str) -> "Event":
        return cls.from_dict(json.loads(text))

    def __repr__(self) -> str:
        return (
            f"<Event {self.event_id[:12]} {self.platform} "
            f"{self.event.action} {self.event.outcome} "
            f"user={self.user.name!r} ip={self.source.ip!r} "
            f"at={self.timestamp.isoformat()}>"
        )
