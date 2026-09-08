"""
Shared log patterns and extraction helpers.

Every regex in v1.0 lived inline in whichever script needed it, and
several existed in more than one place — the IPv4 pattern appeared three
times, and the Windows account extractor was duplicated between
``analyze_windows_logs.py`` and ``correlate_events.py``. That duplication
is what allowed the account-extraction bug to be fixed in one file and
not the other during Phase 14.

Patterns are compiled once at import and exposed through small functions
that return parsed values rather than match objects, so callers never
handle a ``None`` match or a group index.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List, Optional


# =============================================
# NETWORK
# =============================================
#
# v1.0 used r"\b(?:\d{1,3}\.){3}\d{1,3}\b", which matches 999.999.999.999
# and any four-part run of digits inside a longer token. This version
# bounds each octet to 0-255.
# =============================================

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

IPV4 = re.compile(rf"\b(?:{_OCTET}\.){{3}}{_OCTET}\b")


def find_ips(text: str) -> List[str]:
    """Every IPv4 address in *text*, in order of appearance."""

    if not text:
        return []

    return IPV4.findall(text)


def first_ip(text: str) -> Optional[str]:
    """The first IPv4 address in *text*, or None."""

    if not text:
        return None

    match = IPV4.search(text)

    return match.group(0) if match else None


def is_private(ip: str) -> bool:
    """
    Whether *ip* is in RFC1918 space.

    Used from Stage 6 onward for enrichment, and useful now for
    separating lab traffic from anything unexpected.
    """

    try:
        octets = [int(part) for part in ip.split(".")]

    except (ValueError, AttributeError):
        return False

    if len(octets) != 4:
        return False

    if octets[0] == 10:
        return True

    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True

    if octets[0] == 192 and octets[1] == 168:
        return True

    return False


# =============================================
# LINUX AUTH LOG
# =============================================

LINUX_FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<account>\S+)"
    r"(?:\s+from\s+(?P<ip>\S+))?"
)

LINUX_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<account>\S+)"
    r"(?:\s+from\s+(?P<ip>\S+))?"
)

LINUX_INVALID_USER = re.compile(r"Invalid user (?P<account>\S+)")


# Timestamps appear in two forms depending on whether auth.log is
# written by rsyslog in traditional format or by systemd-journald with
# RFC3339 timestamps. v1.0 handled only the second, so the correlation
# stage silently produced zero events on any host using the first
# (roadmap defect D5).

LINUX_TS_RFC3339 = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2}))"
)

LINUX_TS_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)


def parse_linux_timestamp(
    line: str, assume_year: Optional[int] = None
) -> Optional[datetime]:
    """
    Timestamp from an auth.log line, as a timezone-aware UTC datetime.

    Handles both RFC3339 (``2026-09-07T04:11:02+00:00``) and traditional
    syslog (``Sep  7 04:11:02``). Traditional syslog carries no year and
    no timezone: the year is taken from *assume_year* or the current
    year, and the time is treated as local to this host, which is what
    rsyslog actually writes.
    """

    if not line:
        return None

    match = LINUX_TS_RFC3339.search(line)

    if match:

        try:
            parsed = datetime.fromisoformat(
                match.group("ts").replace("Z", "+00:00")
            )

        except ValueError:
            return None

        return parsed.astimezone(timezone.utc)

    match = LINUX_TS_SYSLOG.search(line)

    if match:

        year = assume_year or datetime.now().year

        try:
            parsed = datetime.strptime(
                f"{year} {match.group('ts')}", "%Y %b %d %H:%M:%S"
            )

        except ValueError:
            return None

        # No timezone in the log line; assume this host's local time,
        # which is what wrote it.

        return parsed.astimezone().astimezone(timezone.utc)

    return None


# =============================================
# SUDO
# =============================================

SUDO_MARKER = "sudo:"
SUDO_AUTH_FAILURE = "authentication failure"
SUDO_COMMAND = "COMMAND="


def is_sudo_line(line: str) -> bool:
    return SUDO_MARKER in line


def is_sudo_failure(line: str) -> bool:
    return is_sudo_line(line) and SUDO_AUTH_FAILURE in line


def is_sudo_command(line: str) -> bool:
    return is_sudo_line(line) and SUDO_COMMAND in line


# =============================================
# WINDOWS SECURITY EVENTS
# =============================================

WINDOWS_EVENT_SPLIT = re.compile(r"\n(?=TimeCreated\s*:)")

WINDOWS_EVENT_ID = re.compile(r"EventID\s*:\s*(?P<event_id>\d+)")

WINDOWS_TIME_CREATED = re.compile(r"TimeCreated\s*:\s*(?P<ts>.+)")

WINDOWS_SOURCE_IP = re.compile(
    r"Source Network Address:\s+(?P<ip>[0-9a-fA-F:.]+)"
)

# Anchored per event type. A Windows event message contains several
# "Account Name:" lines — under Subject:, New Logon:, and Account For
# Which Logon Failed: — and the first is not reliably the meaningful
# one. Taking the first match is the Phase 14 bug; these anchors are the
# fix, kept in exactly one place this time.

WINDOWS_ACCOUNT_NEW_LOGON = re.compile(
    r"New Logon:.*?Account Name:\s+(?P<account>[^\r\n]+)", re.DOTALL
)

WINDOWS_ACCOUNT_LOGON_FAILED = re.compile(
    r"Account For Which Logon Failed:.*?"
    r"Account Name:\s+(?P<account>[^\r\n]+)",
    re.DOTALL,
)

WINDOWS_ACCOUNT_ANY = re.compile(r"Account Name:\s+(?P<account>[^\r\n]+)")


EVENT_SUCCESSFUL_LOGON = "4624"
EVENT_FAILED_LOGON = "4625"
EVENT_SPECIAL_PRIVILEGES = "4672"


# PowerShell renders TimeCreated according to the endpoint's locale.
# v1.0 accepted one format; a mismatch silently dropped every event via
# a bare `except ValueError: continue`. These are tried in order.

WINDOWS_TIME_FORMATS = (
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%d/%m/%Y %H:%M:%S",
    "%d-%m-%Y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
)


def split_windows_events(content: str) -> List[str]:
    """Split a collected Windows log into individual event blocks."""

    if not content:
        return []

    return [
        block.strip()
        for block in WINDOWS_EVENT_SPLIT.split(content)
        if block.strip()
    ]


def windows_event_id(event_text: str) -> Optional[str]:
    """Event ID of a Windows event block, as a string."""

    match = WINDOWS_EVENT_ID.search(event_text or "")

    return match.group("event_id") if match else None


def windows_account(
    event_text: str, event_id: Optional[str]
) -> Optional[str]:
    """
    Account name for a Windows event, anchored to the correct section.

    4624 reads from ``New Logon:``, 4625 from ``Account For Which Logon
    Failed:``, and anything else falls back to the first ``Account
    Name:`` line.
    """

    if not event_text:
        return None

    if event_id == EVENT_SUCCESSFUL_LOGON:
        pattern = WINDOWS_ACCOUNT_NEW_LOGON

    elif event_id == EVENT_FAILED_LOGON:
        pattern = WINDOWS_ACCOUNT_LOGON_FAILED

    else:
        pattern = WINDOWS_ACCOUNT_ANY

    match = pattern.search(event_text)

    return match.group("account").strip() if match else None


def windows_source_ip(event_text: str) -> Optional[str]:
    """
    Source network address of a Windows event.

    v1.0 substituted the string "unknown" when absent. Returning None
    lets the caller decide, and keeps the placeholder out of stored
    records where it would be indistinguishable from a real value.
    """

    match = WINDOWS_SOURCE_IP.search(event_text or "")

    if not match:
        return None

    value = match.group("ip").strip()

    # Windows writes "-" for local logons with no network source.

    return value if value and value != "-" else None


def parse_windows_timestamp(event_text: str, tzinfo) -> Optional[datetime]:
    """
    Timestamp of a Windows event block, converted to UTC.

    *tzinfo* is the endpoint's timezone, from
    ``config.windows_timezone`` — Windows event logs are rendered in
    local time with no offset attached.
    """

    match = WINDOWS_TIME_CREATED.search(event_text or "")

    if not match:
        return None

    raw = match.group("ts").strip()

    for time_format in WINDOWS_TIME_FORMATS:

        try:
            parsed = datetime.strptime(raw, time_format)

        except ValueError:
            continue

        return parsed.replace(tzinfo=tzinfo).astimezone(timezone.utc)

    return None


# =============================================
# ALERT MESSAGE FIELDS
# =============================================
#
# Extracting structured fields back out of alert text is a workaround
# for alerts being stored as prose. Stage 2 replaces the alert format
# with structured records and these become unnecessary; they exist now
# so generate_incidents.py has one implementation instead of its own.
# =============================================

ALERT_ACCOUNT = re.compile(r"for account (?P<account>\S+)")

ALERT_FAILED_COUNT = re.compile(r"(?P<count>\d+) failed login attempts")

ALERT_ATTEMPT_COUNT = re.compile(r"\((?P<count>\d+) attempts\)")

ALERT_LINE = re.compile(
    r"^(?P<timestamp>.*?)\s+\[ALERT\]\s+(?P<message>.*)$"
)


def alert_account(message: str) -> Optional[str]:
    """Target account named in an alert message."""

    match = ALERT_ACCOUNT.search(message or "")

    if not match:
        return None

    # Trailing punctuation is part of the sentence, not the account.

    return match.group("account").rstrip(".,;:")


def alert_failed_attempts(message: str) -> Optional[int]:
    """Failed-attempt count stated in an alert message."""

    if not message:
        return None

    for pattern in (ALERT_FAILED_COUNT, ALERT_ATTEMPT_COUNT):

        match = pattern.search(message)

        if match:
            return int(match.group("count"))

    return None


def split_alert_line(line: str):
    """
    Split a stored alert line into (timestamp, message).

    Returns (None, line) if the line carries no ``[ALERT]`` marker.
    """

    match = ALERT_LINE.match((line or "").strip())

    if not match:
        return None, (line or "").strip()

    return match.group("timestamp").strip(), match.group("message").strip()
