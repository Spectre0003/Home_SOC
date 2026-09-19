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


def linux_hostname(line: str) -> Optional[str]:
    """
    Hostname field from a syslog-style auth.log line.

    Both timestamp formats are followed by the same shape:
    ``<hostname> <process>[pid]: message``. Returns None if the line has
    no recognisable leading timestamp — a continuation line, or
    something that is not a syslog line at all.
    """

    if not line:
        return None

    match = LINUX_TS_RFC3339.search(line) or LINUX_TS_SYSLOG.search(line)

    if not match:
        return None

    remainder = line[match.end():].lstrip()

    token = remainder.split(None, 1)

    return token[0] if token else None


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
#
# The rendered-text parsing that used to live here (split_windows_events,
# windows_event_id, windows_account, windows_source_ip,
# parse_windows_timestamp, and the regexes behind them) is retired as of
# Stage 2 pass 2e. homesoc.parse.windows reads structured Windows Event
# XML instead, where TimeCreated is always UTC and TargetUserName means
# the same thing regardless of event ID — there is nothing left to
# anchor to or guess at a timezone for. See that module.
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
