"""
Linux authentication log parsing.

Turns raw ``auth.log`` text into a list of normalized :class:`Event`
objects. This is a pure function: given text, it returns events. It
does not read files, does not decide what counts as an alert, and does
not know about thresholds — all of that is Stage 2 pass 2d, once
``homesoc.detect`` is rewired to consume this instead of scanning lines
itself.

Two authentication actions are recognised, matching what v1.0 detected:

    ssh_login   — "Failed password" / "Accepted password" / "Accepted publickey"
    sudo_auth   — a sudo PAM authentication failure

Sudo *command execution* (a successful sudo invocation, logged with
``COMMAND=``) is deliberately not modelled as an Event here. It is an
audit record of a command being run, not an authentication outcome —
nothing about it succeeded or failed in the sense this schema captures.
v1.0 only ever used it for an informational log line, never an alert;
:func:`count_sudo_commands` below preserves that without stretching the
schema to cover something it doesn't fit.
"""

from __future__ import annotations

import re
from typing import List, Optional

from homesoc.common import patterns
from homesoc.common.log import get_logger
from homesoc.parse.event import (
    ACTION_SSH_LOGIN,
    ACTION_SUDO_AUTH,
    CATEGORY_AUTHENTICATION,
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    PLATFORM_LINUX,
    Event,
)

logger = get_logger(__name__)


# =============================================
# SUDO FIELD EXTRACTION
# =============================================
#
# A sudo authentication failure is logged by pam_unix roughly as:
#
#   sudo: pam_unix(sudo:auth): authentication failure; logname=
#   uid=1000 euid=0 tty=/dev/pts/0 ruser= rhost=  user=alice
#
# Field order varies across distributions and some fields are commonly
# blank. A generic key=value scan is more robust than anchoring to a
# specific order.
#
# Which field identifies the *invoking* account — the person who
# mistyped their password — is a genuine limitation, not a detail this
# regex gets wrong: for a local terminal session, that account is not
# present in the syslog message at all. ruser/logname, and rhost for
# the source address, are only populated for remote or su-driven
# invocations. "user=" is the *target* account (almost always "root")
# and is not who the parser should report as the actor.
# =============================================

_KV_TOKEN = re.compile(r"(\w+)=(\S*)")


def _sudo_fields(line: str) -> dict:
    return dict(_KV_TOKEN.findall(line))


def _non_empty(value: Optional[str]) -> Optional[str]:
    return value if value else None


def sudo_actor(line: str) -> Optional[str]:
    """
    The account that attempted sudo, where the log line makes it known.

    Returns None when the invocation was from a local terminal session,
    which is the common case and not a parsing failure — the account is
    simply not in the message.
    """

    fields = _sudo_fields(line)

    return _non_empty(fields.get("ruser")) or _non_empty(fields.get("logname"))


def sudo_source_host(line: str) -> Optional[str]:
    """The remote host field, when the sudo invocation came from one."""

    return _non_empty(_sudo_fields(line).get("rhost"))


def _sudo_source_ip(line: str) -> Optional[str]:
    """
    ``rhost`` as a validated IPv4 address, or None.

    ``rhost`` is only populated for a remote-driven sudo invocation —
    the common local-tty case leaves it blank, correctly yielding no
    source IP. When it is present it is usually an address rather than
    a hostname, but it is validated the same way SSH's source IP is
    rather than trusted as-is.
    """

    host = sudo_source_host(line)

    if not host or not patterns.IPV4.fullmatch(host):
        return None

    return host


# =============================================
# SSH LOGIN LINES
# =============================================


def _extract_ip(match, group: str = "ip") -> Optional[str]:
    """
    The IP from a regex match, validated as an actual IPv4 address.

    The capturing group is ``\\S+`` and can therefore match a hostname
    or garbage if the log line's shape is unexpected. Anything that
    doesn't validate as an address is treated as unknown rather than
    stored as a guess.
    """

    if match is None:
        return None

    value = match.group(group)

    if not value or not patterns.IPV4.fullmatch(value):
        return None

    return value


def _ssh_event(line: str, timestamp, host: Optional[str]) -> Optional[Event]:

    if "Failed password" in line:

        match = patterns.LINUX_FAILED_PASSWORD.search(line)

        return Event.create(
            timestamp=timestamp,
            platform=PLATFORM_LINUX,
            category=CATEGORY_AUTHENTICATION,
            action=ACTION_SSH_LOGIN,
            outcome=OUTCOME_FAILURE,
            raw=line,
            user=match.group("account") if match else None,
            source_ip=_extract_ip(match),
            host=host,
        )

    if "Accepted password" in line or "Accepted publickey" in line:

        match = patterns.LINUX_ACCEPTED.search(line)

        return Event.create(
            timestamp=timestamp,
            platform=PLATFORM_LINUX,
            category=CATEGORY_AUTHENTICATION,
            action=ACTION_SSH_LOGIN,
            outcome=OUTCOME_SUCCESS,
            raw=line,
            user=match.group("account") if match else None,
            source_ip=_extract_ip(match),
            host=host,
        )

    return None


def _sudo_event(line: str, timestamp, host: Optional[str]) -> Optional[Event]:

    if not patterns.is_sudo_failure(line):
        return None

    return Event.create(
        timestamp=timestamp,
        platform=PLATFORM_LINUX,
        category=CATEGORY_AUTHENTICATION,
        action=ACTION_SUDO_AUTH,
        outcome=OUTCOME_FAILURE,
        raw=line,
        user=sudo_actor(line),
        source_ip=_sudo_source_ip(line),
        host=host,
    )


# =============================================
# PARSER
# =============================================


def parse_auth_log(
    text: str,
    host: Optional[str] = None,
    assume_year: Optional[int] = None,
) -> List[Event]:
    """
    Parse ``auth.log`` text into a list of authentication Events.

    *host* is used when a line carries no extractable hostname of its
    own — normally not needed, since both timestamp formats are
    followed by one, but kept as a fallback for a log format that omits
    it.

    *assume_year* is passed through to timestamp parsing for
    traditional syslog lines, which carry no year of their own.
    """

    if not text:
        return []

    events: List[Event] = []

    skipped = 0

    for line in text.splitlines():

        line = line.strip()

        if not line:
            continue

        is_ssh = "Failed password" in line or "Accepted password" in line or "Accepted publickey" in line

        is_sudo = patterns.is_sudo_failure(line)

        if not (is_ssh or is_sudo):
            continue

        timestamp = patterns.parse_linux_timestamp(line, assume_year=assume_year)

        if timestamp is None:

            logger.debug("No parseable timestamp, skipping: %s", line[:100])
            skipped += 1
            continue

        line_host = patterns.linux_hostname(line) or host

        event = (
            _ssh_event(line, timestamp, line_host)
            if is_ssh
            else _sudo_event(line, timestamp, line_host)
        )

        if event is not None:
            events.append(event)

    if skipped:
        logger.warning(
            "%d authentication line(s) had no parseable timestamp and "
            "were skipped",
            skipped,
        )

    return events


def count_sudo_commands(text: str) -> int:
    """
    Number of successful sudo command invocations in *text*.

    Not modelled as an Event — see the module docstring. This exists so
    the eventual detector can still report the same informational count
    v1.0 did, without the schema pretending a command execution has a
    success/failure outcome.
    """

    if not text:
        return 0

    return sum(
        1
        for line in text.splitlines()
        if patterns.is_sudo_command(line.strip())
    )
