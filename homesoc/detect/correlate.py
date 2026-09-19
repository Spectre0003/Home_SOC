"""
Cross-platform authentication correlation.

Rewired for Stage 2 pass 2d to consume normalized Events instead of
scanning raw lines with its own regexes. The rule is unchanged: N or
more failed authentications followed by a success, within a time
window, from the same source and account, raises a correlated attack
alert.

Two things actually change behaviour, both deliberate:

Fingerprints are rebuilt from event_id rather than from hand-formatted
``ip|account|timestamp|count`` strings. Event now carries a real
content-addressed identity — leaning on it is simpler and more robust
than reconstructing one, and it removes the need for the "unknown"
sentinel string the old scheme depended on to stay stable. The
consequence: fingerprints computed under the old scheme (whatever is
currently in correlation_state.txt) will not match new ones for the
same underlying attack. Any correlation still present in the retained
logs re-alerts once, on the first run after this lands, then suppresses
correctly on every run after that. This is an unavoidable, one-time
cost of the state having been built on data that D1/D2 were inflating
in the first place — not a new bug.

Both platforms' input now comes pre-deduplicated: Linux via
``homesoc.detect.events.gather_linux_text``, which collapses duplicate
lines across every overlapping ``auth_*.log`` before parsing (roadmap
defect D1). That is what makes the match count behind each fingerprint
stable run to run, which is what actually fixes D2 — D2 was a symptom
of D1's inflation, not a separate bug with its own fix.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import List, NamedTuple

from homesoc.common import store
from homesoc.common.log import get_logger
from homesoc.detect import events
from homesoc.parse import linux as linux_parser
from homesoc.parse import windows as windows_parser
from homesoc.parse.event import ACTION_SSH_LOGIN, ACTION_WINDOWS_LOGON, Event

logger = get_logger(__name__)


# Sudo events don't participate here, matching v1.0: this correlation
# is specifically "repeated remote authentication failures followed by
# a success", not privilege escalation on a box already reached.

_CORRELATABLE_ACTIONS = (ACTION_SSH_LOGIN, ACTION_WINDOWS_LOGON)


class CorrelationResult(NamedTuple):
    """What one correlation run found."""

    failed_events: int
    successful_events: int
    alerts: List[str]
    suppressed: int


# =============================================
# EVENT GATHERING
# =============================================


def gather_events(config) -> List[Event]:
    """
    Every correlatable authentication event across both platforms.

    Linux input is already deduplicated by
    ``events.gather_linux_text``. Windows only ever reads the single
    newest collected file (see ``events.find_latest_windows_log``), so
    it has no equivalent cross-file duplication yet — that's a
    property of the collector, addressed in pass 2e.
    """

    linux_text = events.gather_linux_text(config)

    linux_events = linux_parser.parse_auth_log(linux_text)

    windows_log = events.find_latest_windows_log(config)

    windows_events = (
        windows_parser.parse_windows_security(events.read_text(windows_log))
        if windows_log is not None
        else []
    )

    return [
        event
        for event in linux_events + windows_events
        if event.event.action in _CORRELATABLE_ACTIONS
    ]


# =============================================
# MATCHING
# =============================================


def matches(success: Event, failure: Event, window: timedelta) -> bool:
    """
    Whether *failure* belongs to the run leading up to *success*.

    A field only has to agree when it is known on both sides — an event
    with no source IP is not excluded from correlating with one that
    has it. That is v1.0's behaviour, carried through unchanged; it is
    what lets a Windows 4625 with no network address correlate with a
    subsequent 4624.
    """

    if failure.timestamp >= success.timestamp:
        return False

    if success.timestamp - failure.timestamp > window:
        return False

    if (
        success.known_source_ip
        and failure.known_source_ip
        and success.source.ip != failure.source.ip
    ):
        return False

    if (
        success.known_user
        and failure.known_user
        and success.user.name != failure.user.name
    ):
        return False

    return True


def fingerprint(success: Event, matching: List[Event]) -> str:
    """
    Stable identifier for one correlation.

    Built from the endpoints' own content-addressed event IDs rather
    than a hand-formatted string of fields. This is stable across runs
    precisely because the input feeding it is now deduplicated — the
    same real attack produces the same success event, the same first
    failure, and the same last failure every time it's evaluated.
    """

    data = f"{success.event_id}|{matching[0].event_id}|{matching[-1].event_id}"

    return hashlib.sha256(data.encode()).hexdigest()


# =============================================
# CORRELATION
# =============================================


def correlate(config) -> CorrelationResult:
    """Correlate authentication events and append any new alerts."""

    gathered = gather_events(config)

    failures = sorted(
        (event for event in gathered if event.is_failure),
        key=lambda event: event.timestamp,
    )

    successes = sorted(
        (event for event in gathered if event.is_success),
        key=lambda event: event.timestamp,
    )

    logger.info("Failed authentication events:     %d", len(failures))
    logger.info("Successful authentication events: %d", len(successes))

    state = store.StateFile(config.correlation_state)

    window = config.correlation_window

    min_failures = config.get("correlation.min_failures")

    alerts: List[str] = []

    suppressed = 0

    for success in successes:

        matching = [
            failure
            for failure in failures
            if matches(success, failure, window)
        ]

        if len(matching) < min_failures:
            continue

        key = fingerprint(success, matching)

        if key in state:
            suppressed += 1
            continue

        state.add(key)

        alert = (
            f"Authentication attack pattern detected: "
            f"{len(matching)} failed login attempts "
            f"followed by a successful login "
            f"for account {success.user.name or 'unknown'} "
            f"from {success.source.ip or 'unknown'}."
        )

        logger.warning("ALERT %s", alert)

        alerts.append(alert)

    # -----------------------------------------
    # Persist
    # -----------------------------------------

    if alerts:

        store.append_alerts(config.alert_log, alerts)

        state.flush()

        logger.info(
            "Wrote %d correlation alert(s) to %s",
            len(alerts),
            config.alert_log.name,
        )

    else:
        logger.info("No new correlated authentication attacks detected")

    if suppressed:
        logger.info(
            "%d correlation(s) already reported and suppressed", suppressed
        )

    return CorrelationResult(
        failed_events=len(failures),
        successful_events=len(successes),
        alerts=alerts,
        suppressed=suppressed,
    )
