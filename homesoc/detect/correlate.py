"""
Cross-event authentication correlation.

Port of ``correlate_events.py``. The rule is unchanged: N or more failed
authentications followed by a success, within a time window, from the
same source and against the same account, raises a correlated attack
alert.

Fingerprints are computed exactly as v1.0 computed them — same field
order, same separator, same ``unknown`` sentinel — so correlation state
written before the refactor still suppresses the same correlations
afterwards. This is the reason ``events.UNKNOWN`` exists rather than
plain ``None``.

Two known weaknesses are preserved rather than fixed here, both because
fixing them changes what fires and there is nothing to verify against
until Stage 5 has tests:

  * The fingerprint includes the match count, so the same attack
    re-alerts when a later run counts one more failure — which happens
    routinely, because collection re-copies the whole auth log
    (defects D1 and D2).
  * Matching is O(failures x successes) with no time index. Fine at lab
    volume, quadratic past it (defect D11).
"""

from __future__ import annotations

import hashlib
from typing import List, NamedTuple

from homesoc.common import patterns, store
from homesoc.common.log import get_logger
from homesoc.detect import events
from homesoc.detect.events import UNKNOWN, AuthEvent

logger = get_logger(__name__)


class CorrelationResult(NamedTuple):
    """What one correlation run found."""

    failed_events: int
    successful_events: int
    alerts: List[str]
    suppressed: int


# =============================================
# EVENT GATHERING
# =============================================


def gather_linux_events(config) -> List[AuthEvent]:
    """Authentication events from every collected Linux auth log."""

    gathered: List[AuthEvent] = []

    for logfile in events.find_linux_logs(config):

        logger.debug("Reading %s", logfile.name)

        for line in events.read_text(logfile).splitlines():

            line = line.strip()

            if not line:
                continue

            is_failure = "Failed password" in line

            is_success = (
                "Accepted password" in line or "Accepted publickey" in line
            )

            if not (is_failure or is_success):
                continue

            timestamp = patterns.parse_linux_timestamp(line)

            if timestamp is None:

                # v1.0 required an RFC3339 timestamp and silently
                # discarded anything else. The parser now handles
                # traditional syslog too, so reaching here means the
                # line genuinely has no timestamp.

                logger.debug("No timestamp, skipping: %s", line[:80])
                continue

            pattern = (
                patterns.LINUX_FAILED_PASSWORD
                if is_failure
                else patterns.LINUX_ACCEPTED
            )

            match = pattern.search(line)

            source_ip = events.normalize(
                match.group("ip") if match else None
            )

            account = events.normalize(
                match.group("account") if match else None
            )

            gathered.append(
                AuthEvent(
                    timestamp=timestamp,
                    source_ip=source_ip,
                    account=account,
                    platform="Linux",
                    outcome="failure" if is_failure else "success",
                )
            )

    return gathered


def gather_windows_events(config) -> List[AuthEvent]:
    """Authentication events from the most recent Windows log."""

    logfile = events.find_latest_windows_log(config)

    if logfile is None:
        return []

    logger.debug("Reading %s", logfile.name)

    tzinfo = config.windows_timezone

    gathered: List[AuthEvent] = []

    for event in patterns.split_windows_events(events.read_text(logfile)):

        event_id = patterns.windows_event_id(event)

        if event_id not in (
            patterns.EVENT_SUCCESSFUL_LOGON,
            patterns.EVENT_FAILED_LOGON,
        ):
            continue

        timestamp = patterns.parse_windows_timestamp(event, tzinfo)

        if timestamp is None:

            # v1.0 caught ValueError and continued, so a locale change
            # on the endpoint silently emptied the Windows side of
            # correlation. Several formats are tried now, and reaching
            # here is worth reporting.

            logger.warning(
                "Unrecognised Windows timestamp format, event skipped"
            )
            continue

        gathered.append(
            AuthEvent(
                timestamp=timestamp,
                source_ip=events.normalize(
                    patterns.windows_source_ip(event)
                ),
                account=events.normalize(
                    patterns.windows_account(event, event_id)
                ),
                platform="Windows",
                outcome=(
                    "failure"
                    if event_id == patterns.EVENT_FAILED_LOGON
                    else "success"
                ),
            )
        )

    return gathered


# =============================================
# MATCHING
# =============================================


def matches(success: AuthEvent, failure: AuthEvent, window) -> bool:
    """
    Whether *failure* belongs to the run leading up to *success*.

    A field only has to agree when it is known on both sides — an event
    with no source IP is not excluded from correlating with one that has
    it. That is v1.0's behaviour, and it is what lets a Windows 4625
    with no network address correlate with a subsequent 4624.
    """

    if failure.timestamp >= success.timestamp:
        return False

    if success.timestamp - failure.timestamp > window:
        return False

    if (
        success.known_ip
        and failure.known_ip
        and success.source_ip != failure.source_ip
    ):
        return False

    if (
        success.known_account
        and failure.known_account
        and success.account != failure.account
    ):
        return False

    return True


def fingerprint(success: AuthEvent, matching: List[AuthEvent]) -> str:
    """
    Stable identifier for one correlation.

    Field order and formatting are load-bearing: they must match v1.0
    exactly or every previously-seen correlation re-alerts on the first
    run after upgrading.
    """

    data = (
        f"{success.source_ip}|"
        f"{success.account}|"
        f"{matching[0].timestamp.isoformat()}|"
        f"{matching[-1].timestamp.isoformat()}|"
        f"{len(matching)}"
    )

    return hashlib.sha256(data.encode()).hexdigest()


# =============================================
# CORRELATION
# =============================================


def correlate(config) -> CorrelationResult:
    """Correlate authentication events and append any new alerts."""

    gathered = gather_linux_events(config) + gather_windows_events(config)

    failures = sorted(
        (event for event in gathered if event.outcome == "failure"),
        key=lambda event: event.timestamp,
    )

    successes = sorted(
        (event for event in gathered if event.outcome == "success"),
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
            f"for account {success.account} "
            f"from {success.source_ip}."
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
