"""
Windows Security log analysis.

Port of ``analyze_windows_logs.py``. Event handling (4624, 4625, 4672),
thresholds, and alert wording are unchanged.

The account extractor that was fixed during Phase 14 now lives in
``homesoc.common.patterns`` and is shared with the correlation stage.
That duplication is the reason the bug could be fixed in one file and
not the other; there is now one implementation to get wrong.
"""

from __future__ import annotations

from collections import Counter
from typing import List, NamedTuple

from homesoc.common import patterns, store
from homesoc.common.log import get_logger
from homesoc.detect import events

logger = get_logger(__name__)


class WindowsResult(NamedTuple):
    """What one Windows analysis run found."""

    successful_logins: int
    failed_logins: int
    privileged_logins: int
    failed_by_account: Counter
    alerts: List[str]
    analyzed_file: str


def analyze(config) -> WindowsResult:
    """Analyze the most recent Windows Security log."""

    logfile = events.find_latest_windows_log(config)

    if logfile is None:

        return WindowsResult(
            successful_logins=0,
            failed_logins=0,
            privileged_logins=0,
            failed_by_account=Counter(),
            alerts=[],
            analyzed_file="",
        )

    logger.info("Analyzing %s", logfile.name)

    content = events.read_text(logfile)

    successful_logins = 0
    failed_logins = 0
    privileged_logins = 0

    failed_by_account: Counter = Counter()

    unparsed = 0

    for event in events_in(content):

        event_id = patterns.windows_event_id(event)

        if not event_id:
            unparsed += 1
            continue

        if event_id == patterns.EVENT_SUCCESSFUL_LOGON:

            successful_logins += 1

            logger.debug(
                "4624 account=%s ip=%s",
                patterns.windows_account(event, event_id),
                patterns.windows_source_ip(event),
            )

        elif event_id == patterns.EVENT_FAILED_LOGON:

            failed_logins += 1

            account = patterns.windows_account(event, event_id)

            logger.debug(
                "4625 account=%s ip=%s",
                account,
                patterns.windows_source_ip(event),
            )

            if account:
                failed_by_account[account] += 1

        elif event_id == patterns.EVENT_SPECIAL_PRIVILEGES:

            privileged_logins += 1

            logger.debug(
                "4672 account=%s",
                patterns.windows_account(event, event_id),
            )

    # -----------------------------------------
    # Findings
    # -----------------------------------------

    logger.info("Successful logins:    %d", successful_logins)
    logger.info("Failed logins:        %d", failed_logins)
    logger.info("Privileged logons:    %d", privileged_logins)

    if unparsed:
        logger.warning(
            "%d event block(s) had no readable EventID and were skipped",
            unparsed,
        )

    for account, count in failed_by_account.most_common():
        logger.info("  %s: %d failed attempt(s)", account, count)

    # -----------------------------------------
    # Detection rules
    # -----------------------------------------

    alerts: List[str] = []

    failed_threshold = config.get("detection.windows.failed_login_threshold")

    account_threshold = config.get(
        "detection.windows.failed_per_account_threshold"
    )

    # Rule 1 — multiple failed logins overall

    if failed_logins >= failed_threshold:

        alerts.append(
            f"Multiple Windows failed login attempts detected "
            f"({failed_logins} attempts)."
        )

    # Rule 2 — repeated failures against one account

    for account, count in failed_by_account.items():

        if count >= account_threshold:

            alerts.append(
                f"Repeated failed Windows logins detected for account "
                f"{account} ({count} attempts)."
            )

    # Rules 3 and 4 were informational in v1.0 and wrote no alert.

    if successful_logins:
        logger.debug(
            "Successful Windows login activity detected (%d events)",
            successful_logins,
        )

    if privileged_logins:
        logger.debug(
            "Windows privileged logon activity detected (%d events)",
            privileged_logins,
        )

    for alert in alerts:
        logger.warning("ALERT %s", alert)

    if alerts:

        store.append_alerts(config.alert_log, alerts)

        logger.info(
            "Wrote %d alert(s) to %s", len(alerts), config.alert_log.name
        )

    else:
        logger.info("No Windows alerts generated")

    return WindowsResult(
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        privileged_logins=privileged_logins,
        failed_by_account=failed_by_account,
        alerts=alerts,
        analyzed_file=logfile.name,
    )


def events_in(content: str):
    """Yield event blocks from a collected Windows log."""

    for event in patterns.split_windows_events(content):
        yield event
