"""
Windows Security log analysis.

Rewired for Stage 2 pass 2d to consume normalized Events from
``homesoc.parse.windows``, which reads named ``EventData`` fields
instead of rendered message text. See that module for why this is the
actual fix for the account-anchoring bug (roadmap defect D12) rather
than a better-anchored version of the same approach — the
event-ID-dependent anchoring function this module used to call doesn't
exist any more. There's nothing left to anchor to.

Cross-run collection overlap for Windows (D10) is not addressed here.
That's a property of the *collector* pulling an overlapping range of
events on every run, fixed in pass 2e once it becomes incremental. This
module still only analyzes the single most recent ``windows_*.log``,
matching v1.0.
"""

from __future__ import annotations

from collections import Counter
from typing import List, NamedTuple

from homesoc.common import store
from homesoc.common.log import get_logger
from homesoc.detect import events
from homesoc.parse import windows as windows_parser

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

    text = events.read_text(logfile)

    parsed = windows_parser.parse_windows_security(text)

    failed = [event for event in parsed if event.is_failure]

    succeeded = [event for event in parsed if event.is_success]

    # Not modelled as an Event — see homesoc.parse.windows. A raw count
    # over the same text, for the same informational purpose v1.0 used
    # it for.

    privileged_logins = windows_parser.count_privileged_logons(text)

    failed_by_account: Counter = Counter()

    for event in failed:

        if event.known_user:
            failed_by_account[event.user.name] += 1

    # -----------------------------------------
    # Findings
    # -----------------------------------------

    logger.info("Successful logins:    %d", len(succeeded))
    logger.info("Failed logins:        %d", len(failed))
    logger.info("Privileged logons:    %d", privileged_logins)

    for event in failed + succeeded:

        logger.debug(
            "account=%s ip=%s logon_type=%s outcome=%s status=%s/%s",
            event.user.name,
            event.source.ip,
            event.logon_type,
            event.event.outcome,
            event.status,
            event.sub_status,
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

    if len(failed) >= failed_threshold:

        alerts.append(
            f"Multiple Windows failed login attempts detected "
            f"({len(failed)} attempts)."
        )

    # Rule 2 — repeated failures against one account

    for account, count in failed_by_account.items():

        if count >= account_threshold:

            alerts.append(
                f"Repeated failed Windows logins detected for account "
                f"{account} ({count} attempts)."
            )

    # Rules 3 and 4 were informational in v1.0 and wrote no alert.

    if succeeded:
        logger.debug(
            "Successful Windows login activity detected (%d events)",
            len(succeeded),
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
        successful_logins=len(succeeded),
        failed_logins=len(failed),
        privileged_logins=privileged_logins,
        failed_by_account=failed_by_account,
        alerts=alerts,
        analyzed_file=logfile.name,
    )
