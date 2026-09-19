"""
Linux authentication log analysis.

Rewired for Stage 2 pass 2d to consume normalized Events from
``homesoc.parse.linux`` instead of scanning raw lines itself. The
regex matching this module carried since Stage 1 — its own copy of
"what does a failed login line look like" — is gone; the parser is now
the only place that decides that.

The other change is what actually fixes roadmap defect D1 in the
running pipeline rather than just demonstrating the fix in isolation:
``homesoc.detect.events.gather_linux_text()`` deduplicates identical
lines across every currently-collected ``auth_*.log`` before this
module counts a single thing. A failed login sitting in five
overlapping collection copies is counted once, not five times.

Thresholds and alert wording are unchanged from v1.0.
"""

from __future__ import annotations

from collections import Counter
from typing import List, NamedTuple

from homesoc.common import store
from homesoc.common.log import get_logger
from homesoc.detect import events
from homesoc.parse import linux as linux_parser
from homesoc.parse.event import ACTION_SSH_LOGIN, ACTION_SUDO_AUTH

logger = get_logger(__name__)


class LinuxResult(NamedTuple):
    """What one analysis run found."""

    failed_logins: int
    successful_logins: int
    sudo_commands: int
    sudo_failures: int
    failed_by_ip: Counter
    alerts: List[str]
    files_read: int


def analyze(config) -> LinuxResult:
    """Analyze collected Linux auth logs and append any alerts."""

    logfiles = events.find_linux_logs(config)

    text = events.gather_linux_text(config)

    parsed = linux_parser.parse_auth_log(text)

    failed = [
        event for event in parsed
        if event.event.action == ACTION_SSH_LOGIN and event.is_failure
    ]

    succeeded = [
        event for event in parsed
        if event.event.action == ACTION_SSH_LOGIN and event.is_success
    ]

    sudo_failures = [
        event for event in parsed
        if event.event.action == ACTION_SUDO_AUTH
    ]

    # count_sudo_commands operates on the same deduplicated text, so
    # informational counts benefit from the D1 fix too, even though
    # sudo command execution isn't modelled as an Event (see
    # homesoc.parse.linux for why).

    sudo_commands = linux_parser.count_sudo_commands(text)

    failed_by_ip: Counter = Counter()

    for event in failed:

        if event.known_source_ip:
            failed_by_ip[event.source.ip] += 1

    # -----------------------------------------
    # Findings
    # -----------------------------------------

    logger.info("Read %d Linux log file(s)", len(logfiles))
    logger.info("Failed logins:        %d", len(failed))
    logger.info("Successful logins:    %d", len(succeeded))
    logger.info("Sudo commands:        %d", sudo_commands)
    logger.info("Sudo auth failures:   %d", len(sudo_failures))

    for ip, count in failed_by_ip.most_common():
        logger.info("  %s: %d failed attempt(s)", ip, count)

    for event in failed + succeeded + sudo_failures:
        logger.debug("%s", event.raw)

    # -----------------------------------------
    # Detection rules
    # -----------------------------------------

    alerts: List[str] = []

    failed_threshold = config.get("detection.linux.failed_login_threshold")

    ip_threshold = config.get("detection.linux.bruteforce_per_ip_threshold")

    # Rule 1 — multiple failed logins overall

    if len(failed) >= failed_threshold:

        alerts.append("Multiple failed login attempts detected.")

    # Rule 2 — brute force from a single source

    for ip, count in failed_by_ip.items():

        if count >= ip_threshold:

            alerts.append(
                f"Brute-force activity detected from {ip} "
                f"({count} failed login attempts)."
            )

    # Rule 3 — sudo authentication failure

    if sudo_failures:

        alerts.append("Sudo authentication failure detected.")

    # Rules 4 and 5 were informational in v1.0 and wrote no alert.

    if succeeded:
        logger.debug("Successful SSH/login activity detected.")

    if sudo_commands:
        logger.debug("Sudo command execution detected.")

    for alert in alerts:
        logger.warning("ALERT %s", alert)

    if alerts:

        store.append_alerts(config.alert_log, alerts)

        logger.info("Wrote %d alert(s) to %s", len(alerts), config.alert_log.name)

    else:
        logger.info("No Linux alerts generated")

    return LinuxResult(
        failed_logins=len(failed),
        successful_logins=len(succeeded),
        sudo_commands=sudo_commands,
        sudo_failures=len(sudo_failures),
        failed_by_ip=failed_by_ip,
        alerts=alerts,
        files_read=len(logfiles),
    )
