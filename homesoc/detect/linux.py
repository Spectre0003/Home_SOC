"""
Linux authentication log analysis.

Port of ``analyze_linux_logs.py``. Detection rules, thresholds, and alert
wording are unchanged — thresholds now come from config rather than
being literals, but the defaults reproduce v1.0 exactly.

The one visible difference is output volume. v1.0 printed every matched
line in full: with a Hydra run in the log that is thousands of lines of
console output burying the alerts at the end. Those lines are now DEBUG,
so ``homesoc analyze`` shows findings and ``homesoc -v analyze`` shows
the evidence.
"""

from __future__ import annotations

from collections import Counter
from typing import List, NamedTuple

from homesoc.common import patterns, store
from homesoc.common.log import get_logger
from homesoc.detect import events

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

    failed_logins = 0
    successful_logins = 0
    sudo_commands = 0
    sudo_failures = 0

    failed_by_ip: Counter = Counter()

    for logfile in logfiles:

        logger.debug("Reading %s", logfile.name)

        content = events.read_text(logfile)

        for line in content.splitlines():

            line = line.strip()

            if not line:
                continue

            # ---------------------------------
            # SSH authentication
            # ---------------------------------

            if "Failed password" in line:

                failed_logins += 1

                logger.debug("FAILED  %s", line)

                match = patterns.LINUX_FAILED_PASSWORD.search(line)

                if match and match.group("ip"):

                    ip = match.group("ip")

                    # The IP group is greedy about what follows "from";
                    # validate it before counting it as an address.

                    if patterns.IPV4.fullmatch(ip):
                        failed_by_ip[ip] += 1

            elif (
                "Accepted password" in line
                or "Accepted publickey" in line
            ):

                successful_logins += 1

                logger.debug("SUCCESS %s", line)

            # ---------------------------------
            # sudo
            # ---------------------------------

            if patterns.is_sudo_line(line):

                if patterns.is_sudo_failure(line):

                    sudo_failures += 1

                    logger.debug("SUDO-FAIL %s", line)

                elif patterns.is_sudo_command(line):

                    sudo_commands += 1

                    logger.debug("SUDO-CMD  %s", line)

    # -----------------------------------------
    # Findings
    # -----------------------------------------

    logger.info("Read %d Linux log file(s)", len(logfiles))
    logger.info("Failed logins:        %d", failed_logins)
    logger.info("Successful logins:    %d", successful_logins)
    logger.info("Sudo commands:        %d", sudo_commands)
    logger.info("Sudo auth failures:   %d", sudo_failures)

    for ip, count in failed_by_ip.most_common():
        logger.info("  %s: %d failed attempt(s)", ip, count)

    # -----------------------------------------
    # Detection rules
    # -----------------------------------------

    alerts: List[str] = []

    failed_threshold = config.get("detection.linux.failed_login_threshold")

    ip_threshold = config.get("detection.linux.bruteforce_per_ip_threshold")

    # Rule 1 — multiple failed logins overall

    if failed_logins >= failed_threshold:

        alerts.append("Multiple failed login attempts detected.")

    # Rule 2 — brute force from a single source

    for ip, count in failed_by_ip.items():

        if count >= ip_threshold:

            alerts.append(
                f"Brute-force activity detected from {ip} "
                f"({count} failed login attempts)."
            )

    # Rule 3 — sudo authentication failure

    if sudo_failures > 0:

        alerts.append("Sudo authentication failure detected.")

    # Rules 4 and 5 were informational in v1.0 and wrote no alert.

    if successful_logins:
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
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        sudo_commands=sudo_commands,
        sudo_failures=sudo_failures,
        failed_by_ip=failed_by_ip,
        alerts=alerts,
        files_read=len(logfiles),
    )
