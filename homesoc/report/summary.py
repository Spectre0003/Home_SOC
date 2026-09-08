"""
Alert summary.

Port of ``alert_summary.py``. Reads the accumulated alert log and reports
totals, severity breakdown, top source IPs, and recent alerts.

One behaviour correction, carried from ``store.read_alerts``: v1.0
counted every non-empty line in the alert log as an alert, while the
dashboard filtered on the ``[ALERT]`` marker. A blank line or a stray
note therefore made the summary and the dashboard disagree about the
same file (roadmap defect D7). Both now use the same reader.
"""

from __future__ import annotations

from collections import Counter
from typing import List, NamedTuple, Tuple

from homesoc.common import patterns, store
from homesoc.common.classification import Severity, classify
from homesoc.common.log import get_logger

logger = get_logger(__name__)


class SummaryResult(NamedTuple):
    """Aggregated view of the alert log."""

    total: int
    by_severity: Counter
    by_ip: Counter
    recent: List[Tuple[str, Severity]]


def summarize(config, recent_limit: int = None) -> SummaryResult:
    """Aggregate the alert log and log the summary."""

    if recent_limit is None:
        recent_limit = config.get("reporting.recent_limit")

    by_severity: Counter = Counter()
    by_ip: Counter = Counter()

    alerts: List[Tuple[str, Severity]] = []

    for _, message in store.read_alerts(config.alert_log):

        severity = classify(message)

        by_severity[severity] += 1

        for ip in patterns.find_ips(message):
            by_ip[ip] += 1

        alerts.append((message, severity))

    if not alerts:

        logger.info("No alerts recorded in %s", config.alert_log.name)

        return SummaryResult(0, by_severity, by_ip, [])

    # -----------------------------------------
    # Overview
    # -----------------------------------------

    logger.info("Total alerts: %d", len(alerts))

    for severity in sorted(Severity, reverse=True):

        count = by_severity.get(severity, 0)

        if count:
            logger.info("  %-8s %d", severity.name, count)

    # -----------------------------------------
    # Top sources
    # -----------------------------------------

    if by_ip:

        logger.info("Top source IPs:")

        for ip, count in by_ip.most_common(10):

            private = "" if patterns.is_private(ip) else "  (external)"

            logger.info("  %-16s %d alert(s)%s", ip, count, private)

    else:
        logger.info("No source IPs identified")

    # -----------------------------------------
    # Recent
    # -----------------------------------------

    recent = alerts[-recent_limit:]

    logger.info("Most recent %d alert(s):", len(recent))

    for message, severity in recent:
        logger.info("  [%s] %s", severity.name, message)

    # -----------------------------------------
    # Assessment
    # -----------------------------------------

    highest = max(severity for _, severity in alerts)

    if highest >= Severity.CRITICAL:
        logger.warning(
            "Correlated authentication attack activity detected"
        )

    elif highest >= Severity.HIGH:
        logger.warning("Brute-force activity detected")

    else:
        logger.info("Authentication or privilege related alerts detected")

    return SummaryResult(
        total=len(alerts),
        by_severity=by_severity,
        by_ip=by_ip,
        recent=recent,
    )
