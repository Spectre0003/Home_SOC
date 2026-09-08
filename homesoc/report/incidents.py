"""
Incident generation.

Port of ``generate_incidents.py``. Each new alert becomes a structured
incident record in ``incidents.log``, one JSON object per line.

Severity, detection reason, and platform now come from
``homesoc.common.classification`` rather than three local if-chains, and
field extraction from ``homesoc.common.patterns``. The record shape is
unchanged, so existing incidents remain readable by the dashboard.

Known defect preserved deliberately (D4): the fingerprint is a hash of
the whole alert line *including its timestamp*. Because the Linux and
Windows analyzers re-append identical alerts on every run with a fresh
timestamp, each run produces a new fingerprint and therefore a new
incident for the same finding. Fixing it means changing the fingerprint,
which would invalidate every entry in ``incident_state.txt`` and convert
your entire alert history into duplicate incidents on the next run.
Stage 3 handles this properly with a database key on
(rule, entity, window).
"""

from __future__ import annotations

import hashlib
from typing import List, NamedTuple

from homesoc.common import patterns, store
from homesoc.common.classification import classify_all
from homesoc.common.log import get_logger

logger = get_logger(__name__)


class IncidentResult(NamedTuple):
    """What one incident generation run produced."""

    created: List[dict]
    skipped: int


def build_incident(line: str, fingerprint: str) -> dict:
    """Convert one raw alert line into an incident record."""

    alert_time, message = patterns.split_alert_line(line)

    signature = classify_all(message)

    return {
        "incident_id": f"INC-{fingerprint[:8].upper()}",
        "timestamp": alert_time,
        "severity": signature.severity.name,
        "platform": signature.platform,
        "source_ip": patterns.first_ip(message),
        "target_account": patterns.alert_account(message),
        "failed_attempts": patterns.alert_failed_attempts(message),
        "successful_auth": "successful login" in message.lower(),
        "detection_reason": signature.reason,
        "related_events": message,
        "status": "open",
    }


def generate(config) -> IncidentResult:
    """Convert new alerts into incident records."""

    lines = store.read_lines(config.alert_log)

    if not lines:
        logger.info("No alerts to process")
        return IncidentResult([], 0)

    state = store.StateFile(config.incident_state)

    created: List[dict] = []

    skipped = 0

    for line in lines:

        if store.ALERT_MARKER not in line:
            continue

        fingerprint = hashlib.sha256(line.encode()).hexdigest()

        if fingerprint in state:
            skipped += 1
            continue

        state.add(fingerprint)

        created.append(build_incident(line, fingerprint))

    if created:

        store.append_jsonl(config.incident_log, created)

        state.flush()

        logger.info("New incidents created: %d", len(created))

        for incident in created:
            logger.info(
                "  [%s] %s - %s",
                incident["severity"],
                incident["incident_id"],
                incident["detection_reason"],
            )

        logger.info("Written to %s", config.incident_log.name)

    else:
        logger.info("No new alerts to convert into incidents")

    if skipped:
        logger.info("Alerts already processed (skipped): %d", skipped)

    return IncidentResult(created=created, skipped=skipped)
