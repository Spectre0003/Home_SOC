"""
Automated response — simulated, log-only.

Port of ``automated_response.py``. Qualifying incidents produce an action
record in ``actions.log``. Nothing is enforced: no firewall rule, no
``hosts.deny`` entry, no system change of any kind. The stage exists to
demonstrate the detect-to-respond mechanism, and the ``simulated`` status
plus the explanatory note on every record are there so nobody reading the
log later mistakes it for enforcement.

The severity gate and action type now come from config
(``response.severities``, ``response.action_type``) rather than a
module-level constant, so widening the gate to include HIGH is a config
change rather than an edit.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import List, NamedTuple

from homesoc.common import store
from homesoc.common.log import get_logger

logger = get_logger(__name__)


SIMULATION_NOTE = (
    "Log-only response. No firewall, hosts.deny, or system-level "
    "changes were made."
)


class ResponseResult(NamedTuple):
    """What one response run produced."""

    actions: List[dict]
    already_responded: int
    not_qualifying: int


def build_action(incident: dict, action_type: str, now: str) -> dict:
    """Construct a simulated response action for an incident."""

    incident_id = incident["incident_id"]

    source_ip = incident["source_ip"]

    seed = f"{incident_id}|{source_ip}|{now}"

    action_id = "ACT-" + hashlib.sha256(seed.encode()).hexdigest()[:8].upper()

    return {
        "action_id": action_id,
        "incident_id": incident_id,
        "timestamp": now,
        "action_type": action_type,
        "target": source_ip,
        "reason": incident.get("detection_reason"),
        "status": "simulated",
        "notes": SIMULATION_NOTE,
    }


def respond(config) -> ResponseResult:
    """Evaluate incidents and record simulated response actions."""

    incidents = store.read_jsonl(config.incident_log)

    if not incidents:
        logger.info("No incidents to evaluate")
        return ResponseResult([], 0, 0)

    state = store.StateFile(config.response_state)

    severities = config.response_severities

    action_type = config.get("response.action_type")

    logger.debug(
        "Response gate: severity in %s with a known source IP",
        sorted(severities),
    )

    now = datetime.now().strftime(store.TIMESTAMP_FORMAT)

    actions: List[dict] = []

    already_responded = 0
    not_qualifying = 0

    for incident in incidents:

        incident_id = incident.get("incident_id")

        if not incident_id:
            logger.warning("Incident record with no incident_id, skipping")
            continue

        if incident_id in state:
            already_responded += 1
            continue

        if incident.get("severity") not in severities:
            not_qualifying += 1
            continue

        if not incident.get("source_ip"):

            # A block action needs a target. A CRITICAL incident with no
            # source IP is worth noticing rather than silently counting
            # as "not qualifying" the way v1.0 did.

            logger.warning(
                "%s meets the severity gate but has no source IP — "
                "no action possible",
                incident_id,
            )

            not_qualifying += 1
            continue

        state.add(incident_id)

        actions.append(build_action(incident, action_type, now))

    if actions:

        store.append_jsonl(config.action_log, actions)

        state.flush()

        logger.info("New response actions generated: %d", len(actions))

        for action in actions:
            logger.info(
                "  [SIMULATED] %s - %s %s (incident %s)",
                action["action_id"],
                action["action_type"],
                action["target"],
                action["incident_id"],
            )

        logger.info("Written to %s", config.action_log.name)

    else:
        logger.info("No new incidents required a response action")

    if already_responded:
        logger.info(
            "Incidents already responded to (skipped): %d", already_responded
        )

    if not_qualifying:
        logger.info(
            "Incidents not meeting response criteria (skipped): %d",
            not_qualifying,
        )

    return ResponseResult(
        actions=actions,
        already_responded=already_responded,
        not_qualifying=not_qualifying,
    )
