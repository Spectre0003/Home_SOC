"""
Dashboard generation.

Port of ``generate_dashboard.py``. Reads the alert, incident, and action
logs and writes a single self-contained ``dashboard.html`` with no
external CSS or JS, so it opens correctly on a machine with no network.

The markup and styling are unchanged from v1.0. The severity
classification comes from ``homesoc.common.classification``, which means
the dashboard and the alert summary can no longer drift apart — the
original had two separate implementations, one of which had no explicit
MEDIUM branches.

This stage writes nothing into the pipeline and keeps no state; it
reflects current totals every time it runs.
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime
from typing import List, NamedTuple

from homesoc.common import patterns, store
from homesoc.common.classification import classify
from homesoc.common.log import get_logger

logger = get_logger(__name__)


SEVERITY_CLASSES = {
    "CRITICAL": "sev-critical",
    "HIGH": "sev-high",
    "MEDIUM": "sev-medium",
}


class DashboardResult(NamedTuple):
    """What one dashboard run summarised."""

    total_alerts: int
    total_incidents: int
    open_incidents: int
    total_actions: int
    output_file: str


def severity_class(severity: str) -> str:
    return SEVERITY_CLASSES.get(severity, "sev-unknown")


def cell(value) -> str:
    """Escape a value for table output, rendering None as a dash."""

    if value is None or value == "":
        return "-"

    return html.escape(str(value))


def build_ip_rows(ip_count: Counter) -> str:

    rows = "".join(
        f"<tr><td>{cell(ip)}</td><td>{count}</td></tr>\n"
        for ip, count in ip_count.most_common(10)
    )

    return rows or "<tr><td colspan='2'>No source IPs recorded.</td></tr>"


def build_incident_rows(incidents: List[dict], limit: int) -> str:

    rows = ""

    for incident in list(reversed(incidents))[:limit]:

        severity = incident.get("severity", "UNKNOWN")

        rows += (
            "<tr>"
            f"<td>{cell(incident.get('incident_id'))}</td>"
            f"<td>{cell(incident.get('timestamp'))}</td>"
            f"<td><span class='badge {severity_class(severity)}'>"
            f"{cell(severity)}</span></td>"
            f"<td>{cell(incident.get('source_ip'))}</td>"
            f"<td>{cell(incident.get('target_account'))}</td>"
            f"<td>{cell(incident.get('status'))}</td>"
            "</tr>\n"
        )

    return rows or "<tr><td colspan='6'>No incidents recorded.</td></tr>"


def build_action_rows(actions: List[dict], limit: int) -> str:

    rows = ""

    for action in list(reversed(actions))[:limit]:

        rows += (
            "<tr>"
            f"<td>{cell(action.get('action_id'))}</td>"
            f"<td>{cell(action.get('incident_id'))}</td>"
            f"<td>{cell(action.get('target'))}</td>"
            f"<td>{cell(action.get('status'))}</td>"
            f"<td>{cell(action.get('timestamp'))}</td>"
            "</tr>\n"
        )

    return rows or "<tr><td colspan='5'>No response actions recorded.</td></tr>"


TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Home SOC Dashboard</title>
<style>
    body {{
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: 'Consolas', 'Courier New', monospace;
        margin: 0;
        padding: 24px;
    }}
    h1 {{
        color: #58a6ff;
        border-bottom: 1px solid #30363d;
        padding-bottom: 12px;
    }}
    h2 {{
        color: #58a6ff;
        margin-top: 36px;
    }}
    .subtitle {{
        color: #8b949e;
        margin-top: -8px;
    }}
    .cards {{
        display: flex;
        flex-wrap: wrap;
        gap: 16px;
        margin-top: 16px;
    }}
    .card {{
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 16px 24px;
        min-width: 160px;
    }}
    .card .value {{
        font-size: 28px;
        font-weight: bold;
    }}
    .card .label {{
        color: #8b949e;
        font-size: 13px;
        text-transform: uppercase;
    }}
    table {{
        border-collapse: collapse;
        width: 100%;
        margin-top: 12px;
        background-color: #161b22;
    }}
    th, td {{
        border: 1px solid #30363d;
        padding: 8px 12px;
        text-align: left;
        font-size: 13px;
    }}
    th {{
        background-color: #21262d;
        color: #8b949e;
        text-transform: uppercase;
    }}
    .badge {{
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }}
    .sev-critical {{ background-color: #f8514933; color: #f85149; }}
    .sev-high     {{ background-color: #db6d2833; color: #db6d28; }}
    .sev-medium   {{ background-color: #58a6ff33; color: #58a6ff; }}
    .sev-unknown  {{ background-color: #8b949e33; color: #8b949e; }}
    footer {{
        color: #8b949e;
        margin-top: 40px;
        font-size: 12px;
    }}
</style>
</head>
<body>

<h1>Home SOC Dashboard</h1>
<p class="subtitle">Generated {generated_at}</p>

<div class="cards">
    <div class="card"><div class="value">{total_alerts}</div><div class="label">Total Alerts</div></div>
    <div class="card"><div class="value">{critical}</div><div class="label">Critical Alerts</div></div>
    <div class="card"><div class="value">{high}</div><div class="label">High Alerts</div></div>
    <div class="card"><div class="value">{medium}</div><div class="label">Medium Alerts</div></div>
    <div class="card"><div class="value">{total_incidents}</div><div class="label">Total Incidents</div></div>
    <div class="card"><div class="value">{open_incidents}</div><div class="label">Open Incidents</div></div>
    <div class="card"><div class="value">{total_actions}</div><div class="label">Response Actions</div></div>
</div>

<h2>Top Source IPs</h2>
<table>
    <tr><th>Source IP</th><th>Alert Count</th></tr>
    {ip_rows}
</table>

<h2>Recent Incidents</h2>
<table>
    <tr><th>Incident ID</th><th>Timestamp</th><th>Severity</th><th>Source IP</th><th>Account</th><th>Status</th></tr>
    {incident_rows}
</table>

<h2>Recent Response Actions</h2>
<table>
    <tr><th>Action ID</th><th>Incident ID</th><th>Target</th><th>Status</th><th>Timestamp</th></tr>
    {action_rows}
</table>

<footer>Home SOC — log-only lab environment. All response actions are simulated.</footer>

</body>
</html>
"""


def generate(config) -> DashboardResult:
    """Build the dashboard from the current alert, incident, and action logs."""

    limit = config.get("reporting.recent_limit")

    severity_count: Counter = Counter()
    ip_count: Counter = Counter()

    total_alerts = 0

    for _, message in store.read_alerts(config.alert_log):

        total_alerts += 1

        severity_count[classify(message).name] += 1

        for ip in patterns.find_ips(message):
            ip_count[ip] += 1

    incidents = store.read_jsonl(config.incident_log)

    actions = store.read_jsonl(config.action_log)

    open_incidents = sum(
        1 for incident in incidents if incident.get("status") == "open"
    )

    output = TEMPLATE.format(
        generated_at=datetime.now().strftime(store.TIMESTAMP_FORMAT),
        total_alerts=total_alerts,
        critical=severity_count.get("CRITICAL", 0),
        high=severity_count.get("HIGH", 0),
        medium=severity_count.get("MEDIUM", 0),
        total_incidents=len(incidents),
        open_incidents=open_incidents,
        total_actions=len(actions),
        ip_rows=build_ip_rows(ip_count),
        incident_rows=build_incident_rows(incidents, limit),
        action_rows=build_action_rows(actions, limit),
    )

    destination = config.dashboard_file

    destination.parent.mkdir(parents=True, exist_ok=True)

    try:
        destination.write_text(output, encoding="utf-8")

    except PermissionError:
        logger.error("Permission denied writing %s", destination)
        raise

    logger.info("Total alerts:     %d", total_alerts)
    logger.info(
        "Total incidents:  %d (%d open)", len(incidents), open_incidents
    )
    logger.info("Response actions: %d", len(actions))
    logger.info("Dashboard written to %s", destination)

    return DashboardResult(
        total_alerts=total_alerts,
        total_incidents=len(incidents),
        open_incidents=open_incidents,
        total_actions=len(actions),
        output_file=str(destination),
    )
