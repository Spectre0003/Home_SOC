#!/usr/bin/env python3

import re
import json
import html
from datetime import datetime
from collections import Counter


# =============================================
# CONFIGURATION
# =============================================

LOG_DIR = "/home/socadmin/homesoc/logs"
ALERT_LOG = f"{LOG_DIR}/alerts.log"
INCIDENT_LOG = f"{LOG_DIR}/incidents.log"
ACTION_LOG = f"{LOG_DIR}/actions.log"

OUTPUT_FILE = "/home/socadmin/homesoc/dashboard.html"

RECENT_LIMIT = 10


print("========================================")
print("        HOME SOC DASHBOARD GENERATOR")
print("========================================")


# =============================================
# HELPER: SEVERITY
# (mirrors alert_summary.py / generate_incidents.py)
# =============================================

def get_severity(message):

    if "Authentication attack pattern detected" in message:

        return "CRITICAL"

    elif "Brute-force activity detected" in message:

        return "HIGH"

    else:

        return "MEDIUM"


# =============================================
# LOAD ALERTS
# =============================================

alert_severity_count = Counter()
ip_count = Counter()

total_alerts = 0

try:

    with open(ALERT_LOG, "r", errors="ignore") as f:

        for line in f:

            line = line.strip()

            if not line or "[ALERT]" not in line:

                continue

            total_alerts += 1

            severity = get_severity(line)

            alert_severity_count[severity] += 1

            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):

                ip_count[ip] += 1

except FileNotFoundError:

    print(f"\n[!] Alert log not found: {ALERT_LOG}")


# =============================================
# LOAD INCIDENTS
# =============================================

incidents = []

try:

    with open(INCIDENT_LOG, "r", errors="ignore") as f:

        for line in f:

            line = line.strip()

            if not line:

                continue

            try:

                incidents.append(json.loads(line))

            except json.JSONDecodeError:

                continue

except FileNotFoundError:

    print(f"\n[!] Incident log not found: {INCIDENT_LOG}")


incident_severity_count = Counter(
    incident.get("severity", "UNKNOWN") for incident in incidents
)

open_incidents = sum(
    1 for incident in incidents if incident.get("status") == "open"
)


# =============================================
# LOAD RESPONSE ACTIONS
# =============================================

actions = []

try:

    with open(ACTION_LOG, "r", errors="ignore") as f:

        for line in f:

            line = line.strip()

            if not line:

                continue

            try:

                actions.append(json.loads(line))

            except json.JSONDecodeError:

                continue

except FileNotFoundError:

    print(f"\n[!] Action log not found: {ACTION_LOG}")
    print("[!] Continuing without response action data.")


# =============================================
# BUILD HTML FRAGMENTS
# =============================================

def severity_class(severity):

    return {
        "CRITICAL": "sev-critical",
        "HIGH": "sev-high",
        "MEDIUM": "sev-medium"
    }.get(severity, "sev-unknown")


def build_ip_rows():

    rows = ""

    for ip, count in ip_count.most_common(10):

        rows += (
            f"<tr><td>{html.escape(ip)}</td>"
            f"<td>{count}</td></tr>\n"
        )

    if not rows:

        rows = "<tr><td colspan='2'>No source IPs recorded.</td></tr>"

    return rows


def build_incident_rows():

    rows = ""

    recent = list(reversed(incidents))[:RECENT_LIMIT]

    for incident in recent:

        severity = incident.get("severity", "UNKNOWN")

        rows += (
            "<tr>"
            f"<td>{html.escape(str(incident.get('incident_id', '')))}</td>"
            f"<td>{html.escape(str(incident.get('timestamp', '')))}</td>"
            f"<td><span class='badge {severity_class(severity)}'>{html.escape(severity)}</span></td>"
            f"<td>{html.escape(str(incident.get('source_ip') or '-'))}</td>"
            f"<td>{html.escape(str(incident.get('target_account') or '-'))}</td>"
            f"<td>{html.escape(str(incident.get('status', '')))}</td>"
            "</tr>\n"
        )

    if not rows:

        rows = "<tr><td colspan='6'>No incidents recorded.</td></tr>"

    return rows


def build_action_rows():

    rows = ""

    recent = list(reversed(actions))[:RECENT_LIMIT]

    for action in recent:

        rows += (
            "<tr>"
            f"<td>{html.escape(str(action.get('action_id', '')))}</td>"
            f"<td>{html.escape(str(action.get('incident_id', '')))}</td>"
            f"<td>{html.escape(str(action.get('target', '')))}</td>"
            f"<td>{html.escape(str(action.get('status', '')))}</td>"
            f"<td>{html.escape(str(action.get('timestamp', '')))}</td>"
            "</tr>\n"
        )

    if not rows:

        rows = "<tr><td colspan='5'>No response actions recorded.</td></tr>"

    return rows


# =============================================
# ASSEMBLE HTML
# =============================================

generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

html_output = f"""<!DOCTYPE html>
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
    <div class="card"><div class="value">{alert_severity_count.get('CRITICAL', 0)}</div><div class="label">Critical Alerts</div></div>
    <div class="card"><div class="value">{alert_severity_count.get('HIGH', 0)}</div><div class="label">High Alerts</div></div>
    <div class="card"><div class="value">{alert_severity_count.get('MEDIUM', 0)}</div><div class="label">Medium Alerts</div></div>
    <div class="card"><div class="value">{len(incidents)}</div><div class="label">Total Incidents</div></div>
    <div class="card"><div class="value">{open_incidents}</div><div class="label">Open Incidents</div></div>
    <div class="card"><div class="value">{len(actions)}</div><div class="label">Response Actions</div></div>
</div>

<h2>Top Source IPs</h2>
<table>
    <tr><th>Source IP</th><th>Alert Count</th></tr>
    {build_ip_rows()}
</table>

<h2>Recent Incidents</h2>
<table>
    <tr><th>Incident ID</th><th>Timestamp</th><th>Severity</th><th>Source IP</th><th>Account</th><th>Status</th></tr>
    {build_incident_rows()}
</table>

<h2>Recent Response Actions</h2>
<table>
    <tr><th>Action ID</th><th>Incident ID</th><th>Target</th><th>Status</th><th>Timestamp</th></tr>
    {build_action_rows()}
</table>

<footer>Home SOC — log-only lab environment. All response actions are simulated.</footer>

</body>
</html>
"""


# =============================================
# WRITE FILE
# =============================================

try:

    with open(OUTPUT_FILE, "w") as f:

        f.write(html_output)

except PermissionError:

    print(f"\n[!] Permission denied: {OUTPUT_FILE}")
    exit()


# =============================================
# SUMMARY
# =============================================

print(f"\n[+] Total alerts:     {total_alerts}")
print(f"[+] Total incidents:  {len(incidents)} ({open_incidents} open)")
print(f"[+] Response actions: {len(actions)}")
print(f"\n[+] Dashboard written to: {OUTPUT_FILE}")
print("\n[+] Dashboard generation complete.")
