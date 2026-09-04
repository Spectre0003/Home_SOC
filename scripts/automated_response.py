#!/usr/bin/env python3

import json
import hashlib
from datetime import datetime


# =============================================
# CONFIGURATION
# =============================================

LOG_DIR = "/home/socadmin/homesoc/logs"
INCIDENT_LOG = f"{LOG_DIR}/incidents.log"
ACTION_LOG = f"{LOG_DIR}/actions.log"
STATE_FILE = f"{LOG_DIR}/response_state.txt"

# Incidents at or above this severity trigger a response action.
# Currently only "CRITICAL" incidents (correlated attack patterns)
# qualify. Widen this if you want HIGH included later.

RESPONSE_SEVERITIES = {"CRITICAL"}


print("========================================")
print("      HOME SOC AUTOMATED RESPONSE")
print("========================================")


# =============================================
# LOAD PREVIOUSLY RESPONDED INCIDENTS
# =============================================

seen_incident_ids = set()

try:

    with open(STATE_FILE, "r") as f:

        for line in f:

            line = line.strip()

            if line:

                seen_incident_ids.add(line)

except FileNotFoundError:

    pass


# =============================================
# LOAD INCIDENTS
# =============================================

try:

    with open(INCIDENT_LOG, "r", errors="ignore") as f:

        raw_lines = [line.strip() for line in f if line.strip()]

except FileNotFoundError:

    print("\n[!] Incident log not found.")
    print(f"[!] Expected: {INCIDENT_LOG}")
    exit()

except PermissionError:

    print("\n[!] Permission denied.")
    exit()


if not raw_lines:

    print("\n[OK] No incidents to evaluate.")
    exit()


# =============================================
# PROCESS INCIDENTS
# =============================================

new_actions = []
new_incident_ids = []

skipped_already_responded = 0
skipped_not_qualifying = 0


for line in raw_lines:

    try:

        incident = json.loads(line)

    except json.JSONDecodeError:

        continue

    incident_id = incident.get("incident_id")

    if not incident_id:

        continue

    # -----------------------------------------
    # Already responded to
    # -----------------------------------------

    if incident_id in seen_incident_ids:

        skipped_already_responded += 1

        continue

    # -----------------------------------------
    # Severity gate
    # -----------------------------------------

    if incident.get("severity") not in RESPONSE_SEVERITIES:

        skipped_not_qualifying += 1

        continue

    # -----------------------------------------
    # Need a target to act on
    # -----------------------------------------

    source_ip = incident.get("source_ip")

    if not source_ip:

        skipped_not_qualifying += 1

        continue

    # -----------------------------------------
    # Build simulated response action
    # -----------------------------------------

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    action_seed = f"{incident_id}|{source_ip}|{now}"

    action_id = "ACT-" + hashlib.sha256(
        action_seed.encode()
    ).hexdigest()[:8].upper()

    action = {
        "action_id": action_id,
        "incident_id": incident_id,
        "timestamp": now,
        "action_type": "block_ip",
        "target": source_ip,
        "reason": incident.get("detection_reason"),
        "status": "simulated",
        "notes": (
            "Log-only response. No firewall, hosts.deny, "
            "or system-level changes were made."
        )
    }

    new_actions.append(action)
    new_incident_ids.append(incident_id)

    seen_incident_ids.add(incident_id)


# =============================================
# WRITE ACTIONS
# =============================================

if new_actions:

    try:

        with open(ACTION_LOG, "a") as f:

            for action in new_actions:

                f.write(json.dumps(action) + "\n")

    except PermissionError:

        print(f"\n[!] Permission denied: {ACTION_LOG}")
        exit()

    with open(STATE_FILE, "a") as f:

        for incident_id in new_incident_ids:

            f.write(incident_id + "\n")

else:

    print("\n[OK] No new incidents required a response action.")


# =============================================
# SUMMARY
# =============================================

print(f"\n[+] New response actions generated: {len(new_actions)}")
print(f"[+] Incidents already responded to (skipped): {skipped_already_responded}")
print(f"[+] Incidents not meeting response criteria (skipped): {skipped_not_qualifying}")

if new_actions:

    print("\n========== NEW RESPONSE ACTIONS ==========")

    for action in new_actions:

        print(
            f"[SIMULATED] {action['action_id']} - "
            f"block {action['target']} "
            f"(incident {action['incident_id']})"
        )

    print(f"\n[+] Actions written to: {ACTION_LOG}")
    print(f"[+] Response state updated: {STATE_FILE}")


print("\n[+] Automated response complete.")
