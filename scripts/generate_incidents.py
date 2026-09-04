#!/usr/bin/env python3

import re
import json
import hashlib
from datetime import datetime


# =============================================
# CONFIGURATION
# =============================================

LOG_DIR = "/home/socadmin/homesoc/logs"
ALERT_LOG = f"{LOG_DIR}/alerts.log"
INCIDENT_LOG = f"{LOG_DIR}/incidents.log"
STATE_FILE = f"{LOG_DIR}/incident_state.txt"


print("========================================")
print("      HOME SOC INCIDENT GENERATOR")
print("========================================")


# =============================================
# LOAD PREVIOUSLY PROCESSED ALERTS
# =============================================

seen_fingerprints = set()

try:

    with open(STATE_FILE, "r") as f:

        for line in f:

            line = line.strip()

            if line:

                seen_fingerprints.add(line)

except FileNotFoundError:

    pass


# =============================================
# LOAD ALERTS
# =============================================

try:

    with open(ALERT_LOG, "r", errors="ignore") as f:

        raw_lines = [line.rstrip("\n") for line in f if line.strip()]

except FileNotFoundError:

    print("\n[!] Alert log not found.")
    print(f"[!] Expected: {ALERT_LOG}")
    exit()

except PermissionError:

    print("\n[!] Permission denied.")
    exit()


if not raw_lines:

    print("\n[OK] No alerts to process.")
    exit()


# =============================================
# HELPER: SEVERITY
# (mirrors alert_summary.py classification)
# =============================================

def get_severity(message):

    if "Authentication attack pattern detected" in message:

        return "CRITICAL"

    elif "Brute-force activity detected" in message:

        return "HIGH"

    elif "Multiple failed login attempts detected" in message:

        return "MEDIUM"

    elif "Sudo authentication failure detected" in message:

        return "MEDIUM"

    else:

        return "MEDIUM"


# =============================================
# HELPER: DETECTION REASON
# =============================================

def get_detection_reason(message):

    if "Authentication attack pattern detected" in message:

        return "Correlated authentication attack pattern (failed logins + successful login)"

    elif "Brute-force activity detected" in message:

        return "Brute-force login activity from a single source IP"

    elif "Multiple Windows failed login attempts detected" in message:

        return "Multiple failed Windows login attempts"

    elif "Repeated failed Windows logins detected" in message:

        return "Repeated failed Windows logins against a single account"

    elif "Multiple failed login attempts detected" in message:

        return "Multiple failed Linux login attempts"

    elif "Sudo authentication failure detected" in message:

        return "Sudo authentication failure"

    else:

        return "Unclassified alert"


# =============================================
# HELPER: PLATFORM
# =============================================

def get_platform(message):

    if "Windows" in message:

        return "Windows"

    elif "Authentication attack pattern detected" in message:

        return "Correlated"

    else:

        return "Linux"


# =============================================
# HELPER: FIELD EXTRACTION
# =============================================

def extract_ip(message):

    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)

    return match.group(0) if match else None


def extract_account(message):

    match = re.search(r"for account (\S+)", message)

    return match.group(1) if match else None


def extract_failed_attempts(message):

    match = re.search(r"(\d+) failed login attempts", message)

    if match:

        return int(match.group(1))

    match = re.search(r"\((\d+) attempts\)", message)

    if match:

        return int(match.group(1))

    return None


def extract_successful_auth(message):

    return "successful login" in message.lower()


# =============================================
# PROCESS ALERTS
# =============================================

new_incidents = []
new_fingerprints = []

skipped = 0


for line in raw_lines:

    if "[ALERT]" not in line:

        continue

    fingerprint = hashlib.sha256(line.encode()).hexdigest()

    if fingerprint in seen_fingerprints:

        skipped += 1

        continue

    # -----------------------------------------
    # Split timestamp / message
    # -----------------------------------------

    parts = line.split(" [ALERT] ", 1)

    if len(parts) == 2:

        alert_time = parts[0].strip()
        message = parts[1].strip()

    else:

        alert_time = None
        message = line.strip()

    incident = {
        "incident_id": f"INC-{fingerprint[:8].upper()}",
        "timestamp": alert_time,
        "severity": get_severity(message),
        "platform": get_platform(message),
        "source_ip": extract_ip(message),
        "target_account": extract_account(message),
        "failed_attempts": extract_failed_attempts(message),
        "successful_auth": extract_successful_auth(message),
        "detection_reason": get_detection_reason(message),
        "related_events": message,
        "status": "open"
    }

    new_incidents.append(incident)
    new_fingerprints.append(fingerprint)

    seen_fingerprints.add(fingerprint)


# =============================================
# WRITE INCIDENTS
# =============================================

if new_incidents:

    try:

        with open(INCIDENT_LOG, "a") as f:

            for incident in new_incidents:

                f.write(json.dumps(incident) + "\n")

    except PermissionError:

        print(f"\n[!] Permission denied: {INCIDENT_LOG}")
        exit()

    with open(STATE_FILE, "a") as f:

        for fingerprint in new_fingerprints:

            f.write(fingerprint + "\n")

else:

    print("\n[OK] No new alerts to convert into incidents.")


# =============================================
# SUMMARY
# =============================================

print(f"\n[+] New incidents created: {len(new_incidents)}")
print(f"[+] Alerts already processed (skipped): {skipped}")

if new_incidents:

    print("\n========== NEW INCIDENTS ==========")

    for incident in new_incidents:

        print(
            f"[{incident['severity']}] "
            f"{incident['incident_id']} - "
            f"{incident['detection_reason']}"
        )

    print(f"\n[+] Incidents written to: {INCIDENT_LOG}")
    print(f"[+] Incident state updated: {STATE_FILE}")


print("\n[+] Incident generation complete.")
