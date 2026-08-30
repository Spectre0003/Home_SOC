#!/usr/bin/env python3

import re
from collections import Counter
from datetime import datetime


# =============================================
# CONFIGURATION
# =============================================

LOG_DIR = "/home/socadmin/homesoc/logs"
ALERT_LOG = f"{LOG_DIR}/alerts.log"


# =============================================
# STARTUP
# =============================================

print("========================================")
print("        HOME SOC ALERT SUMMARY")
print("========================================")


# =============================================
# CHECK ALERT LOG
# =============================================

try:

    with open(ALERT_LOG, "r", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip()]

except FileNotFoundError:

    print("\n[!] Alert log not found.")
    print(f"[!] Expected: {ALERT_LOG}")
    exit()

except PermissionError:

    print("\n[!] Permission denied.")
    exit()


if not lines:

    print("\n[OK] No alerts recorded.")
    exit()


# =============================================
# ALERT STORAGE
# =============================================

alerts = []

severity_count = Counter()
ip_count = Counter()


# =============================================
# PROCESS ALERTS
# =============================================

for line in lines:

    severity = "MEDIUM"

    # -----------------------------------------
    # CRITICAL
    # -----------------------------------------

    if "Authentication attack pattern detected" in line:

        severity = "CRITICAL"


    # -----------------------------------------
    # HIGH
    # -----------------------------------------

    elif "Brute-force activity detected" in line:

        severity = "HIGH"


    # -----------------------------------------
    # MEDIUM
    # -----------------------------------------

    elif "Multiple failed login attempts detected" in line:

        severity = "MEDIUM"

    elif "Sudo authentication failure detected" in line:

        severity = "MEDIUM"


    # -----------------------------------------
    # COUNT SEVERITY
    # -----------------------------------------

    severity_count[severity] += 1


    # -----------------------------------------
    # EXTRACT SOURCE IP
    # -----------------------------------------

    ip_matches = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        line
    )

    for ip in ip_matches:

        ip_count[ip] += 1


    # -----------------------------------------
    # STORE ALERT
    # -----------------------------------------

    alerts.append({
        "severity": severity,
        "message": line
    })


# =============================================
# SUMMARY
# =============================================

print("\n========== ALERT OVERVIEW ==========")

print(f"\n[+] Total alerts: {len(alerts)}")

print(
    f"[!] Critical: "
    f"{severity_count['CRITICAL']}"
)

print(
    f"[!] High:     "
    f"{severity_count['HIGH']}"
)

print(
    f"[!] Medium:   "
    f"{severity_count['MEDIUM']}"
)


# =============================================
# TOP SOURCE IPS
# =============================================

print("\n========== TOP SOURCE IPS ==========")

if ip_count:

    for ip, count in ip_count.most_common(10):

        print(
            f"[!] {ip}: "
            f"{count} alert(s)"
        )

else:

    print("[OK] No source IPs identified.")


# =============================================
# RECENT ALERTS
# =============================================

print("\n========== RECENT ALERTS ==========")

recent_alerts = alerts[-10:]


for alert in recent_alerts:

    print(
        f"[{alert['severity']}] "
        f"{alert['message']}"
    )


# =============================================
# ANALYSIS
# =============================================

print("\n========== ANALYSIS ==========")


if severity_count["CRITICAL"] > 0:

    print(
        "[CRITICAL] Correlated authentication "
        "attack activity detected."
    )

elif severity_count["HIGH"] > 0:

    print(
        "[HIGH] Brute-force activity detected."
    )

elif severity_count["MEDIUM"] > 0:

    print(
        "[MEDIUM] Authentication or privilege "
        "related alerts detected."
    )

else:

    print("[OK] No significant threats detected.")


# =============================================
# COMPLETE
# =============================================

print("\n[+] Alert summary complete.")