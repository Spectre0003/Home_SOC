#!/usr/bin/env python3

import re
import glob
from datetime import datetime


# =============================================
# CONFIGURATION
# =============================================

LOG_DIR = "/home/socadmin/homesoc/logs"
ALERT_LOG = f"{LOG_DIR}/alerts.log"


print("[+] Linux Log Analyzer")
print("[+] Scanning logs...\n")


# =============================================
# STORAGE
# =============================================

failed_logins = []
successful_logins = []
sudo_commands = []
sudo_failures = []

failed_ips = {}


# =============================================
# LOG COLLECTION / PARSING
# =============================================

for logfile in glob.glob(f"{LOG_DIR}/auth_*.log"):

    print(f"[*] Reading: {logfile}")

    try:

        with open(logfile, "r", errors="ignore") as f:

            for line in f:

                line = line.strip()


                # ---------------------------------
                # SSH / LOGIN DETECTION
                # ---------------------------------

                if "Failed password" in line:

                    failed_logins.append(line)


                    # Extract source IP

                    match = re.search(
                        r"Failed password .* from (\d+\.\d+\.\d+\.\d+)",
                        line
                    )


                    if match:

                        ip = match.group(1)


                        if ip not in failed_ips:

                            failed_ips[ip] = 0


                        failed_ips[ip] += 1


                elif (
                    "Accepted password" in line
                    or "Accepted publickey" in line
                ):

                    successful_logins.append(line)


                # ---------------------------------
                # SUDO DETECTION
                # ---------------------------------

                if "sudo:" in line:

                    if "authentication failure" in line:

                        sudo_failures.append(line)

                    elif "COMMAND=" in line:

                        sudo_commands.append(line)


    except PermissionError:

        print(f"[!] Permission denied: {logfile}")

        continue


# =============================================
# RESULTS
# =============================================

print("\n========== RESULTS ==========")


# ---------------------------------------------
# FAILED LOGINS
# ---------------------------------------------

print(
    f"\n[!] Failed login attempts: "
    f"{len(failed_logins)}"
)


for event in failed_logins:

    print(f"    {event}")


# ---------------------------------------------
# SUCCESSFUL LOGINS
# ---------------------------------------------

print(
    f"\n[+] Successful login attempts: "
    f"{len(successful_logins)}"
)


for event in successful_logins:

    print(f"    {event}")


# ---------------------------------------------
# SUDO COMMANDS
# ---------------------------------------------

print(
    f"\n[*] Sudo commands executed: "
    f"{len(sudo_commands)}"
)


for event in sudo_commands:

    print(f"    {event}")


# ---------------------------------------------
# SUDO FAILURES
# ---------------------------------------------

print(
    f"\n[!] Sudo authentication failures: "
    f"{len(sudo_failures)}"
)


for event in sudo_failures:

    print(f"    {event}")


# =============================================
# FAILED LOGINS BY IP
# =============================================

print("\n========== FAILED LOGINS BY IP ==========")


if failed_ips:

    for ip, count in failed_ips.items():

        print(
            f"[!] {ip}: "
            f"{count} failed attempt(s)"
        )

else:

    print(
        "[+] No failed login attempts "
        "by IP detected."
    )


# =============================================
# DETECTION RULES
# =============================================

print("\n========== DETECTIONS ==========")

alerts = []


# ---------------------------------------------
# RULE 1: MULTIPLE FAILED LOGINS
# ---------------------------------------------

if len(failed_logins) >= 5:

    alert = (
        "Multiple failed login attempts detected."
    )

    print(f"[ALERT] {alert}")

    alerts.append(alert)


# ---------------------------------------------
# RULE 2: BRUTE-FORCE ACTIVITY BY IP
# ---------------------------------------------

for ip, count in failed_ips.items():

    if count >= 5:

        alert = (
            f"Brute-force activity detected from "
            f"{ip} ({count} failed login attempts)."
        )

        print(f"[ALERT] {alert}")

        alerts.append(alert)


# ---------------------------------------------
# RULE 3: SUDO AUTHENTICATION FAILURE
# ---------------------------------------------

if len(sudo_failures) > 0:

    alert = (
        "Sudo authentication failure detected."
    )

    print(f"[ALERT] {alert}")

    alerts.append(alert)


# ---------------------------------------------
# RULE 4: SUCCESSFUL SSH LOGIN
# ---------------------------------------------

if len(successful_logins) > 0:

    message = (
        "Successful SSH/login activity detected."
    )

    print(f"[INFO] {message}")


# ---------------------------------------------
# RULE 5: SUDO COMMAND EXECUTION
# ---------------------------------------------

if len(sudo_commands) > 0:

    message = (
        "Sudo command execution detected."
    )

    print(f"[INFO] {message}")


# =============================================
# WRITE ALERTS TO FILE
# =============================================

if alerts:

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    try:

        with open(ALERT_LOG, "a") as f:

            for alert in alerts:

                f.write(
                    f"{timestamp} [ALERT] "
                    f"{alert}\n"
                )


        print(
            f"\n[+] Alerts written to: "
            f"{ALERT_LOG}"
        )


    except PermissionError:

        print(
            f"\n[!] Permission denied: "
            f"{ALERT_LOG}"
        )


else:

    print("\n[OK] No alerts generated.")


# =============================================
# COMPLETE
# =============================================

print("\n[+] Analysis complete.")