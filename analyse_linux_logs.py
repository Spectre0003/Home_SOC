#!/usr/bin/env python3

import re
import glob

LOG_DIR = "/home/socadmin/homesoc/logs"

print("[+] Linux Log Analyzer")
print("[+] Scanning logs...\n")

failed_logins = []
successful_logins = []
sudo_commands = []
sudo_failures = []

# Used to prevent duplicate events from overlapping log snapshots
seen_failed = set()
seen_successful = set()
seen_sudo_commands = set()
seen_sudo_failures = set()

for logfile in glob.glob(f"{LOG_DIR}/auth_*.log"):

    print(f"[*] Reading: {logfile}")

    with open(logfile, "r", errors="ignore") as f:

        for line in f:
            line = line.strip()

            # ---------------------------------
            # SSH / Login Detection
            # ---------------------------------

            if "Failed password" in line:

                if line not in seen_failed:
                    seen_failed.add(line)
                    failed_logins.append(line)

            elif "Accepted password" in line or "Accepted publickey" in line:

                if line not in seen_successful:
                    seen_successful.add(line)
                    successful_logins.append(line)

            # ---------------------------------
            # Sudo Detection
            # ---------------------------------

            if "sudo:" in line:

                if "authentication failure" in line:

                    if line not in seen_sudo_failures:
                        seen_sudo_failures.add(line)
                        sudo_failures.append(line)

                elif "COMMAND=" in line:

                    if line not in seen_sudo_commands:
                        seen_sudo_commands.add(line)
                        sudo_commands.append(line)


# =============================================
# RESULTS
# =============================================

print("\n========== RESULTS ==========")

print(f"\n[!] Failed login attempts: {len(failed_logins)}")

for event in failed_logins:
    print(f"    {event}")


print(f"\n[+] Successful login attempts: {len(successful_logins)}")

for event in successful_logins:
    print(f"    {event}")


print(f"\n[*] Sudo commands executed: {len(sudo_commands)}")

for event in sudo_commands:
    print(f"    {event}")


print(f"\n[!] Sudo authentication failures: {len(sudo_failures)}")

for event in sudo_failures:
    print(f"    {event}")


# =============================================
# BASIC DETECTION RULES
# =============================================

print("\n========== DETECTIONS ==========")

# Rule 1: Multiple failed logins
if len(failed_logins) >= 5:
    print("[ALERT] Multiple failed login attempts detected.")

# Rule 2: Sudo authentication failure
if len(sudo_failures) > 0:
    print("[ALERT] Sudo authentication failure detected.")

# Rule 3: Successful SSH login
if len(successful_logins) > 0:
    print("[INFO] Successful SSH/login activity detected.")

# Rule 4: Sudo command execution
if len(sudo_commands) > 0:
    print("[INFO] Sudo command execution detected.")

if (
    len(failed_logins) == 0
    and len(sudo_failures) == 0
    and len(successful_logins) == 0
    and len(sudo_commands) == 0
):
    print("[OK] No security-relevant events detected.")


print("\n[+] Analysis complete.")