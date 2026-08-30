#!/usr/bin/env python3

import glob
import re
from datetime import datetime


LOG_DIR = "/home/socadmin/homesoc/logs"
ALERT_LOG = f"{LOG_DIR}/alerts.log"


print("[+] Windows Security Log Analyzer")
print("[+] Scanning Windows security logs...\n")


# =============================================
# FIND WINDOWS LOGS
# =============================================

logfiles = sorted(
    glob.glob(f"{LOG_DIR}/windows_*.log")
)


if not logfiles:

    print("[!] No Windows security logs found.")

    exit()


# Analyze the most recent collected Windows log

logfile = logfiles[-1]

print(f"[*] Reading: {logfile}")


# =============================================
# EVENT STORAGE
# =============================================

successful_logins = []
failed_logins = []
privileged_logins = []

failed_by_account = {}


# =============================================
# READ LOG
# =============================================

try:

    with open(logfile, "r", errors="ignore") as f:

        content = f.read()


except PermissionError:

    print(
        f"[!] Permission denied: {logfile}"
    )

    exit()


# =============================================
# SPLIT INTO EVENT BLOCKS
# =============================================

events = re.split(
    r"\n(?=TimeCreated\s*:)",
    content
)


for event in events:

    event = event.strip()


    if not event:

        continue


    # -----------------------------------------
    # Extract Event ID
    # -----------------------------------------

    event_id_match = re.search(
        r"EventID\s*:\s*(\d+)",
        event
    )


    if not event_id_match:

        continue


    event_id = event_id_match.group(1)


    # -----------------------------------------
    # Event 4624 - Successful Logon
    # -----------------------------------------

    if event_id == "4624":

        successful_logins.append(event)


    # -----------------------------------------
    # Event 4625 - Failed Logon
    # -----------------------------------------

    elif event_id == "4625":

        failed_logins.append(event)


        # Try to identify the account

        account_match = re.search(
            r"Account Name:\s+([^\r\n]+)",
            event
        )


        if account_match:

            account = (
                account_match.group(1).strip()
            )


            failed_by_account[account] = (
                failed_by_account.get(account, 0)
                + 1
            )


    # -----------------------------------------
    # Event 4672 - Special Privileges
    # -----------------------------------------

    elif event_id == "4672":

        privileged_logins.append(event)


# =============================================
# RESULTS
# =============================================

print("\n========== WINDOWS RESULTS ==========")


# ---------------------------------------------
# Successful Logins
# ---------------------------------------------

print(
    f"\n[+] Successful logins: "
    f"{len(successful_logins)}"
)


for event in successful_logins:

    print(
        "    "
        + event.replace(
            "\n",
            "\n    "
        )
    )


# ---------------------------------------------
# Failed Logins
# ---------------------------------------------

print(
    f"\n[!] Failed logins: "
    f"{len(failed_logins)}"
)


for event in failed_logins:

    print(
        "    "
        + event.replace(
            "\n",
            "\n    "
        )
    )


# ---------------------------------------------
# Privileged Logins
# ---------------------------------------------

print(
    f"\n[*] Privileged logon events: "
    f"{len(privileged_logins)}"
)


for event in privileged_logins:

    print(
        "    "
        + event.replace(
            "\n",
            "\n    "
        )
    )


# =============================================
# FAILED LOGINS BY ACCOUNT
# =============================================

if failed_by_account:

    print(
        "\n========== "
        "FAILED LOGINS BY ACCOUNT "
        "=========="
    )


    for account, count in (
        failed_by_account.items()
    ):

        print(
            f"[!] {account}: "
            f"{count} failed attempt(s)"
        )


# =============================================
# DETECTIONS
# =============================================

print(
    "\n========== WINDOWS DETECTIONS =========="
)

alerts = []


# ---------------------------------------------
# Rule 1: Multiple Failed Logins
# ---------------------------------------------

if len(failed_logins) >= 5:

    alert = (
        f"Multiple Windows failed login attempts "
        f"detected ({len(failed_logins)} attempts)."
    )


    print(f"[ALERT] {alert}")

    alerts.append(alert)


# ---------------------------------------------
# Rule 2: Repeated Failed Login Account
# ---------------------------------------------

for account, count in failed_by_account.items():

    if count >= 3:

        alert = (
            f"Repeated failed Windows logins "
            f"detected for account {account} "
            f"({count} attempts)."
        )


        print(f"[ALERT] {alert}")

        alerts.append(alert)


# ---------------------------------------------
# Rule 3: Successful Logins
# ---------------------------------------------

if successful_logins:

    message = (
        f"Successful Windows login activity "
        f"detected ({len(successful_logins)} events)."
    )


    print(f"[INFO] {message}")


# ---------------------------------------------
# Rule 4: Privileged Logons
# ---------------------------------------------

if privileged_logins:

    message = (
        f"Windows privileged logon activity "
        f"detected ({len(privileged_logins)} events)."
    )


    print(f"[INFO] {message}")


# =============================================
# WRITE ALERTS
# =============================================

if alerts:

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


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


else:

    print(
        "\n[OK] No Windows alerts generated."
    )


print(
    "\n[+] Windows analysis complete."
)