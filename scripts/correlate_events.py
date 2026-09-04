#!/usr/bin/env python3

import glob
import re
import hashlib
from datetime import datetime, timedelta, timezone


LOG_DIR = "/home/socadmin/homesoc/logs"
ALERT_LOG = f"{LOG_DIR}/alerts.log"
STATE_FILE = f"{LOG_DIR}/correlation_state.txt"


print("[+] Home SOC Event Correlator")
print("[+] Correlating authentication events...\n")


# =============================================
# ACCOUNT EXTRACTION
# =============================================
#
# Windows event text contains multiple "Account
# Name:" lines per event (Subject, New Logon,
# Account For Which Logon Failed). Anchor to the
# correct section per event type instead of
# grabbing whichever "Account Name:" comes first.
# =============================================

def extract_windows_account(event_text, event_id):

    if event_id == "4624":

        match = re.search(
            r"New Logon:.*?Account Name:\s+([^\r\n]+)",
            event_text,
            re.DOTALL
        )

    elif event_id == "4625":

        match = re.search(
            r"Account For Which Logon Failed:.*?"
            r"Account Name:\s+([^\r\n]+)",
            event_text,
            re.DOTALL
        )

    else:

        match = re.search(
            r"Account Name:\s+([^\r\n]+)",
            event_text
        )

    if match:

        return match.group(1).strip()

    return "unknown"


# =============================================
# CONFIGURATION
# =============================================

TIME_WINDOW = timedelta(minutes=5)


# Windows logs on this system are recorded in IST.

WINDOWS_TIMEZONE = timezone(
    timedelta(hours=5, minutes=30)
)


# =============================================
# LOAD PREVIOUS CORRELATIONS
# =============================================

seen_correlations = set()


try:

    with open(STATE_FILE, "r") as f:

        for line in f:

            line = line.strip()


            if line:

                seen_correlations.add(line)


except FileNotFoundError:

    pass


# =============================================
# EVENT STORAGE
# =============================================

failed_logins = []
successful_logins = []


# =============================================
# LINUX LOGS
# =============================================

linux_logs = sorted(
    glob.glob(f"{LOG_DIR}/auth_*.log")
)


for logfile in linux_logs:

    print(
        f"[*] Reading Linux log: {logfile}"
    )


    try:

        with open(
            logfile,
            "r",
            errors="ignore"
        ) as f:

            for line in f:

                line = line.strip()


                # ---------------------------------
                # Failed SSH login
                # ---------------------------------

                if "Failed password" in line:

                    timestamp_match = re.search(
                        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+00:00)",
                        line
                    )


                    ip_match = re.search(
                        r"from\s+(\d+\.\d+\.\d+\.\d+)",
                        line
                    )


                    account_match = re.search(
                        r"Failed password for "
                        r"(?:invalid user )?(\S+)",
                        line
                    )


                    if timestamp_match and ip_match:

                        timestamp = datetime.fromisoformat(
                            timestamp_match.group(1)
                        )


                        source_ip = (
                            ip_match.group(1)
                        )


                        account = (
                            account_match.group(1)
                            if account_match
                            else "unknown"
                        )


                        failed_logins.append(
                            {
                                "timestamp": timestamp,
                                "source_ip": source_ip,
                                "account": account,
                                "platform": "Linux"
                            }
                        )


                # ---------------------------------
                # Successful SSH login
                # ---------------------------------

                elif (
                    "Accepted password" in line
                    or "Accepted publickey" in line
                ):

                    timestamp_match = re.search(
                        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+00:00)",
                        line
                    )


                    ip_match = re.search(
                        r"from\s+(\d+\.\d+\.\d+\.\d+)",
                        line
                    )


                    account_match = re.search(
                        r"Accepted "
                        r"(?:password|publickey) "
                        r"for (\S+)",
                        line
                    )


                    if timestamp_match and ip_match:

                        timestamp = datetime.fromisoformat(
                            timestamp_match.group(1)
                        )


                        source_ip = (
                            ip_match.group(1)
                        )


                        account = (
                            account_match.group(1)
                            if account_match
                            else "unknown"
                        )


                        successful_logins.append(
                            {
                                "timestamp": timestamp,
                                "source_ip": source_ip,
                                "account": account,
                                "platform": "Linux"
                            }
                        )


    except PermissionError:

        print(
            f"[!] Permission denied: {logfile}"
        )


# =============================================
# WINDOWS LOGS
# =============================================

windows_logs = sorted(
    glob.glob(f"{LOG_DIR}/windows_*.log")
)


if windows_logs:

    logfile = windows_logs[-1]


    print(
        f"[*] Reading Windows log: {logfile}"
    )


    try:

        with open(
            logfile,
            "r",
            errors="ignore"
        ) as f:

            content = f.read()


    except PermissionError:

        print(
            f"[!] Permission denied: {logfile}"
        )

        content = ""


    # -----------------------------------------
    # Split Windows events
    # -----------------------------------------

    events = re.split(
        r"\n(?=TimeCreated\s*:)",
        content
    )


    for event in events:

        event = event.strip()


        if not event:

            continue


        # -----------------------------------------
        # Event ID
        # -----------------------------------------

        event_id_match = re.search(
            r"EventID\s*:\s*(\d+)",
            event
        )


        if not event_id_match:

            continue


        event_id = (
            event_id_match.group(1)
        )


        # -----------------------------------------
        # Timestamp
        # -----------------------------------------

        timestamp_match = re.search(
            r"TimeCreated\s*:\s*(.+)",
            event
        )


        if not timestamp_match:

            continue


        timestamp_string = (
            timestamp_match.group(1).strip()
        )


        try:

            # Windows timestamp is local IST.

            timestamp = datetime.strptime(
                timestamp_string,
                "%m/%d/%Y %H:%M:%S"
            )


            timestamp = timestamp.replace(
                tzinfo=WINDOWS_TIMEZONE
            )


            # Convert to UTC.

            timestamp = timestamp.astimezone(
                timezone.utc
            )


        except ValueError:

            continue


        # -----------------------------------------
        # Account
        # -----------------------------------------

        account = extract_windows_account(
            event,
            event_id
        )


        # -----------------------------------------
        # Source IP
        # -----------------------------------------

        ip_match = re.search(
            r"Source Network Address:\s+([0-9a-fA-F:.]+)",
            event
        )


        source_ip = (
            ip_match.group(1).strip()
            if ip_match
            else "unknown"
        )


        # -----------------------------------------
        # Windows 4625
        # Failed login
        # -----------------------------------------

        if event_id == "4625":

            failed_logins.append(
                {
                    "timestamp": timestamp,
                    "source_ip": source_ip,
                    "account": account,
                    "platform": "Windows"
                }
            )


        # -----------------------------------------
        # Windows 4624
        # Successful login
        # -----------------------------------------

        elif event_id == "4624":

            successful_logins.append(
                {
                    "timestamp": timestamp,
                    "source_ip": source_ip,
                    "account": account,
                    "platform": "Windows"
                }
            )


# =============================================
# RESULTS
# =============================================

print(
    "\n========== CORRELATION DATA =========="
)


print(
    f"[+] Failed authentication events: "
    f"{len(failed_logins)}"
)


print(
    f"[+] Successful authentication events: "
    f"{len(successful_logins)}"
)


# =============================================
# SORT EVENTS
# =============================================

failed_logins.sort(
    key=lambda event: event["timestamp"]
)


successful_logins.sort(
    key=lambda event: event["timestamp"]
)


# =============================================
# CORRELATION
# =============================================

print(
    "\n========== CORRELATION RESULTS =========="
)


correlation_alerts = []
new_correlation_keys = []


for success in successful_logins:

    success_time = (
        success["timestamp"]
    )

    success_ip = (
        success["source_ip"]
    )

    success_account = (
        success["account"]
    )


    matching_failures = []


    for failure in failed_logins:

        failure_time = (
            failure["timestamp"]
        )


        # -------------------------------------
        # Failure must occur before success
        # -------------------------------------

        if failure_time >= success_time:

            continue


        # -------------------------------------
        # Failure must be within time window
        # -------------------------------------

        if (
            success_time - failure_time
            > TIME_WINDOW
        ):

            continue


        # -------------------------------------
        # Source IP must match
        # -------------------------------------

        if (
            success_ip != "unknown"
            and failure["source_ip"] != "unknown"
            and success_ip != failure["source_ip"]
        ):

            continue


        # -------------------------------------
        # Account must match when known
        # -------------------------------------

        if (
            success_account != "unknown"
            and failure["account"] != "unknown"
            and success_account != failure["account"]
        ):

            continue


        matching_failures.append(
            failure
        )


    # =========================================
    # CORRELATION RULE
    # =========================================

    if len(matching_failures) >= 3:

        first_failure = (
            matching_failures[0]["timestamp"]
        )


        last_failure = (
            matching_failures[-1]["timestamp"]
        )


        # -------------------------------------
        # Create a stable fingerprint
        # -------------------------------------

        correlation_data = (
            f"{success_ip}|"
            f"{success_account}|"
            f"{first_failure.isoformat()}|"
            f"{last_failure.isoformat()}|"
            f"{len(matching_failures)}"
        )


        correlation_key = hashlib.sha256(
            correlation_data.encode()
        ).hexdigest()


        # -------------------------------------
        # Persistent duplicate prevention
        # -------------------------------------

        if correlation_key in seen_correlations:

            continue


        # -------------------------------------
        # Mark as seen
        # -------------------------------------

        seen_correlations.add(
            correlation_key
        )


        new_correlation_keys.append(
            correlation_key
        )


        # -------------------------------------
        # Generate alert
        # -------------------------------------

        alert = (
            f"Authentication attack pattern detected: "
            f"{len(matching_failures)} failed login attempts "
            f"followed by a successful login "
            f"for account {success_account} "
            f"from {success_ip}."
        )


        print(
            f"[ALERT] {alert}"
        )


        correlation_alerts.append(
            alert
        )


# =============================================
# NO NEW CORRELATIONS
# =============================================

if not correlation_alerts:

    print(
        "[OK] No new correlated authentication "
        "attacks detected."
    )


# =============================================
# WRITE ALERTS
# =============================================

if correlation_alerts:

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    with open(ALERT_LOG, "a") as f:

        for alert in correlation_alerts:

            f.write(
                f"{timestamp} [ALERT] "
                f"{alert}\n"
            )


    print(
        f"\n[+] Correlation alerts written to: "
        f"{ALERT_LOG}"
    )


# =============================================
# SAVE CORRELATION STATE
# =============================================

if new_correlation_keys:

    with open(STATE_FILE, "a") as f:

        for key in new_correlation_keys:

            f.write(
                f"{key}\n"
            )


    print(
        f"[+] Correlation state updated: "
        f"{STATE_FILE}"
    )


# =============================================
# COMPLETE
# =============================================

print(
    "\n[+] Correlation complete."
)