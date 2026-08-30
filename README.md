# Home SOC Project — Complete Documentation

## 1. Project Overview

The Home SOC project is a small, locally hosted Security Operations Center environment designed to demonstrate the core workflow of a SOC:

1. Collect security-relevant logs.
2. Store the collected logs centrally.
3. Analyze the logs for suspicious activity.
4. Generate detections/alerts.
5. Automate the collection and analysis process.
6. Build toward a simple monitoring/dashboard layer.

The project currently uses:

- Windows as the primary host system.
- An Ubuntu VM as the Home SOC server.
- SSH for controlled access between systems.
- Bash for Linux log collection and SOC orchestration.
- Python for log analysis and detection logic.
- systemd/journald and traditional Linux authentication logs as data sources.
- cron for scheduled execution.

The current project is functional at the log-collection, analysis, detection, alert-writing, and automated-run stages.

---

# 2. Current Architecture

```text
                    Windows Host
                         |
                         | SSH
                         v
              +----------------------+
              |     Ubuntu VM        |
              |      Home SOC        |
              +----------------------+
                         |
          +--------------+--------------+
          |                             |
          v                             v
   /var/log/auth.log              systemd journal
          |                             |
          +--------------+--------------+
                         |
                         v
              collect_linux_logs.sh
                         |
                         v
                ~/homesoc/logs/
                         |
                         v
                analyze_linux_logs.py
                         |
                         v
                    Detections
                         |
                         v
                    alerts.log
                         |
                         v
                    run_soc.sh
```

---

# 3. Project Directory Structure

The current Home SOC directory is:

```text
/home/socadmin/homesoc/
```

Current structure:

```text
/home/socadmin/homesoc/
├── config/
├── logs/
└── scripts/
```

The `scripts` directory contains the project automation and analysis scripts.

The `logs` directory contains collected authentication logs, journal exports, and the generated alert log.

---

# 4. Log Collection

## 4.1 Linux Authentication Logs

The project collects `/var/log/auth.log`.

This log contains security-relevant authentication and privilege events such as:

- SSH login failures
- Successful SSH logins
- sudo command execution
- sudo authentication failures
- PAM authentication events

Because `/var/log/auth.log` requires elevated privileges to read on this system, the collection script uses `sudo`.

---

## 4.2 System Journal

The project also collects the systemd journal using:

```bash
sudo journalctl --no-pager
```

The output is redirected into a timestamped file.

This provides a broader source of system activity beyond authentication events.

---

# 5. Linux Log Collection Script

File:

```text
/home/socadmin/homesoc/scripts/collect_linux_logs.sh
```

The script:

1. Defines the Home SOC log directory.
2. Generates a timestamp.
3. Creates the log directory if required.
4. Copies `/var/log/auth.log`.
5. Exports the system journal.
6. Saves both outputs using timestamped filenames.

The collection process produces files similar to:

```text
auth_2026-08-30_12-36-48.log
journal_2026-08-30_12-36-48.log
```

The timestamp allows multiple collection runs to coexist instead of overwriting previous evidence.

---

# 6. Permissions and Ownership

Collected authentication logs may initially be owned by `root` because `/var/log/auth.log` is a privileged system log.

Example:

```text
-rw-r----- 1 root socadmin ... auth_2026-08-30_12-36-48.log
```

This caused the Python analyzer to initially receive:

```text
PermissionError: [Errno 13] Permission denied
```

The problem was resolved by adjusting the collected file permissions so that the `socadmin` account could read the files.

The analyzer can now successfully process multiple authentication log files.

---

# 7. Linux Log Analyzer

File:

```text
/home/socadmin/homesoc/scripts/analyze_linux_logs.py
```

The analyzer is written in Python 3.

It scans:

```text
/home/socadmin/homesoc/logs/auth_*.log
```

This means every collected authentication log matching the timestamped `auth_*.log` naming convention is analyzed.

---

# 8. Detection Categories

The analyzer currently detects four main categories.

## 8.1 Failed Login Attempts

The analyzer searches for:

```text
Failed password
```

These events are stored in:

```python
failed_logins
```

Example event:

```text
sshd: Failed password for socadmin from 192.168.8.128 ...
```

The analyzer reports the total number of failed login events.

---

## 8.2 Successful Login Attempts

The analyzer searches for:

```text
Accepted password
```

and:

```text
Accepted publickey
```

These events are stored in:

```python
successful_logins
```

Example:

```text
sshd: Accepted password for socadmin from 192.168.8.128 ...
```

---

## 8.3 Sudo Command Execution

The analyzer searches for:

```text
sudo:
```

and then checks for:

```text
COMMAND=
```

Matching events are stored in:

```python
sudo_commands
```

This provides visibility into commands executed with elevated privileges.

Example:

```text
sudo: socadmin : TTY=pts/0 ; PWD=/home/socadmin ; USER=root ; COMMAND=/usr/bin/...
```

---

## 8.4 Sudo Authentication Failures

The analyzer searches for:

```text
sudo:
```

combined with:

```text
authentication failure
```

These events are stored in:

```python
sudo_failures
```

Example:

```text
sudo: pam_unix(sudo:auth): authentication failure; ...
```

---

# 9. Current Detection Rules

The analyzer currently has four basic detection rules.

## Rule 1 — Multiple Failed Logins

If:

```python
len(failed_logins) >= 5
```

the analyzer generates:

```text
[ALERT] Multiple failed login attempts detected.
```

This represents a basic brute-force / repeated-authentication-failure detection.

---

## Rule 2 — Sudo Authentication Failure

If at least one sudo authentication failure is detected:

```python
len(sudo_failures) > 0
```

the analyzer generates:

```text
[ALERT] Sudo authentication failure detected.
```

---

## Rule 3 — Successful Login

If successful login activity exists:

```python
len(successful_logins) > 0
```

the analyzer generates:

```text
[INFO] Successful SSH/login activity detected.
```

---

## Rule 4 — Sudo Command Execution

If sudo commands are present:

```python
len(sudo_commands) > 0
```

the analyzer generates:

```text
[INFO] Sudo command execution detected.
```

---

# 10. Current Analyzer Output

The analyzer produces four result sections:

```text
========== RESULTS ==========
```

followed by:

```text
[!] Failed login attempts
[+] Successful login attempts
[*] Sudo commands executed
[!] Sudo authentication failures
```

It then produces:

```text
========== DETECTIONS ==========
```

with the applicable detection messages.

Finally:

```text
[+] Analysis complete.
```

---

# 11. Alert Logging

The analyzer has been extended so that generated alerts are also written to:

```text
/home/socadmin/homesoc/logs/alerts.log
```

Example:

```text
2026-08-30 12:34:17 [ALERT] Multiple failed login attempts detected.
2026-08-30 12:34:17 [ALERT] Sudo authentication failure detected.
```

This creates a persistent alert history rather than displaying detections only on the terminal.

The file can be viewed with:

```bash
cat ~/homesoc/logs/alerts.log
```

---

# 12. SOC Runner

The project has a master execution script:

```text
/home/socadmin/homesoc/scripts/run_soc.sh
```

Its purpose is to execute the SOC workflow as a single operation.

Current workflow:

```text
START
  |
  v
Collect Linux logs
  |
  v
Save timestamped logs
  |
  v
Run Python log analyzer
  |
  v
Generate detections
  |
  v
Write alerts.log
  |
  v
SOC run complete
```

The script can be executed with:

```bash
~/homesoc/scripts/run_soc.sh
```

A successful run displays:

```text
==============================
       HOME SOC RUN
==============================

[+] Starting log collection ...
...
[+] Starting log analysis ...
...
[+] Alerts written to: /home/socadmin/homesoc/logs/alerts.log
...
[+] SOC run complete.
```

---

# 13. Scheduled Execution

The system's cron service is enabled and running.

Verified using:

```bash
systemctl status cron --no-pager
```

The output confirmed:

```text
Loaded: loaded (...; enabled)
Active: active (running)
```

Cron activity was also visible in the system journal.

Therefore, scheduled task execution is functioning at the operating-system level.

The SOC runner can be used as the command executed by a cron job.

---

# 14. Testing Performed

The system has been tested by generating real authentication activity.

Observed events include:

### Failed SSH authentication

```text
Failed password for socadmin from 192.168.8.128
```

### Successful SSH authentication

```text
Accepted password for socadmin from 192.168.8.128
```

### Sudo authentication failure

```text
sudo: pam_unix(sudo:auth): authentication failure
```

### Sudo command execution

```text
sudo: socadmin : TTY=pts/0 ; PWD=/home/socadmin ; USER=root ; COMMAND=...
```

The Python analyzer correctly identified these events.

---

# 15. Current Test Results

During testing, the analyzer successfully produced results such as:

```text
Failed login attempts: 8
Successful login attempts: 5
Sudo commands executed: 15
Sudo authentication failures: 1
```

and generated:

```text
[ALERT] Multiple failed login attempts detected.
[ALERT] Sudo authentication failure detected.
[INFO] Successful SSH/login activity detected.
[INFO] Sudo command execution detected.
```

Later automated runs successfully collected additional logs and analyzed the growing set of timestamped authentication files.

The exact counts will naturally increase as more tests and SOC runs are performed.

---

# 16. Important Observation About Repeated Events

The analyzer currently scans every historical file matching:

```text
auth_*.log
```

Therefore, the same original authentication event can appear more than once if multiple collection files contain overlapping data.

This can cause the reported counts to increase even when no new unique event occurred.

For example:

```text
auth_08-53-50.log
auth_09-09-08.log
auth_09-14-19.log
auth_12-22-19.log
```

may contain overlapping portions of `/var/log/auth.log`.

This is acceptable for the current prototype because the primary goal at this stage is demonstrating collection and detection.

A later improvement should introduce event deduplication or incremental log processing.

---

# 17. Current Project Status

## Completed

- [x] Ubuntu Home SOC VM created
- [x] Home SOC directory structure created
- [x] Linux authentication log collection
- [x] systemd journal collection
- [x] Timestamped log storage
- [x] Python log analyzer
- [x] SSH failed-login detection
- [x] SSH successful-login detection
- [x] sudo command detection
- [x] sudo authentication-failure detection
- [x] Basic threshold-based alerting
- [x] Persistent `alerts.log`
- [x] Master `run_soc.sh` workflow
- [x] Cron service verified
- [x] Automated collection/analysis workflow tested
- [x] Real log events generated and detected
- [x] Permission issues during log analysis resolved

---

# 18. Current Limitations

The current Home SOC is intentionally a lightweight prototype.

Known limitations:

1. The analyzer processes historical authentication files every time it runs.
2. Duplicate events can therefore be counted multiple times.
3. Detection rules are currently simple threshold/string-matching rules.
4. Alerts are stored in a flat text file.
5. There is no graphical dashboard yet.
6. There is no centralized Windows log ingestion yet.
7. There is no network telemetry ingestion yet.
8. There is no alert severity classification beyond ALERT/INFO.
9. There is no correlation between multiple event types.
10. There is no automated response/remediation mechanism.

These are future development stages rather than failures of the current implementation.

---

# 19. Recommended Next Development Stages

The remaining work should focus on turning the working prototype into a more complete Home SOC.

## Stage 1 — Improve Detection Quality

Add better detection logic, including:

- Failed-login threshold per source IP
- Failed-login threshold within a time window
- Successful login following multiple failures
- Unusual login sources
- Suspicious sudo activity
- Repeated sudo authentication failures
- SSH activity correlation

The goal is to move from simple string matching toward basic SOC-style correlation.

---

## Stage 2 — Improve Alert Structure

Instead of writing only plain alert messages, introduce structured fields such as:

```text
Timestamp
Severity
Detection
Source
User
Event type
Description
```

A structured format such as CSV or JSON can eventually make alerts easier to consume by a dashboard.

---

## Stage 3 — Windows Log Collection

Extend the SOC to collect security events from the Windows host.

Important Windows Event IDs to investigate include:

```text
4624 — Successful logon
4625 — Failed logon
4672 — Special privileges assigned
4688 — Process creation
4720 — User account created
4732 — Member added to a security-enabled local group
7045 — Service installed
```

The exact events collected should be selected according to the telemetry available on the Windows system.

---

## Stage 4 — Network Visibility

Add network telemetry.

Possible sources include:

- Wireshark
- tcpdump
- Zeek
- connection logs
- firewall logs

The goal is to allow the SOC to correlate host activity with network activity.

---

## Stage 5 — Detection Correlation

Combine different events into a single incident.

Example:

```text
5 failed SSH logins
        +
successful SSH login
        +
sudo command execution
        =
Higher-severity suspicious login incident
```

This is a major step toward realistic SOC analysis.

---

## Stage 6 — Dashboard

Build a simple local dashboard showing:

```text
+--------------------------------------+
|             HOME SOC                 |
+--------------------------------------+
| Alerts        | Failed Logins        |
| 12            | 24                   |
+--------------------------------------+
| Successful Logins | Sudo Events      |
| 7                 | 31               |
+--------------------------------------+
| Recent Alerts                         |
| [ALERT] Multiple SSH failures         |
| [ALERT] Sudo authentication failure   |
+--------------------------------------+
```

The dashboard does not need to be highly polished. Its purpose is to demonstrate that the SOC pipeline can feed a monitoring interface.

---

# 20. Target Final Architecture

The intended final architecture is:

```text
                     +----------------+
                     | Windows Host   |
                     | Security Logs  |
                     +-------+--------+
                             |
                             |
                             v
                     +----------------+
                     | Ubuntu Home SOC|
                     +-------+--------+
                             |
              +--------------+--------------+
              |              |              |
              v              v              v
          Linux Logs    Windows Logs    Network Logs
              |              |              |
              +--------------+--------------+
                             |
                             v
                     +----------------+
                     | Log Processing |
                     +-------+--------+
                             |
                             v
                     +----------------+
                     | Detection      |
                     | Engine         |
                     +-------+--------+
                             |
                             v
                     +----------------+
                     | Alert Store    |
                     +-------+--------+
                             |
                             v
                     +----------------+
                     | Dashboard      |
                     +----------------+
```

---

# 21. Useful Commands

## Run Linux log collection

```bash
~/homesoc/scripts/collect_linux_logs.sh
```

## Run the analyzer

```bash
python3 ~/homesoc/scripts/analyze_linux_logs.py
```

## Run the entire SOC

```bash
~/homesoc/scripts/run_soc.sh
```

## List collected logs

```bash
ls -lh ~/homesoc/logs
```

## View recent alerts

```bash
tail -n 20 ~/homesoc/logs/alerts.log
```

## View authentication log activity

```bash
sudo tail -n 20 /var/log/auth.log
```

## View recent journal entries

```bash
sudo journalctl --no-pager -n 20
```

## Check cron

```bash
systemctl status cron --no-pager
```

## Check SOC scripts

```bash
ls -lh ~/homesoc/scripts
```

---

# 22. Project Learning Outcomes

The project currently demonstrates practical understanding of:

- Linux authentication logging
- `/var/log/auth.log`
- systemd journal
- SSH authentication telemetry
- sudo/PAM events
- Bash scripting
- Python log parsing
- regular expression concepts
- file permissions
- root vs normal-user access
- timestamped evidence collection
- basic detection engineering
- alert generation
- cron scheduling
- SOC workflow automation
- security event triage

The most important concept demonstrated by the project is the complete pipeline:

```text
Telemetry
    ↓
Collection
    ↓
Storage
    ↓
Parsing
    ↓
Detection
    ↓
Alert
    ↓
Monitoring
```

---

# 23. Current Milestone

The Home SOC has moved beyond being a collection of disconnected scripts.

It now has a working end-to-end Linux SOC pipeline:

```text
Linux system activity
        ↓
collect_linux_logs.sh
        ↓
timestamped evidence
        ↓
analyze_linux_logs.py
        ↓
detection rules
        ↓
alerts.log
        ↓
run_soc.sh
        ↓
automated SOC execution
```

The next major milestone is therefore not basic log collection.

The next phase is **improving the detection engine and expanding telemetry**, followed by **visualizing the resulting alerts**.

---

# 24. Project Status Summary

```text
HOME SOC STATUS
===============

Environment             COMPLETE
Directory structure     COMPLETE
Linux log collection    COMPLETE
Journal collection      COMPLETE
Python analyzer         COMPLETE
Basic detections        COMPLETE
Alert logging           COMPLETE
SOC runner              COMPLETE
Cron integration        FUNCTIONAL
Testing                 COMPLETE

Detection improvement   NEXT
Windows telemetry       NEXT
Network telemetry       NEXT
Correlation             NEXT
Dashboard               FINAL MAJOR STAGE
Documentation           CURRENTLY UPDATED
```

The Linux side of the Home SOC is now operational.
