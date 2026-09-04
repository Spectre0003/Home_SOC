# Home SOC — Architecture

## 1. Current Status

The Home SOC has completed its core collection, analysis, detection, correlation, alerting, incident reporting, and automated response pipeline.

**Current phase:** Automated Response → Visualization → Testing → Final Documentation.

## 2. Architecture

```text
                         HOME SOC LAB
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
           Kali            Windows          Ubuntu
         (Testing)         Endpoint        SOC Server
              |               |               |
              |               v               |
              |       Windows Log Collector   |
              |               |               |
              +---------------+---------------+
                              |
                              v
                         LOG STORAGE
                              |
             +----------------+----------------+
             |                                 |
             v                                 v
      Linux Log Analyzer              Windows Log Analyzer
             |                                 |
             +----------------+----------------+
                              |
                              v
                     Event Correlator
                              |
                     +--------+--------+
                     |                 |
                     v                 v
                 alerts.log    correlation_state.txt
                     |
                     v
                 Alert Summary
                     |
                     v
               Incident Generator
                     |
             +-------+-------+
             |               |
             v               v
      incidents.log   incident_state.txt
                     |
                     v
               Automated Response
                     |
             +-------+-------+
             |               |
             v               v
       actions.log   response_state.txt
                     |
                     v
                  Analyst
```

## 3. Project Files

```text
/home/socadmin/homesoc/
|
+-- scripts/
|   +-- collect_linux_logs.sh
|   +-- analyze_linux_logs.py
|   +-- analyze_windows_logs.py
|   +-- correlate_events.py
|   +-- alert_summary.py
|   +-- generate_incidents.py
|   +-- automated_response.py
|   +-- run_soc.sh
|
+-- logs/
    +-- auth_*.log
    +-- journal_*.log
    +-- windows_*.log
    +-- alerts.log
    +-- correlation_state.txt
    +-- incidents.log
    +-- incident_state.txt
    +-- actions.log
    +-- response_state.txt
```

## 4. Pipeline

### Collection
- `collect_linux_logs.sh` collects Linux authentication logs and system journal data.
- Windows Security events are collected into timestamped Windows log files.

### Analysis
- `analyze_linux_logs.py` detects failed/successful SSH authentication and sudo activity.
- `analyze_windows_logs.py` analyzes Windows Security Events 4624, 4625, and 4672.

### Correlation
- `correlate_events.py` correlates failed authentication with subsequent successful authentication.
- Correlations are tracked using `correlation_state.txt` to prevent repeated alerts for the same correlation.

### Alerting
- Detection and correlation alerts are written to `alerts.log`.
- `alert_summary.py` provides an analyst-facing summary of accumulated alerts.

### Incident Reporting
- `generate_incidents.py` reads `alerts.log` and converts each new alert into a structured incident record (JSON) written to `incidents.log`.
- Each incident includes an incident ID, timestamp, severity, platform, source IP, target account, failed-attempt count, successful-auth flag, detection reason, the originating alert text, and a status field (defaults to `open`).
- Previously processed alerts are tracked via a fingerprint in `incident_state.txt`, preventing duplicate incidents on repeated `run_soc.sh` runs — mirroring the correlation deduplication approach.

### Automated Response
- `automated_response.py` reads `incidents.log` and evaluates each new incident against a severity gate (currently `CRITICAL` only) and the presence of a `source_ip`.
- Qualifying incidents produce a **simulated, log-only** response action written to `actions.log` — no firewall, `hosts.deny`, or other system-level changes are made.
- Each action record links back to its source `incident_id`, carries the original detection reason, and is explicitly marked `status: "simulated"` with a note confirming no real change occurred.
- Previously responded-to incidents are tracked in `response_state.txt`, preventing duplicate action records on repeated runs.

### Orchestration
- `run_soc.sh` executes the SOC pipeline in sequence, including incident generation as the final stage.

## 5. Current Detection Coverage

### Linux
- Multiple failed login attempts
- Brute-force activity by source IP
- Successful SSH/login activity
- Sudo authentication failures
- Sudo command execution

### Windows
- Successful logons — Event ID 4624
- Failed logons — Event ID 4625
- Privileged logons — Event ID 4672
- Repeated failed logins by account

### Correlation
- Multiple authentication failures followed by a successful login
- Persistent correlation state / duplicate prevention

### Incident Reporting
- Structured, analyst-readable case records generated from alerts
- Deduplicated against previously reported alerts

### Automated Response
- Simulated, log-only response actions for CRITICAL incidents with a known source IP
- Deduplicated against previously responded-to incidents
- No system-level or firewall changes are made

## 6. Current Project Progress

| Phase | Status |
|---|---|
| Lab setup | Complete |
| Connectivity and attack generation | Complete |
| Linux log collection | Complete |
| Linux log analysis | Complete |
| Windows log collection | Complete |
| Windows log analysis | Complete |
| Detection rules | Complete |
| Event correlation | Complete |
| Alert deduplication/state tracking | Complete |
| Alert reporting | Complete |
| Incident/case reporting | Complete |
| Automated response | Complete |
| Dashboard/visualization | Next |
| Attack scenario testing | Planned |
| Final documentation | Planned |

## 7. Next Architecture Additions

The next components will build on the existing pipeline rather than replace it:

```text
actions.log
    |
    v
Dashboard / Visualization
    |
    v
Testing and Validation
```