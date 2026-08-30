# Home SOC — Architecture

## 1. Current Status

The Home SOC has completed its core collection, analysis, detection, correlation, and alerting pipeline.

**Current phase:** Alert Reporting → Incident Reporting → Automated Response → Visualization → Testing → Final Documentation.

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
|   +-- run_soc.sh
|
+-- logs/
    +-- auth_*.log
    +-- journal_*.log
    +-- windows_*.log
    +-- alerts.log
    +-- correlation_state.txt
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

### Orchestration
- `run_soc.sh` executes the SOC pipeline in sequence.

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
| Incident/case reporting | Next |
| Automated response | Planned |
| Dashboard/visualization | Planned |
| Attack scenario testing | Planned |
| Final documentation | Planned |

## 7. Next Architecture Additions

The next components will build on the existing pipeline rather than replace it:

```text
alerts.log
    |
    v
Incident / Case Reporting
    |
    v
Automated Response
    |
    v
Dashboard / Visualization
    |
    v
Testing and Validation
```
