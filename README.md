# Home SOC

A small, custom Security Operations Center (SOC) lab built to learn and demonstrate practical security monitoring, log analysis, detection, event correlation, alerting, and incident reporting.

## Current Progress

The project has completed its core SOC detection and reporting pipeline:

- Linux log collection
- Linux authentication and sudo analysis
- Windows Security log collection
- Windows Security event analysis
- Detection rules
- Cross-event authentication correlation
- Persistent correlation state / alert deduplication
- Central alert logging
- Alert summary reporting
- Structured incident/case reporting
- Automated response (log-only simulated actions)
- Dashboard/visualization

**Current stage:** moving from dashboard/visualization into attack scenario testing and final documentation.

## Architecture

```text
Kali / Testing
      |
      | attack / test activity
      v
Windows Endpoint --------+
      |                  |
      | Security logs    |
      v                  |
Windows Collector        |
      |                  |
      +--------+---------+
               |
Linux -------->+
logs           |
               v
          Log Storage
               |
       +-------+-------+
       |               |
       v               v
Linux Analyzer   Windows Analyzer
       |               |
       +-------+-------+
               |
               v
        Event Correlator
               |
          alerts.log
               |
               v
         Alert Summary
               |
               v
       Incident Generator
               |
          incidents.log
               |
               v
       Automated Response
               |
          actions.log
               |
               v
      Dashboard Generator
               |
          dashboard.html
               |
               v
            Analyst
```

## Project Structure

```text
homesoc/
|
+-- scripts/
|   +-- collect_linux_logs.sh
|   +-- analyze_linux_logs.py
|   +-- analyze_windows_logs.py
|   +-- correlate_events.py
|   +-- alert_summary.py
|   +-- generate_incidents.py
|   +-- automated_response.py
|   +-- generate_dashboard.py
|   +-- run_soc.sh
|
+-- dashboard.html
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

## Components

### `collect_linux_logs.sh`
Collects Linux authentication logs and system journal data and stores timestamped copies in the SOC log directory.

### `analyze_linux_logs.py`
Analyzes collected Linux authentication logs for:

- Failed logins
- Successful logins
- Brute-force activity
- Sudo authentication failures
- Sudo command execution

Detected alerts are written to `alerts.log`.

### `analyze_windows_logs.py`
Analyzes collected Windows Security logs and currently handles:

- Event ID 4624 — successful logon
- Event ID 4625 — failed logon
- Event ID 4672 — privileged logon activity
- Repeated failed logins by account

Detected alerts are written to `alerts.log`.

### `correlate_events.py`
Correlates authentication events across collected logs.

The main correlation currently looks for:

```text
Multiple failed logins
        +
Successful login
        +
Matching account/source
        +
Short time window
        =
Authentication attack pattern
```

Correlation state is stored in `correlation_state.txt` to prevent the same correlation from generating repeated alerts.

### `alert_summary.py`
Reads `alerts.log` and provides:

- Total alert count
- Severity breakdown
- Top source IPs
- Recent alerts
- High-level threat assessment

### `generate_incidents.py`
Reads `alerts.log` and converts new alerts into structured incident records written to `incidents.log` (one JSON object per line). Each incident includes:

- Incident ID
- Timestamp
- Severity
- Platform (Linux / Windows / Correlated)
- Source IP
- Target account
- Failed-attempt count
- Successful-auth flag
- Detection reason
- The originating alert text
- Status (defaults to `open`)

Previously processed alerts are tracked via `incident_state.txt`, so re-running the pipeline does not generate duplicate incidents for alerts already reported.

### `automated_response.py`
Reads `incidents.log` and generates a **log-only, simulated** response action for each new `CRITICAL` incident that has a known source IP. No firewall rules, `hosts.deny` entries, or other system-level changes are made — this stage only demonstrates the detect-to-response mechanism. Each action record written to `actions.log` includes:

- Action ID
- Linked incident ID
- Timestamp
- Action type (currently `block_ip`)
- Target (source IP)
- Reason (carried over from the incident's detection reason)
- Status (`simulated`)
- A note confirming no real change was made

Previously responded-to incidents are tracked via `response_state.txt`, preventing duplicate action records on repeated runs. The severity threshold for triggering a response is a single constant at the top of the script and can be widened (e.g. to include `HIGH`) later.

### `generate_dashboard.py`
Reads `alerts.log`, `incidents.log`, and `actions.log` and writes a single self-contained `dashboard.html` (project root) — no external CSS/JS dependencies, so it works fully offline. The dashboard shows:

- Summary counts (total/critical/high/medium alerts, total and open incidents, total response actions)
- Top source IPs
- The 10 most recent incidents
- The 10 most recent response actions

This stage reflects current totals each time it runs rather than tracking state — there's nothing to deduplicate, since it doesn't write anything to the log pipeline itself.

### `run_soc.sh`
Acts as the main SOC orchestrator and runs the collection, analysis, correlation, reporting, and incident generation stages sequentially.

## Current Detection Coverage

### Linux

```text
Failed authentication
Successful authentication
Brute-force activity
Sudo authentication failure
Sudo command execution
```

### Windows

```text
4624 → Successful logon
4625 → Failed logon
4672 → Special privileges assigned
```

### Correlation

```text
Failed authentication
        ↓
Repeated attempts
        ↓
Successful authentication
        ↓
Correlated attack alert
```

### Incident Reporting

```text
alerts.log
        ↓
Structured incident record
        ↓
incidents.log (deduplicated)
```

### Automated Response

```text
incidents.log (CRITICAL + known source IP)
        ↓
Simulated response action
        ↓
actions.log (deduplicated, log-only)
```

### Dashboard

```text
alerts.log + incidents.log + actions.log
        ↓
dashboard.html (static, regenerated each run)
```

## Current Status

| Component | Status |
|---|---|
| Lab environment | Complete |
| Linux collection | Complete |
| Linux analysis | Complete |
| Windows collection | Complete |
| Windows analysis | Complete |
| Detection rules | Complete |
| Event correlation | Complete |
| Alert state/deduplication | Complete |
| Alert reporting | Complete |
| Incident reporting | Complete |
| Automated response | Complete |
| Dashboard | Complete |
| Attack scenario testing | Next |
| Final documentation | Planned |

## Running the SOC

Run the complete pipeline with:

```bash
~/homesoc/scripts/run_soc.sh
```

Or run individual components directly:

```bash
~/homesoc/scripts/collect_linux_logs.sh

python3 ~/homesoc/scripts/analyze_linux_logs.py

python3 ~/homesoc/scripts/analyze_windows_logs.py

python3 ~/homesoc/scripts/correlate_events.py

python3 ~/homesoc/scripts/alert_summary.py

python3 ~/homesoc/scripts/generate_incidents.py

python3 ~/homesoc/scripts/automated_response.py

python3 ~/homesoc/scripts/generate_dashboard.py
```

## Goal

The goal is to progressively turn the lab into a functional small-scale SOC that demonstrates the workflow:

```text
Collect
  ↓
Parse
  ↓
Detect
  ↓
Correlate
  ↓
Alert
  ↓
Report
  ↓
Respond
  ↓
Visualize
  ↓
Validate
```

The project intentionally builds these capabilities incrementally so that the underlying SOC processes are understood rather than hidden behind a pre-built SIEM.