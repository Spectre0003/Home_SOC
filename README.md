# Home SOC

A small, custom Security Operations Center (SOC) lab built to learn and demonstrate practical security monitoring, log analysis, detection, event correlation, and alerting.

## Current Progress

The project has completed its core SOC detection pipeline:

- Linux log collection
- Linux authentication and sudo analysis
- Windows Security log collection
- Windows Security event analysis
- Detection rules
- Cross-event authentication correlation
- Persistent correlation state / alert deduplication
- Central alert logging
- Alert summary reporting

**Current stage:** moving from alert reporting into incident reporting, automated response, visualization, testing, and final documentation.

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
|   +-- run_soc.sh
|
+-- logs/
    +-- auth_*.log
    +-- journal_*.log
    +-- windows_*.log
    +-- alerts.log
    +-- correlation_state.txt
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

### `run_soc.sh`
Acts as the main SOC orchestrator and runs the collection, analysis, correlation, and reporting stages sequentially.

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
| Incident reporting | Next |
| Automated response | Planned |
| Dashboard | Planned |
| Attack scenario testing | Planned |
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
