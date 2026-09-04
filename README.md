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
- Attack scenario testing (validated end-to-end against both Linux and Windows targets)

**Current stage:** final documentation. All core pipeline stages have been built and validated end-to-end.

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
| Attack scenario testing | Complete |
| Final documentation | Complete |

## Testing & Validation

The full pipeline was validated end to end using Kali Linux against both lab targets, rather than relying only on incidental login activity.

### Linux target (SSH)

A brute-force wordlist attack via Hydra against the Ubuntu SOC server's own SSH service, ending in a real successful login, confirmed:

- Failed-login and brute-force-by-IP detection in `analyze_linux_logs.py`
- The correlation rule in `correlate_events.py` (failed attempts followed by a success, same source and account)
- Correct flow through incident generation, simulated response, and the dashboard

### Windows target (SMB)

Hydra's SSH and RDP modules were not viable against the Windows target (SSH isn't installed; RDP was blocked by Windows Firewall until Remote Desktop was enabled). SMB brute-force via Metasploit's `auxiliary/scanner/smb/smb_login` succeeded and confirmed the same end-to-end flow on the Windows side — with one real bug found and fixed along the way:

**Bug found:** `analyze_windows_logs.py` and `correlate_events.py` both extracted the account name from a raw Windows event using the *first* `Account Name:` match in the event text. Windows event messages contain multiple `Account Name:` lines (under `Subject:`, `New Logon:`, and `Account For Which Logon Failed:` depending on event type), and the first one isn't reliably the meaningful one — it inconsistently returned `-` or a system/computer account instead of the actual attempted username, depending on logon type.

**Fix:** both scripts now anchor the extraction to the correct labeled section per event ID (`New Logon:` for 4624, `Account For Which Logon Failed:` for 4625) instead of taking whichever `Account Name:` line appears first.

This was caught specifically because Phase 14 exercised the pipeline with real, deliberate Windows authentication failures rather than only reviewing the code — the bug did not surface during earlier development because the correlation logic had not yet processed genuine Windows brute-force data end to end.

## Known Limitations / Future Work

This is a learning/portfolio SOC, not a production system. Known gaps, by design or by scope:

- **Incident status never transitions.** Every incident defaults to `open` and nothing in the pipeline currently closes, triages, or re-scores one — there's no analyst workflow for marking something resolved.
- **Automated response only covers CRITICAL correlated incidents with a known source IP.** HIGH and MEDIUM incidents (raw brute-force or repeated-failure detections that didn't also correlate with a success) don't currently get a response action.
- **Response actions are simulated, log-only.** `actions.log` records what *would* be blocked; nothing is wired to an actual firewall, `hosts.deny`, or similar enforcement point.
- **Windows log collection is manual.** The PowerShell collector script pulls the latest Security events and `scp`s them to the SOC server, but it's run by hand, not scheduled or triggered automatically the way `collect_linux_logs.sh` effectively is via `run_soc.sh`.
- **Only the most recent Windows log file is analyzed per run.** `analyze_windows_logs.py` and `correlate_events.py` both pick the newest `windows_*.log` via `glob` — older Windows log files aren't reprocessed once a newer one exists.
- **No log rotation or retention policy.** `alerts.log`, `incidents.log`, and `actions.log` all grow indefinitely; nothing archives or prunes old entries.
- **Detection is threshold-based, not behavioral or ML-driven.** Rules like "5+ failed logins" or "3+ failures then a success" are simple by design — intentional for a learning project, but worth stating plainly rather than implying anything more sophisticated.

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