# Home SOC

A small, custom Security Operations Center (SOC) lab built to learn and demonstrate practical security monitoring, log analysis, detection, event correlation, alerting, and incident reporting.

## Current Progress

v1.0 completed the core SOC detection and reporting pipeline. v1.1 restructured that pipeline from a folder of standalone scripts into an installable, configurable Python package — the same detections, the same outputs, on a foundation that further stages can build on.

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
- **Installable package with external configuration and a single CLI (v1.1)**

**Current stage:** v1.1 complete. See `ROADMAP.md` for the ten-stage plan through v2.0.

## Installation

Requires Python 3.9 or later.

```bash
git clone <repository-url> homesoc
cd homesoc

python3 -m venv .venv
source .venv/bin/activate

pip install -e .

cp config.example.yaml config.yaml
```

If `python3 -m venv` fails with an `ensurepip` error, install the venv package first (`sudo apt install python3-venv`).

Verify the installation:

```bash
homesoc config --check
```

## Configuration

All paths, thresholds, and timezones live in `config.yaml`. Nothing in the source contains an absolute path or a magic number.

`config.yaml` is gitignored; `config.example.yaml` is committed and documents every key. Configuration is deep-merged over built-in defaults, so a file naming only the two or three values you want to change is valid — and the pipeline runs correctly with no config file at all.

Resolution order (first match wins):

```text
1. --config PATH
2. $HOMESOC_CONFIG
3. ./config.yaml
4. ~/.config/homesoc/config.yaml
5. built-in defaults
```

Configuration is validated at load. A threshold below 1, an unknown severity name, an unresolvable timezone, or a circular path reference fails immediately with a specific message rather than partway through a run. Unrecognised keys are reported as probable typos rather than silently ignored.

Key settings:

| Key | Purpose |
|---|---|
| `paths.home` | Root for runtime data (logs, dashboard) |
| `collection.linux.auth_log` | Source authentication log |
| `collection.windows.timezone` | Endpoint timezone; IANA name or fixed offset |
| `detection.*.threshold` | Per-platform detection thresholds |
| `correlation.window_minutes` | Correlation time window |
| `correlation.min_failures` | Failures required before a success correlates |
| `response.severities` | Which severities trigger a simulated action |

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
+-- homesoc/                     # the installable package
|   +-- __init__.py
|   +-- cli.py                   # single entry point, subcommand dispatch
|   |
|   +-- common/                  # shared across every stage
|   |   +-- config.py            # configuration loading and validation
|   |   +-- classification.py    # severity, detection reason, platform
|   |   +-- patterns.py          # log regexes and field extraction
|   |   +-- log.py               # logging setup
|   |   +-- store.py             # alert, state, and JSONL file I/O
|   |
|   +-- collect/
|   |   +-- linux.py
|   |
|   +-- detect/
|   |   +-- events.py            # auth event record, log discovery
|   |   +-- linux.py
|   |   +-- windows.py
|   |   +-- correlate.py
|   |
|   +-- report/
|   |   +-- summary.py
|   |   +-- incidents.py
|   |   +-- dashboard.py
|   |
|   +-- respond/
|       +-- actions.py
|
+-- scripts/
|   +-- run_soc.sh               # wrapper around `homesoc run`
|   +-- collect_windows_logs.ps1 # replaced in Stage 2
|
+-- config.example.yaml
+-- pyproject.toml
+-- ROADMAP.md
+-- CHANGELOG.md
+-- docs/decisions/              # architecture decision records
|
+-- dashboard.html               # generated
+-- logs/                        # generated
    +-- auth_*.log
    +-- journal_*.log
    +-- windows_*.log
    +-- alerts.log
    +-- correlation_state.txt
    +-- incidents.log
    +-- incident_state.txt
    +-- actions.log
    +-- response_state.txt
    +-- homesoc.log              # run log, rotated
```

## Components

### `homesoc/cli.py`
Single entry point. Stages are registered in a command table and imported lazily inside their handler, so a stage that fails to import breaks that command rather than the whole CLI. Global flags (`--config`, `--verbose`, `--quiet`) work before or after the subcommand.

Exit codes: `0` success, `1` a stage reported a problem, `2` usage or configuration error, `130` interrupted.

### `homesoc/common/config.py`
Loads, merges, and validates configuration; resolves and expands all paths; exposes typed values (correlation window as a `timedelta`, endpoint timezone as a `tzinfo`).

### `homesoc/common/classification.py`
One signature table mapping an alert message to its severity, detection reason, and platform. v1.0 derived these from three separate if-chains across three files, which agreed by coincidence rather than by construction.

### `homesoc/common/patterns.py`
Every log regex and extraction helper. The Windows account extractor — anchored to `New Logon:` for 4624 and `Account For Which Logon Failed:` for 4625 — lives here once, rather than being duplicated between the analyzer and the correlator.

### `homesoc/common/log.py`
Console output plus a rotating run log. The console honours `--verbose` / `--quiet`; the file always records DEBUG, because the run you need detail from is the one that already happened.

### `homesoc/common/store.py`
All reading and writing of `alerts.log`, the state files, and the JSONL incident and action logs. State entries are buffered and written on flush, so a run that fails partway does not record work it never completed.

### `homesoc/collect/linux.py`
Collects Linux authentication logs and system journal data into timestamped files. A failed copy or a `journalctl` error is now an error rather than a silent success.

### `homesoc/detect/linux.py`
Analyzes collected Linux authentication logs for:

- Failed logins
- Successful logins
- Brute-force activity by source IP
- Sudo authentication failures
- Sudo command execution

### `homesoc/detect/windows.py`
Analyzes the most recent collected Windows Security log:

- Event ID 4624 — successful logon
- Event ID 4625 — failed logon
- Event ID 4672 — privileged logon activity
- Repeated failed logins by account

### `homesoc/detect/correlate.py`
Correlates authentication events across platforms:

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

Correlation state is stored in `correlation_state.txt`. Fingerprints are computed exactly as in v1.0, so state written before the refactor still suppresses the same correlations.

### `homesoc/report/summary.py`
Total alert count, severity breakdown, top source IPs (flagging any outside RFC1918 space), recent alerts, and a high-level assessment.

### `homesoc/report/incidents.py`
Converts new alerts into structured incident records in `incidents.log`, one JSON object per line, with incident ID, timestamp, severity, platform, source IP, target account, failed-attempt count, successful-auth flag, detection reason, originating alert text, and status.

### `homesoc/respond/actions.py`
Generates **log-only, simulated** response actions for incidents meeting the configured severity gate with a known source IP. No firewall rules, `hosts.deny` entries, or other system-level changes are made. The gate and action type are configuration, not constants.

### `homesoc/report/dashboard.py`
Writes a single self-contained `dashboard.html` with no external CSS or JS, so it works fully offline. Shows summary counts, top source IPs, and the most recent incidents and response actions.

### `scripts/run_soc.sh`
Thin wrapper around `homesoc run`, kept so existing habits and documented commands keep working. Arguments are passed through.

## Running the SOC

```bash
homesoc run
```

Or individual stages:

```bash
homesoc collect
homesoc analyze                 # both platforms
homesoc analyze --platform windows
homesoc correlate
homesoc summary
homesoc incidents
homesoc respond
homesoc dashboard
```

Useful flags:

```bash
homesoc config --check          # verify paths exist and are usable
homesoc run --verbose           # show every matched log line
homesoc run --quiet             # warnings and errors only
homesoc -c /tmp/test.yaml run   # run against an isolated config
```

`python3 -m homesoc.cli run` is equivalent and does not depend on the console script being installed.

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
| Incident reporting | Complete |
| Automated response | Complete |
| Dashboard | Complete |
| Attack scenario testing | Complete |
| Documentation | Complete |
| Package structure and configuration (v1.1) | Complete |
| Normalized event schema (v1.2) | Planned |

## Testing & Validation

The pipeline was validated end to end using Kali Linux against both lab targets, rather than relying only on incidental login activity.

### Linux target (SSH)

A brute-force wordlist attack via Hydra against the Ubuntu SOC server's own SSH service, ending in a real successful login, confirmed failed-login and brute-force-by-IP detection, the correlation rule, and correct flow through incident generation, simulated response, and the dashboard.

### Windows target (SMB)

Hydra's SSH and RDP modules were not viable against the Windows target (SSH isn't installed; RDP was blocked by Windows Firewall until Remote Desktop was enabled). SMB brute-force via Metasploit's `auxiliary/scanner/smb/smb_login` succeeded and confirmed the same end-to-end flow — with one real bug found and fixed along the way:

**Bug found:** the Windows analyzer and the correlator both extracted the account name using the *first* `Account Name:` match in the event text. Windows event messages contain several such lines (under `Subject:`, `New Logon:`, and `Account For Which Logon Failed:`), and the first is not reliably the meaningful one — it returned `-` or a system account instead of the attempted username, depending on logon type.

**Fix:** extraction is anchored to the correct labeled section per event ID. As of v1.1 that extractor exists in exactly one place (`homesoc/common/patterns.py`); the duplication is what allowed the bug to be fixed in one file and not the other in the first place.

### v1.1 refactor verification

The refactor was verified rather than assumed. v1.0's three `get_severity()` implementations and its `get_detection_reason()` were run side by side with the new classification module across every alert string the pipeline can emit — zero mismatches, so existing `incidents.log` records classify identically. The full pipeline was then run end to end against synthetic Linux and Windows attack data, and re-run to confirm correlation and response deduplication still suppress correctly.

## Known Limitations / Future Work

This is a learning/portfolio SOC, not a production system. Known gaps, by design or by scope. `ROADMAP.md` tracks each with a defect ID and the stage that addresses it.

- **Duplicate ingest.** Collection copies the entire `auth.log` on every run, and analysis reads every collected copy, so one event is counted once per run. Detection counts inflate and correlations re-fire with a changed count. (D1, D2 — Stage 2)
- **Repeated alerts become repeated incidents.** The Linux and Windows analyzers have no alert state file and re-append identical alerts each run; incident fingerprints hash the alert line including its timestamp, so each run creates fresh incidents for the same finding. (D3, D4 — Stage 3)
- **Incident status never transitions.** Every incident defaults to `open`; nothing closes, triages, or re-scores one. (Stage 7)
- **Response only covers CRITICAL incidents with a known source IP.** Configurable now, but HIGH and MEDIUM incidents get no action by default. (Stage 7)
- **Response actions are simulated, log-only.** Nothing is wired to a firewall or other enforcement point — a deliberate boundary, not an oversight.
- **Windows log collection is manual and pushes to the SOC.** The PowerShell collector is run by hand and `scp`s to the SOC server, which means the monitored endpoint holds a key to the monitoring host. (D10, D13 — Stage 2)
- **Windows events are parsed from rendered message text**, which is locale-dependent and structurally fragile. (D12 — Stage 2)
- **Only the most recent Windows log file is analyzed per run.** Older files are never reprocessed once a newer one exists. (Stage 8)
- **No log rotation or retention policy** for `alerts.log`, `incidents.log`, or `actions.log`. The run log rotates; the pipeline logs do not. (Stage 3)
- **No automated tests.** (Stage 5)
- **Detection is threshold-based, not behavioral or ML-driven.** Rules like "5+ failed logins" are simple by design — intentional for a learning project, but worth stating plainly. (Stage 4)

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