# Home SOC — Architecture

## 1. Current Status

The Home SOC has completed its full pipeline — collection, analysis, detection, correlation, alerting, incident reporting, automated response, dashboard, and end-to-end attack scenario testing against both Linux and Windows targets.

v1.1 restructured that pipeline into an installable Python package with external configuration, shared libraries, structured logging, and a single CLI. Detection behaviour is unchanged and was verified equivalent to v1.0.

**Current phase:** v1.1 complete. Stage 2 (normalized event schema, parser layer, Windows collection redesign) is next. See `ROADMAP.md`.

## 2. Architecture

### 2.1 Deployment

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
              Dashboard Generator
                     |
                     v
               dashboard.html
                     |
                     v
                  Analyst
```

### 2.2 Software layers (v1.1)

```text
                        homesoc.cli
                             |
           dispatch to one stage per subcommand
                             |
    +---------+---------+----+----+---------+---------+
    |         |         |         |         |         |
    v         v         v         v         v         v
 collect   detect    detect    report    respond   report
 .linux    .linux   .correlate .summary  .actions .dashboard
           .windows            .incidents
    |         |         |         |         |         |
    +---------+---------+----+----+---------+---------+
                             |
                       homesoc.common
                             |
    +------------+-----------+-----------+------------+
    |            |           |           |            |
    v            v           v           v            v
 config    classification patterns      log         store
 paths,     severity,     regexes,   console +    alert, state,
 thresholds reason,       field      run log      and JSONL
            platform      extraction              file I/O
```

Every stage depends only on `common`. No stage imports another stage. The CLI is the only thing that knows the order they run in, which is what makes the pipeline reorderable and each stage independently runnable.

## 3. Project Files

```text
homesoc/
|
+-- homesoc/
|   +-- __init__.py
|   +-- cli.py
|   |
|   +-- common/
|   |   +-- config.py
|   |   +-- classification.py
|   |   +-- patterns.py
|   |   +-- log.py
|   |   +-- store.py
|   |
|   +-- collect/
|   |   +-- linux.py
|   |
|   +-- detect/
|   |   +-- events.py
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
|   +-- run_soc.sh
|   +-- collect_windows_logs.ps1
|
+-- config.example.yaml
+-- pyproject.toml
+-- ROADMAP.md
+-- CHANGELOG.md
+-- docs/decisions/
|
+-- dashboard.html
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
    +-- homesoc.log
```

## 4. Configuration

Configuration is external and validated at load. Built-in defaults reproduce v1.0 behaviour exactly, so the pipeline runs correctly with no config file present; a user file is deep-merged over them.

```text
--config PATH
      |
$HOMESOC_CONFIG
      |
./config.yaml
      |
~/.config/homesoc/config.yaml
      |
built-in defaults
      |
      v
  deep merge
      |
      v
  validation ----> ConfigError (exit 2, specific message)
      |
      v
 path resolution   ~ expansion, {home}/{logs} tokens, absolute
      |
      v
   Config object   typed accessors: timedelta, tzinfo, Path
```

Validation covers threshold ranges, severity names, timezone resolvability, event ID types, and circular path references. Unrecognised keys are reported rather than ignored, so a typo does not become a setting that silently has no effect.

## 5. Pipeline

### Collection
- `collect/linux.py` collects Linux authentication logs and system journal data. A failed copy or a non-zero `journalctl` exit is reported and the stage returns failure, rather than reporting success over an empty file.
- Windows Security events are collected into timestamped Windows log files by `scripts/collect_windows_logs.ps1`, run manually on the endpoint.

### Analysis
- `detect/linux.py` detects failed and successful SSH authentication and sudo activity.
- `detect/windows.py` analyzes Windows Security Events 4624, 4625, and 4672.
- Thresholds come from configuration. Matched log lines are logged at DEBUG, so findings are visible at default verbosity and evidence is available with `--verbose`.

### Correlation
- `detect/correlate.py` correlates failed authentication with subsequent successful authentication across both platforms.
- Linux timestamps are parsed in both RFC3339 and traditional syslog form; Windows timestamps are tried against several locale formats and converted from the configured endpoint timezone to UTC.
- Correlations are tracked in `correlation_state.txt`. Fingerprint construction is byte-identical to v1.0 so pre-existing state remains valid.

### Alerting
- Detection and correlation alerts are written to `alerts.log` through `common/store.py`.
- `report/summary.py` provides an analyst-facing summary. Both it and the dashboard now read alerts through the same function, so their totals cannot disagree.

### Incident Reporting
- `report/incidents.py` converts each new alert into a structured JSON incident record.
- Severity, detection reason, and platform come from `common/classification.py`; field extraction from `common/patterns.py`.
- Processed alerts are tracked by fingerprint in `incident_state.txt`.

### Automated Response
- `respond/actions.py` evaluates incidents against a configurable severity gate and the presence of a source IP.
- Qualifying incidents produce a **simulated, log-only** action in `actions.log` — no firewall, `hosts.deny`, or other system change.
- An incident that meets the severity gate but has no source IP is now reported by ID rather than silently counted as non-qualifying.
- Responded incidents are tracked in `response_state.txt`.

### Dashboard
- `report/dashboard.py` writes a self-contained `dashboard.html` with no external dependencies.
- Regenerated fresh on every run; no state file, since it reflects current totals rather than tracking new versus previously-seen data.

### Orchestration
- `homesoc run` executes the stages in sequence. `scripts/run_soc.sh` is a wrapper that passes its arguments through.

## 6. Current Detection Coverage

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
- Simulated, log-only actions for incidents at or above the configured severity with a known source IP
- Deduplicated against previously responded-to incidents

### Dashboard
- Static HTML summary of alerts, incidents, and response actions

## 7. Current Project Progress

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
| Dashboard/visualization | Complete |
| Attack scenario testing | Complete |
| Documentation | Complete |
| **Stage 1 — package, configuration, shared library (v1.1)** | **Complete** |
| Stage 2 — event schema, parsers, Windows collection redesign | Planned |
| Stage 3 — SQLite datastore | Planned |

## 8. Attack Scenario Testing Summary

The pipeline was validated end to end with deliberate attacks from Kali against both lab targets rather than relying on incidental traffic:

- **Linux (SSH):** Hydra brute-force against Ubuntu, ending in a real successful login. Confirmed detection, correlation, incident generation, simulated response, and dashboard reflection.
- **Windows (SMB):** Metasploit `smb_login` brute-force against the Windows target, after SSH (not installed) and RDP (blocked by firewall until Remote Desktop was enabled) proved non-viable. This testing surfaced and led to the fix of a real account-extraction bug — both the analyzer and the correlator were taking the first `Account Name:` match in a Windows event rather than anchoring to the correct section per event type. That extractor now exists in exactly one module.

## 9. Known Structural Issues

Carried forward deliberately, with the stage that resolves each. Fixing any of them means changing a fingerprint or a stored value, which would invalidate existing state files — so they are scheduled behind the point where there is something to verify a change against.

| ID | Issue | Resolved in |
|---|---|---|
| D1 | Collection re-copies the whole auth log; analysis reads every copy, counting each event once per run | Stage 2 |
| D2 | Correlation fingerprint includes the match count, so an inflated count re-fires a seen correlation | Stage 2 |
| D3 | Analyzers have no alert state file and re-append identical alerts every run | Stage 3 |
| D4 | Incident fingerprint hashes the alert line including its timestamp, creating duplicate incidents | Stage 3 |
| D10 | Windows collector always pulls the latest 500 events, guaranteeing overlap | Stage 2 |
| D11 | Correlation is O(failures × successes) with no time index | Stage 3 |
| D12 | Windows parsing reads rendered message text — locale-dependent and structurally fragile | Stage 2 |
| D13 | The Windows endpoint holds an SSH key to the SOC server | Stage 2 |

Resolved in v1.1: D5 (syslog timestamp formats), D6 (hardcoded timezone), D7 (alert counting mismatch between summary and dashboard), D8 (duplicated severity logic), D9 (hardcoded absolute paths).