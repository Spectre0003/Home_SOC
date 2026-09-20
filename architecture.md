# Home SOC — Architecture

## 1. Current Status

The Home SOC has completed its full pipeline — collection, analysis, detection, correlation, alerting, incident reporting, automated response, dashboard, and end-to-end attack scenario testing against both Linux and Windows targets.

v1.1 restructured that pipeline into an installable Python package with external configuration, shared libraries, structured logging, and a single CLI. v1.2 replaced regex-scraped log lines with a normalized event schema and real parsers for both platforms, and replaced the manual, push-based Windows collector with an automated WinRM pull. Both were verified against real Linux and Windows data — the Windows side required a live diagnosis and fix of a genuine output-corruption bug, documented in ADR 0003.

**Current phase:** v1.2 complete. Stage 3 (SQLite datastore) is next. See `ROADMAP.md`.

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
              |               |<--------------+
              |         Security log     WinRM pull (pypsrp),
              |         read only,       SOC-initiated (ADR 0002);
              |         no agent,        watermark + credential
              |         no credential    live on this side only
              |               |               |
              +---------------+---------------+
                              |
                              v
                         LOG STORAGE
                              |
             +----------------+----------------+
             |                                 |
             v                                 v
       Linux Parser                    Windows Parser         (homesoc.parse,
             |                                 |                v1.2 — normalized
             +----------------+----------------+                Events; XML fields,
                              |                                 not rendered text)
             +----------------+----------------+
             |                                 |
             v                                 v
      Linux Detector                  Windows Detector
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

### 2.2 Software layers (v1.2)

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
 .windows  .windows            .incidents
    |         |         |         |         |         |
    +---------+----+----+---------+---------+---------+
                   |
                   v
             homesoc.parse            (v1.2 — raw text/XML -> Event;
                   |                   no detector touches a raw line)
    +---------+----+----+
    |         |         |
    v         v         v
 event.py  linux.py  windows.py
    |         |         |
    +---------+----+----+
                   |
                   v
             homesoc.common
                   |
    +----------+---+---+----------+----------+
    |          |       |          |          |
    v          v       v          v          v
 config  classification patterns    log       store
 paths,   severity,    Linux regexes console + alert, state,
 creds    reason,      field extract run log   JSONL, and
          platform                            watermark I/O
```

Every stage depends only on `common` (and, since v1.2, `parse`). No stage imports another stage. The CLI is the only thing that knows the order they run in, which is what makes the pipeline reorderable and each stage independently runnable.

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
|   +-- parse/
|   |   +-- event.py
|   |   +-- linux.py
|   |   +-- windows.py
|   |
|   +-- collect/
|   |   +-- linux.py
|   |   +-- windows.py
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
    +-- windows_watermark.json
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
   Config object   typed accessors: timedelta, WinRM password preferring env over file
```

Validation covers threshold ranges, severity names, WinRM port range and auth mechanism, event ID types, and circular path references. Unrecognised keys are reported rather than ignored, so a typo does not become a setting that silently has no effect.

`collection.windows.timezone` existed through v1.1 and is gone as of v1.2 — Windows Event XML's own `TimeCreated` is always UTC, so there was nothing left to configure once collection moved to structured XML rather than rendered text.

## 5. Pipeline

### Collection
- `collect/linux.py` collects Linux authentication logs and system journal data. A failed copy or a non-zero `journalctl` exit is reported and the stage returns failure, rather than reporting success over an empty file.
- `collect/windows.py` pulls Security events from the Windows endpoint over WinRM (`pypsrp`), SOC-initiated (ADR 0002). A persisted watermark (`windows_watermark.json`, keyed by host) makes each pull incremental; a Security log clear or replacement is detected by comparing the log's current head record against the stored watermark and recovered from automatically. Events are joined with an XML-illegal delimiter (`0x1E`) and reconstructed from the raw response rather than trusting newlines in transit — PowerShell's own output formatter word-wraps long strings before either transport library involved ever sees them, confirmed live against the real endpoint (ADR 0003).

### Parsing
- `parse/event.py` defines the normalized `Event` schema (ECS-style grouping) every parser produces and every detector consumes.
- `parse/linux.py` turns `auth.log` text into Events: SSH logins and sudo authentication failures. Sudo command execution stays a raw count, not an Event — it has no success/failure outcome to model.
- `parse/windows.py` reads named `EventData` fields from Windows Event XML. `TargetUserName` means the same thing on a 4624 and a 4625, so there is no per-event-ID branch in the account-extraction path — the v1.0/v1.1 anchoring bug's entire class doesn't exist here.

### Analysis
- `detect/linux.py` and `detect/windows.py` consume `Event` lists from the parsers; neither touches a raw log line or a regex directly any more.
- Thresholds come from configuration. Matched events are logged at DEBUG, so findings are visible at default verbosity and evidence is available with `--verbose`.

### Correlation
- `detect/correlate.py` correlates failed authentication with subsequent successful authentication across both platforms, using `Event` objects from both parsers.
- `detect/events.py`'s `gather_linux_text` deduplicates identical lines across every currently-retained `auth_*.log` before parsing — this is what fixes duplicate counting from overlapping collections (D1), and fixing D1 is what made D2 (correlation re-firing) resolve as a consequence rather than needing its own fix.
- The correlation fingerprint is built from the matching events' own `event_id`s rather than a hand-formatted string of fields. State written before v1.2 will not match the new scheme; any correlation still present re-alerts once on the first run after upgrading, then suppresses correctly — confirmed live against a real deployment's existing state.

### Alerting
- Detection and correlation alerts are written to `alerts.log` through `common/store.py`.
- `report/summary.py` provides an analyst-facing summary. Both it and the dashboard read alerts through the same function, so their totals cannot disagree.

### Incident Reporting
- `report/incidents.py` converts each new alert into a structured JSON incident record.
- Severity, detection reason, and platform come from `common/classification.py`; field extraction from `common/patterns.py`.
- Processed alerts are tracked by fingerprint in `incident_state.txt`.

### Automated Response
- `respond/actions.py` evaluates incidents against a configurable severity gate and the presence of a source IP.
- Qualifying incidents produce a **simulated, log-only** action in `actions.log` — no firewall, `hosts.deny`, or other system change.
- An incident that meets the severity gate but has no source IP is reported by ID rather than silently counted as non-qualifying.
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
- Persistent correlation state / duplicate prevention, keyed by event identity rather than a formatted string of fields

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
| Stage 1 — package, configuration, shared library (v1.1) | Complete |
| **Stage 2 — event schema, parsers, Windows collection redesign (v1.2)** | **Complete** |
| Stage 3 — SQLite datastore | Planned |

## 8. Attack Scenario Testing Summary

The pipeline was validated end to end with deliberate attacks from Kali against both lab targets rather than relying on incidental traffic:

- **Linux (SSH):** Hydra brute-force against Ubuntu, ending in a real successful login. Confirmed detection, correlation, incident generation, simulated response, and dashboard reflection.
- **Windows (SMB):** Metasploit `smb_login` brute-force against the Windows target, after SSH (not installed) and RDP (blocked by firewall until Remote Desktop was enabled) proved non-viable. This testing surfaced a real account-extraction bug — both the analyzer and the correlator were taking the first `Account Name:` match in a Windows event rather than anchoring to the correct section per event type. v1.1 anchored the fix to one shared function; v1.2 removed the anchoring problem's entire cause by reading `TargetUserName` as a named XML field instead of prose.
- **v1.2, against the real endpoint directly (not a scripted attack):** a bootstrap collection surfaced genuine output corruption from PowerShell's own formatter, and a real log directory surfaced a file-selection bug from leftover files the old collector had produced. Both are documented in `docs/decisions/0003-windows-output-reconstruction.md` and the README's verification section — neither was found by, or reproducible from, a fixture.

## 9. Known Structural Issues

Carried forward deliberately, with the stage that resolves each. Fixing any of them means changing a fingerprint or a stored value, which would invalidate existing state files — so they are scheduled behind the point where there is something to verify a change against.

| ID | Issue | Resolved in |
|---|---|---|
| D3 | Analyzers have no alert state file and re-append identical alerts every run | Stage 3 |
| D4 | Incident fingerprint hashes the alert line including its timestamp, creating duplicate incidents | Stage 3 |
| D11 | Correlation is O(failures × successes) with no time index | Stage 3 |
| D14 | Correlator evaluates every qualifying successful login independently; several successes from one real session each raise a separate, near-identical alert | Stage 7 |

Resolved in v1.1: D5 (syslog timestamp formats), D6 (hardcoded timezone), D7 (alert counting mismatch between summary and dashboard), D8 (duplicated severity logic), D9 (hardcoded absolute paths).

Resolved in v1.2: D1 (duplicate counting from overlapping collections, via line-level deduplication — verified against 7 overlapping copies of one real attack), D2 (correlation re-firing, resolved as a direct consequence of fixing D1 rather than needing its own change), D10 (Windows collector now incremental via a persisted watermark), D12 (account extraction reads named XML fields; the anchoring bug's entire class is structurally impossible now, not better-anchored), D13 (the Windows endpoint holds no credential for the SOC; collection is SOC-initiated per ADR 0002).

D14 is new, found live: the correlator has always evaluated each qualifying successful login independently, but this was never observed producing near-duplicate alerts until real reconnect activity on the SOC server triggered it during v1.2 verification.
