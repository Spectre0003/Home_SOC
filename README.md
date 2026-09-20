# Home SOC

A small, custom Security Operations Center (SOC) lab built to learn and demonstrate practical security monitoring, log analysis, detection, event correlation, alerting, and incident reporting.

## Current Progress

v1.0 completed the core SOC detection and reporting pipeline. v1.1 restructured that pipeline into an installable, configurable Python package. v1.2 replaced regex-scraped log lines with a normalized event schema and real parsers, and replaced the manual Windows collection script with an automated WinRM pull — verified against real Linux and Windows data, including a live diagnosis and fix of a genuine data-corruption bug.

- Linux log collection
- Linux authentication and sudo analysis
- Windows Security log collection — now an automated WinRM pull, not a script run by hand
- Windows Security event analysis — now via structured event fields, not rendered text
- Detection rules
- Cross-event authentication correlation
- Persistent correlation state / alert deduplication
- Central alert logging
- Alert summary reporting
- Structured incident/case reporting
- Automated response (log-only simulated actions)
- Dashboard/visualization
- Attack scenario testing (validated end-to-end against both Linux and Windows targets)
- Installable package with external configuration and a single CLI (v1.1)
- **Normalized event schema, real parsers, and automated Windows collection (v1.2)**

**Current stage:** v1.2 complete. See `ROADMAP.md` for the ten-stage plan through v2.0.

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

Configuration is validated at load. A threshold below 1, an unknown severity name, an out-of-range port, or a circular path reference fails immediately with a specific message rather than partway through a run. Unrecognised keys are reported as probable typos rather than silently ignored.

Key settings:

| Key | Purpose |
|---|---|
| `paths.home` | Root for runtime data (logs, dashboard) |
| `collection.linux.auth_log` | Source authentication log |
| `collection.windows.host` | Windows endpoint to pull events from; `null` disables Windows collection |
| `collection.windows.username` | Dedicated low-privilege account — see Windows Collection Setup below |
| `collection.windows.max_events` | Bootstrap window and per-call incremental safety cap |
| `detection.*.threshold` | Per-platform detection thresholds |
| `correlation.window_minutes` | Correlation time window |
| `correlation.min_failures` | Failures required before a success correlates |
| `response.severities` | Which severities trigger a simulated action |

The Windows endpoint's password is never required to live in `config.yaml`, even though that file is gitignored — set the `HOMESOC_WINRM_PASSWORD` environment variable instead. It's checked before `collection.windows.password`, which exists purely as a documented fallback.

## Windows Collection Setup

The SOC server pulls Security events from the Windows endpoint over WinRM (ADR 0002); nothing runs on the endpoint on a schedule, and no script needs to live there at all.

**On the Windows endpoint**, in an elevated PowerShell prompt:

1. `Enable-PSRemoting -Force`. On a freshly-created lab network, this commonly fails to add the firewall exception with a message about the network being "Public" — a NAT or host-only adapter usually gets that category by default. Fix with `Set-NetConnectionProfile -InterfaceAlias "<your adapter>" -NetworkCategory Private` (find the alias via `Get-NetConnectionProfile`), then re-run `Enable-PSRemoting -Force`.
2. Confirm the firewall rule is actually enabled, not just present: `Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP" | Select-Object Enabled`. If it shows `False` — which can happen if the first `Enable-PSRemoting` ran before the network category was fixed — enable it directly: `Enable-NetFirewallRule -Name "WINRM-HTTP-In-TCP"`.
3. Create a dedicated account and grant exactly two group memberships, no more:
   ```powershell
   $password = Read-Host -AsSecureString -Prompt "Password"
   New-LocalUser -Name "socmonitor" -Password $password -PasswordNeverExpires -AccountNeverExpires
   Add-LocalGroupMember -Group "Event Log Readers" -Member "socmonitor"
   Add-LocalGroupMember -Group "Remote Management Users" -Member "socmonitor"
   ```
   The first grants read access to the Security log specifically (it has stricter ACLs than other logs); the second is what lets a non-administrator authenticate over WinRM at all.

**On the SOC server**, set `collection.windows.host` and `collection.windows.username` in `config.yaml`, then:

```bash
export HOMESOC_WINRM_PASSWORD="..."
homesoc -v collect
```

A successful run logs `Collected N new Windows event(s) into windows_...log`. An "Access is denied" style error after the setup above usually means a typo in the account name rather than a missing permission — both required group memberships are checked for by name in that error path.

## Architecture

```text
Kali / Testing
      |
      | attack / test activity
      v
Windows Endpoint <-------+
      |                  |  WinRM pull, SOC-initiated (ADR 0002)
      | Security events  |  no script or credential on the endpoint
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
 Linux Parser    Windows Parser        (homesoc.parse — normalized Events,
       |               |                no detector touches a raw line)
       +-------+-------+
               |
       +-------+-------+
       |               |
       v               v
Linux Detector   Windows Detector
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
|   |   +-- patterns.py          # Linux log regexes and field extraction
|   |   +-- log.py               # logging setup
|   |   +-- store.py             # alert, state, JSONL, and watermark I/O
|   |
|   +-- parse/                   # raw text/XML -> normalized Event (v1.2)
|   |   +-- event.py             # the Event schema itself
|   |   +-- linux.py             # auth.log -> Event
|   |   +-- windows.py           # Windows Event XML -> Event
|   |
|   +-- collect/
|   |   +-- linux.py
|   |   +-- windows.py           # WinRM pull over pypsrp, watermarked (v1.2)
|   |
|   +-- detect/
|   |   +-- events.py            # log discovery, cross-file deduplication
|   |   +-- linux.py             # consumes parse.linux's Events
|   |   +-- windows.py           # consumes parse.windows's Events
|   |   +-- correlate.py         # event_id-based fingerprint (v1.2)
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
    +-- windows_watermark.json   # incremental collection state (v1.2)
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
Loads, merges, and validates configuration; resolves and expands all paths; exposes typed values (correlation window as a `timedelta`, the Windows WinRM password preferring the environment over the file).

### `homesoc/common/classification.py`
One signature table mapping an alert message to its severity, detection reason, and platform. v1.0 derived these from three separate if-chains across three files, which agreed by coincidence rather than by construction.

### `homesoc/common/patterns.py`
Linux log regexes and field extraction (timestamp formats, hostname, sudo field parsing, IPv4 validation). The rendered-text Windows parsing this module carried through Stage 1 — the account anchoring, the timezone conversion — was removed in v1.2 once `homesoc.parse.windows` made it dead code; confirmed via a full-codebase search for callers before deletion.

### `homesoc/common/log.py`
Console output plus a rotating run log. The console honours `--verbose` / `--quiet`; the file always records DEBUG, because the run you need detail from is the one that already happened.

### `homesoc/common/store.py`
All reading and writing of `alerts.log`, the state files, the JSONL incident and action logs, and — new in v1.2 — the Windows collection watermark (`windows_watermark.json`, keyed by host). State entries are buffered and written on flush, so a run that fails partway does not record work it never completed.

### `homesoc/parse/event.py`
The normalized event schema every parser produces and every detector consumes. Grouped like Elastic Common Schema (`event.category`/`action`/`outcome`, `user.name`, `source.ip`) via nested dataclasses. `event_id` is a content-only hash of the raw line or XML document — not the source filename, not a line offset — which is what lets identical events collected in overlapping files collapse to one rather than being counted per copy.

### `homesoc/parse/linux.py`
Turns raw `auth.log` text into `Event` objects: SSH logins (`Failed password` / `Accepted password` / `Accepted publickey`) and sudo authentication failures. Sudo *command execution* is deliberately not modelled as an Event — it's an audit record, not an authentication outcome — and stays a separate informational count.

### `homesoc/parse/windows.py`
Reads named `EventData` fields (`TargetUserName`, `IpAddress`, `LogonType`, `Status`, `SubStatus`) from Windows Event XML instead of rendered message text. `TargetUserName` means the same thing on a 4624 and a 4625, so there is no per-event-ID branching to get the account right — the Phase 14 anchoring bug's entire class is structurally impossible here, not better-anchored.

### `homesoc/collect/linux.py`
Collects Linux authentication logs and system journal data into timestamped files. A failed copy or a `journalctl` error is now an error rather than a silent success.

### `homesoc/collect/windows.py`
Pulls new Security events from the Windows endpoint over WinRM (`pypsrp`), rather than waiting for a script to be run by hand on the endpoint. A persisted watermark means each collection asks for only what's new since last time; a Security log clear or replacement is detected and recovered from automatically. Events are joined with an XML-illegal delimiter and reconstructed on receipt rather than trusting newlines during transit — PowerShell's own output formatter word-wraps long strings before either transport library involved ever sees them (ADR 0003).

### `homesoc/detect/events.py`
Log discovery (`find_linux_logs`, `find_latest_windows_log`) and, new in v1.2, `gather_linux_text` — line-level deduplication across every currently-retained `auth_*.log`, which is what actually fixes the duplicate counting that overlapping collections caused. File matching uses this pipeline's exact naming shape and selects by modification time, not filename string order, after a real deployment's leftover files from the old collector proved lexicographic sort insufficient.

### `homesoc/detect/linux.py`
Consumes `Event` lists from `homesoc.parse.linux` — no regex matching of its own — for:

- Failed logins
- Successful logins
- Brute-force activity by source IP
- Sudo authentication failures
- Sudo command execution

### `homesoc/detect/windows.py`
Consumes `Event` lists from `homesoc.parse.windows`:

- Event ID 4624 — successful logon
- Event ID 4625 — failed logon
- Event ID 4672 — privileged logon activity (informational count only, not an Event)
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

Correlation state is stored in `correlation_state.txt`. **The fingerprint scheme changed in v1.2** — it's now built from the endpoints' own `event_id`s rather than a hand-formatted `ip|account|timestamp|count` string, which is what makes the count behind it stable once the input is deduplicated. State written before v1.2 will not match; any correlation still present re-alerts once on the first run after upgrading, then suppresses correctly from then on.

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
| Normalized event schema, parsers, WinRM collection (v1.2) | Complete |
| SQLite datastore (v1.3) | Planned |

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

### v1.2 verification, against real data — not only fixtures

The parser layer (`homesoc/parse/`) was unit-tested extensively against hand-built fixtures before ever touching real hardware, including the D1 duplicate-ingest scenario reproduced with 7 overlapping full-copy collections of one real attack. But the Windows collector specifically could only be proven against the actual endpoint, and doing that surfaced two real bugs no fixture would have caught:

**Bug found:** a bootstrap pull of 500 events came back as 3022 lines, most of them unparseable. Switching the transport library (`pywinrm` → `pypsrp`) reproduced the exact same corrupted count, which ruled out a transport-layer fragmentation bug — the damage was happening inside PowerShell's own output formatter, which word-wraps long strings to a console width even in a headless remote session with none.

**Fix:** events are now joined with an XML-illegal delimiter (`0x1E`) instead of a newline, and reconstructed on the Python side by stripping every formatter-inserted newline before splitting on the real delimiter. Verified by simulating the formatter's own word-wrap at several widths, including a wrap boundary forced to land inside a short XML tag — full reconstruction survives all of them. See `docs/decisions/0003-windows-output-reconstruction.md` for the complete story, including the fix that turned out not to be sufficient on its own.

**Bug found:** `find_latest_windows_log` globbed `windows_*.log` and picked the alphabetically-last match. A real log directory holding leftover files from the old v1.0 push-based collector (`windows_security_*.log`) exposed that `"windows_security_..."` sorts *after* the current naming convention — the analyzer would have silently picked a three-week-old stale file over a genuine same-day collection, with no error.

**Fix:** file discovery now matches this pipeline's exact naming shape and selects by file modification time rather than filename string order.

Both bugs were found and fixed live against the real lab, in the order the evidence pointed: diagnose, form a hypothesis, test it, and revise when the test disagreed with the hypothesis (the `pypsrp` swap looked sufficient on paper and wasn't, confirmed by testing it directly rather than assuming).

## Known Limitations / Future Work

This is a learning/portfolio SOC, not a production system. Known gaps, by design or by scope. `ROADMAP.md` tracks each with a defect ID and the stage that addresses it.

- **Repeated alerts become repeated incidents.** The Linux and Windows analyzers have no alert state file and re-append identical alerts each run; incident fingerprints hash the alert line including its timestamp, so each run creates fresh incidents for the same finding. (D3, D4 — Stage 3)
- **Multiple alerts for one real session aren't grouped.** The correlator evaluates every qualifying successful login independently, so a few quick legitimate reconnects can each raise their own, textually near-identical alert instead of being recognised as one entity. Observed live in this deployment. (D14 — Stage 7)
- **Incident status never transitions.** Every incident defaults to `open`; nothing closes, triages, or re-scores one. (Stage 7)
- **Response only covers CRITICAL incidents with a known source IP.** Configurable now, but HIGH and MEDIUM incidents get no action by default. (Stage 7)
- **Response actions are simulated, log-only.** Nothing is wired to a firewall or other enforcement point — a deliberate boundary, not an oversight.
- **Only the most recent Windows log file is analyzed per run.** Older files are never reprocessed once a newer one exists. (Stage 8)
- **No log rotation or retention policy** for `alerts.log`, `incidents.log`, or `actions.log`. The run log rotates; the pipeline logs do not. (Stage 3)
- **No automated tests.** (Stage 5)
- **Correlation is O(failures × successes)** with no time index. Fine at lab scale, quadratic past it. (D11 — Stage 3)
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
