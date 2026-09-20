# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.2.0] - 2026-09-20

Stage 2 of the v2.0 roadmap: a normalized event schema, real parsers for both
platforms, and a Windows collector that pulls over WinRM instead of waiting for
a script to be run by hand. Verified against real Linux and Windows data, not
only fixtures — twice, including a live diagnosis and fix of a genuine data
corruption bug (see ADR 0003).

### Added
- `homesoc/parse/event.py` — the normalized `Event` schema (ECS-style grouping:
  `event.*`, `user.*`, `source.*`), with a content-addressed `event_id` computed
  from raw line content alone, not filename or position
- `homesoc/parse/linux.py` — pure-function parser for `auth.log`, replacing the
  regex matching `homesoc.detect.linux` carried since Stage 1
- `homesoc/parse/windows.py` — parser reading named Windows Event XML fields
  (`TargetUserName`, `IpAddress`, `LogonType`, `Status`, `SubStatus`) instead of
  rendered message text
- `homesoc/collect/windows.py` — SOC-initiated WinRM pull over `pypsrp`, with a
  persisted watermark (`windows_watermark.json`) for incremental collection and
  automatic recovery if the Security log is cleared or replaced
- `homesoc.common.store.read_watermark` / `write_watermark` — small JSON-backed
  state, one file, keyed by host, so a second endpoint later needs no schema change
- `docs/decisions/0003-windows-output-reconstruction.md` — the pypsrp swap and
  the delimiter-based reconstruction that actually fixed the corruption, with the
  live evidence for each step

### Changed
- `homesoc/detect/linux.py`, `homesoc/detect/windows.py`, `homesoc/detect/correlate.py`
  rewired to consume `Event` lists from the parsers; no detector touches a raw
  log line directly any more
- Correlation fingerprint rebuilt from `event_id` pairs instead of a hand-formatted
  `ip|account|timestamp|count` string — see Migration note below
- `homesoc/detect/events.py`'s `AuthEvent`/`UNKNOWN` stopgap retired, as flagged
  when it was introduced in Stage 1; replaced everywhere by `Event`
- `find_linux_logs` / `find_latest_windows_log` now match this pipeline's exact
  filename shape (`auth_YYYY-MM-DD_HH-MM-SS.log`, `windows_YYYY-MM-DD_HH-MM-SS.log`)
  and select by file modification time, not filename string order
- Windows event transport: `pypsrp` instead of `pywinrm` (ADR 0003)
- `config.yaml` schema: `collection.windows.timezone` removed — Windows Event XML's
  own `TimeCreated` is always UTC, so there is nothing left to configure. Added
  `username`, `password` (env var preferred), `winrm_port`, `use_ssl`, `auth`,
  `timeout_seconds`. `transport` (pywinrm's conflated encryption+auth string) is
  gone; replaced by `auth` and `use_ssl` as separate settings
- `common/patterns.py`'s entire rendered-text Windows section removed
  (`windows_account`, `parse_windows_timestamp`, the anchoring regexes) — confirmed
  via full-codebase search to have zero remaining callers before deletion

### Fixed
- **D1** — collection re-copying the whole auth log on every run inflated every
  count proportionally to how many overlapping copies had accumulated. Fixed by
  `homesoc.detect.events.gather_linux_text`, which deduplicates identical lines
  across every currently-retained `auth_*.log` before anything counts a thing.
  Verified against 7 overlapping copies of one real attack: true count (8) reported,
  not the naive 56
- **D2** — correlation re-firing on an already-suppressed attack because the
  fingerprint embedded an inflated match count. This was a direct symptom of D1,
  not a separate bug; fixing D1 made the count stable and the existing suppression
  mechanism started working correctly on its own
- **D5** — traditional syslog timestamps (`Sep  7 04:11:02`, no year, no offset)
  parse correctly through the same code path RFC3339 uses
- **D10** — Windows collector pulled the latest N events regardless of what had
  already been collected, guaranteeing overlap on every run. Fixed by the
  persisted watermark; a backlog larger than `max_events` drains in order across
  successive runs via `-Oldest` rather than silently skipping a gap
- **D12** — the account-anchoring bug class (reading the first `Account Name:`
  line in rendered prose, which sits under a different heading depending on
  event type) is structurally impossible now, not better-anchored: `TargetUserName`
  means the same thing on every logon event, so there is no per-event-ID branch
  in the account-extraction path at all — verified by asserting zero such
  branches exist in `parse_event_xml`
- **D13** — the Windows endpoint no longer holds a credential for the SOC server;
  the SOC initiates every collection (ADR 0002)
- Windows output corruption: PowerShell's own output formatter was word-wrapping
  large strings before either transport library ever saw them, corrupting roughly
  80% of a 500-event bootstrap pull. Fixed by joining events with an XML-illegal
  delimiter and reconstructing on the Python side rather than trusting newlines in
  transit (ADR 0003) — the `pypsrp` swap alone did not fix this, confirmed live
- `find_latest_windows_log` could silently select a stale file left by the old
  v1.0 push-based collector (`windows_security_*.log`) over the genuinely newest
  collection, because that filename sorts *after* the current naming convention
  lexicographically. Found from real leftover files in a real log directory, not
  a fixture

### Known issues
Carried forward deliberately; see `architecture.md` section 9 and `ROADMAP.md`.

- **D3, D4** (repeated alerts becoming duplicate incidents) — still Stage 3
- **D11** (correlation complexity) — still Stage 3
- **D14** (new) — the correlator evaluates every qualifying successful login
  independently; several successes from one real session (e.g. a few quick SSH
  reconnects) each raise their own, textually near-identical alert instead of
  being recognised as one entity. Observed live: three alerts for one evening's
  legitimate reconnect activity. Alert-to-incident grouping is Stage 7's job

### Migration note
The correlation fingerprint scheme changed (see Changed, above). Any correlation
still present in a deployment's retained logs will re-alert **once** on the first
`homesoc correlate` run after upgrading, then suppress correctly on every run after
that. This is a one-time, bounded cost of the old state having been built on data
D1/D2 were inflating in the first place — confirmed live: a deployment with 14
entries in `correlation_state.txt` saw exactly one re-alert batch, then returned to
normal.

## [1.1.0] - 2026-09-08

Stage 1 of the v2.0 roadmap: the pipeline becomes an installable package
with external configuration. Detection behaviour is unchanged and was
verified equivalent to v1.0.

### Added
- Installable `homesoc` package with `pyproject.toml` and a `homesoc` console command
- External `config.yaml` with deep-merged defaults, path token expansion, and load-time validation
- `homesoc config --check` to verify configured paths exist and are usable
- Shared `common/` modules: configuration, alert classification, log patterns, logging, and file I/O
- Rotating run log at `logs/homesoc.log`, recording DEBUG regardless of console verbosity
- `--verbose` / `--quiet`, usable before or after the subcommand
- `--platform` filter on `homesoc analyze`
- `ROADMAP.md`, `CHANGELOG.md`, and `docs/decisions/` architecture decision records
- `.gitattributes` normalising line endings across the Windows/Linux split

### Changed
- Nine standalone scripts replaced by package modules; `run_soc.sh` is now a wrapper around `homesoc run`
- Detection thresholds, correlation window, response severity gate, and endpoint timezone moved from source literals to configuration
- Matched log lines moved from stdout to DEBUG, so findings are visible at default verbosity
- Windows event timestamps tried against several locale formats instead of one
- `windows_source_ip` returns `None` rather than the string `"unknown"` when absent

### Fixed
- Alert summary counted every non-empty line in `alerts.log` as an alert while the dashboard filtered on `[ALERT]`, so the two disagreed on the same file (D7)
- Severity classification existed in three files with differing fallthrough branches (D8)
- Linux timestamps in traditional syslog format were silently unparseable, emptying correlation on any host not using RFC3339 (D5)
- IPv4 pattern matched invalid addresses such as `999.999.999.999`
- Endpoint timezone was hardcoded to `+05:30` (D6)
- Absolute paths to `/home/socadmin` were hardcoded throughout (D9)
- A failed `cp` or `journalctl` during collection reported success over an empty file
- A CRITICAL incident with no source IP was silently counted as non-qualifying for response

### Known issues
Carried forward deliberately; see `architecture.md` section 9 and `ROADMAP.md`.
D1, D2 (duplicate ingest and correlation re-firing), D3, D4 (repeated alerts
becoming duplicate incidents), D10, D12, D13 (Windows collection), D11
(correlation complexity).

## [1.0.0] - 2026-09-04

Initial complete pipeline: collection, analysis, detection, correlation,
alerting, incident reporting, simulated response, dashboard, and end-to-end
attack scenario testing against Linux and Windows targets.
