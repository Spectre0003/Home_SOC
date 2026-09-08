# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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