# Home SOC — Telemetry Notes

This document describes the raw data the pipeline actually consumes: where it comes from, how it's structured, and the quirks and assumptions each parser depends on. `architecture.md` describes the pipeline's shape; this document describes the data flowing through it.

## 1. Linux Telemetry

**Source:** `/var/log/auth.log`, copied verbatim by `collect_linux_logs.sh` into a timestamped `auth_*.log`. `journalctl --no-pager` output is also captured into `journal_*.log`, though only `auth_*.log` is currently parsed by the analysis/correlation scripts.

**Timestamp format:** ISO 8601 with UTC offset, e.g. `2026-09-04T09:34:21.123456+00:00`. `correlate_events.py` parses this with `datetime.fromisoformat()`. `analyze_linux_logs.py` does not use the timestamp at all — it only counts and pattern-matches on line content.

**Relevant line patterns:**

| Event | Line contains | Fields extracted |
|---|---|---|
| Failed SSH login | `Failed password` | source IP (`from (\d+\.\d+\.\d+\.\d+)`), account (`Failed password for (invalid user )?(\S+)`) |
| Successful SSH login | `Accepted password` or `Accepted publickey` | source IP, account (`Accepted (password|publickey) for (\S+)`) |
| Sudo failure | `sudo:` + `authentication failure` | none extracted beyond presence |
| Sudo command | `sudo:` + `COMMAND=` | none extracted beyond presence |

**Notes:**
- Linux telemetry is UTC throughout — no timezone conversion needed on this side of the correlator.
- `account` defaults to `"unknown"` (the literal string) when the regex doesn't match, not `None`/`null`. This matters for correlation matching logic (see Section 3).

## 2. Windows Telemetry

**Source:** A manually-run PowerShell collector script on the Windows endpoint (`C:\homesoc\...`, not currently part of `run_soc.sh`). It pulls the 500 most recent Security events matching IDs 4624, 4625, 4672 via `Get-WinEvent -FilterHashtable`, formats each into a text block, and `scp`s the result to the Ubuntu SOC server as `windows_security_<timestamp>.log`.

**Collection quirk — event ordering:** `Get-WinEvent` returns events **newest-first** by default, and the collector writes them to the log file in that same order. The top of the file is the most recent activity; the bottom is the oldest of the 500 captured. This is easy to get backwards when spot-checking a log with `tail`.

**Analysis quirk — only the newest log file is read:** Both `analyze_windows_logs.py` and `correlate_events.py` select the Windows log to analyze via `sorted(glob.glob(f"{LOG_DIR}/windows_*.log"))[-1]` — i.e., only the most recently collected file. Older `windows_*.log` files are never reprocessed once a newer one exists.

**Timestamp format:** `TimeCreated : MM/dd/yyyy HH:mm:ss`, e.g. `09/04/2026 12:14:05`. `correlate_events.py` parses this with `strptime(timestamp_string, "%m/%d/%Y %H:%M:%S")` — strict 24-hour, zero-padded. This format has held consistently in testing, but it is a PowerShell default-locale rendering, not a fixed export format — a different regional/locale setting on the Windows box (e.g. 12-hour `AM/PM`, or non-zero-padded values) would silently break parsing. `correlate_events.py` swallows the resulting `ValueError` and skips the event with no error output, so a locale change would show up as Windows events quietly failing to correlate, not as a visible failure.

**Timezone handling:** Windows event timestamps are treated as local time in `WINDOWS_TIMEZONE = timezone(timedelta(hours=5, minutes=30))` (IST), hardcoded in `correlate_events.py`, then converted to UTC before comparison against Linux's already-UTC timestamps. This offset is **not derived from the Windows box's actual configured timezone** — it's a fixed assumption baked into the script. If the Windows VM's timezone or the lab's location ever changes, this constant needs to be updated manually or correlation timing will be silently wrong.

**Multiple `Account Name:` fields per event — the core parsing hazard:** Windows event message text contains more than one `Account Name:` line, in different sections depending on event type. Which one is meaningful depends on the event ID:

| Event ID | Section containing the *meaningful* account | Other `Account Name:` occurrences that can appear first |
|---|---|---|
| 4624 (successful logon) | `New Logon:` | `Subject:` — often `-` for network logons, or a system/computer account |
| 4625 (failed logon) | `Account For Which Logon Failed:` | `Subject:` — typically `-` (anonymous, since a failed logon has no authenticated subject) |
| 4672 (privileged logon) | `Subject:` (only one section present) | none — single occurrence, safe to match generically |

Both `analyze_windows_logs.py` and `correlate_events.py` extract the account by anchoring to the correct section per event ID (`New Logon:` / `Account For Which Logon Failed:`) rather than taking the first `Account Name:` match in the whole event — see `troubleshooting_log.md` for the bug this replaced.

**Source IP field:** `Source Network Address:` under `Network Information:` — a single, unambiguous occurrence per event, no equivalent hazard to the account field.

## 3. Cross-Source Correlation Assumptions

`correlate_events.py` matches a successful login against prior failures using:

- **Time window:** failure must occur before the success and within `TIME_WINDOW = timedelta(minutes=5)`.
- **Source IP match:** only enforced if *both* the success and the failure have a known (non-`"unknown"`) IP; if either side is `"unknown"`, the IP check is skipped rather than treated as a mismatch.
- **Account match:** same logic — only enforced if both sides have a known (non-`"unknown"`) account.

This means a literal extracted value of `"-"` is **not** treated as unknown — it's treated as a specific, matchable account value. Two events that both happen to extract `"-"` as their account (e.g. two anonymous-subject events) will satisfy the account-match check against each other, which is how the pre-fix account-extraction bug produced a `CRITICAL` correlation attributed to account `-` instead of failing to correlate at all. `"unknown"` is the only value the matching logic treats as a wildcard; `"-"` is not.

## 4. Alert Message Format ("Schema")

There is no structured/serialized alert schema — every downstream stage (`alert_summary.py`, `generate_incidents.py`, `generate_dashboard.py`) re-parses the plain-text alert strings written to `alerts.log`. The exact wording is therefore a de facto contract; changing a message string in one of the detection scripts without updating the parsers elsewhere will silently break severity classification, field extraction, or both.

Current message templates, by source:

| Source script | Message template |
|---|---|
| `analyze_linux_logs.py` | `Multiple failed login attempts detected.` |
| `analyze_linux_logs.py` | `Brute-force activity detected from {ip} ({count} failed login attempts).` |
| `analyze_linux_logs.py` | `Sudo authentication failure detected.` |
| `analyze_windows_logs.py` | `Multiple Windows failed login attempts detected ({count} attempts).` |
| `analyze_windows_logs.py` | `Repeated failed Windows logins detected for account {account} ({count} attempts).` |
| `correlate_events.py` | `Authentication attack pattern detected: {count} failed login attempts followed by a successful login for account {account} from {ip}.` |

All alert lines share the same prefix format: `{"%Y-%m-%d %H:%M:%S"} [ALERT] {message}`.

## 5. Known Telemetry Risks / Fragility

- **Locale-dependent Windows timestamp parsing** (Section 2) — works today, not guaranteed to survive a system locale change.
- **Hardcoded IST offset** (Section 2) — not derived from the Windows box's actual timezone; a silent source of correlation error if the lab's timezone assumptions ever change.
- **Only the newest Windows log is analyzed per run** — if the collector isn't run promptly after an attack, or is run multiple times before `run_soc.sh`, older captured events between collections are never analyzed unless they happen to still be within the 500-event window of a later pull.
- **Plain-text alert message parsing as a de facto schema** (Section 4) — no validation layer; a wording change in one script is a silent breaking change for every downstream consumer.
- **`"-"` vs `"unknown"` are not equivalent** in the correlator's matching logic (Section 3) — worth keeping in mind for any future detection rule that extracts fields from raw event text.