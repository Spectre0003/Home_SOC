"""
Windows Security event collection.

Pulls new events from the Windows endpoint's Security log over WinRM,
rather than v1.0's model of a script run by hand on the endpoint that
``scp``s its own output to the SOC server (ADR 0002). The SOC server
initiates every collection; the endpoint holds no credential for the
SOC and keeps no state of its own — the watermark lives here, in
``homesoc.common.store``.

A persisted watermark (the highest EventRecordID collected so far)
means each run asks Windows for only what's new since last time. That
is the actual fix for roadmap defect D10 — v1.0's collector always
pulled the latest 500 events regardless of what had already been
collected, guaranteeing overlap on every run.

Output lands under the same ``windows_*.log`` naming and one-XML-event-
per-line shape ``homesoc.parse.windows`` already expects (built in pass
2c), so nothing downstream of collection changed for this pass.

The policy decisions — bootstrap vs. incremental, and detecting a
cleared Security log — are deliberately plain Python functions with no
WinRM call inside them (:func:`decide_watermark`, :func:`build_xpath`).
Only the mechanical "run this script over this session" part touches
the network, so the decisions themselves can be tested without a
Windows box, pywinrm, or a mock of either.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import List, Optional
from pathlib import Path

from homesoc.common import store
from homesoc.common.log import get_logger

logger = get_logger(__name__)


LOG_NAME = "Security"

_RECORD_ID = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")


# =============================================
# POLICY (pure — no I/O, no network)
# =============================================


def decide_watermark(
    stored_watermark: Optional[int], head_id: Optional[int]
) -> Optional[int]:
    """
    Whether this collection is incremental or a bootstrap.

    Returns the watermark to filter from, or None to mean "bootstrap:
    take the most recent events, there is nothing to resume from".

    A *head_id* lower than *stored_watermark* means the Security log's
    current newest record is behind where we last left off — the log
    was cleared or replaced since the last collection. There is nothing
    to recover from that; the right response is to resume monitoring
    from a bounded recent window, not to keep filtering for a record ID
    that will never appear again.

    *head_id* being None (the diagnostic call to find it failed) is not
    treated as a clear — it degrades to ordinary incremental collection
    rather than needlessly discarding a perfectly good watermark over a
    failed side-query.
    """

    if stored_watermark is None:
        return None

    if head_id is not None and head_id < stored_watermark:
        return None

    return stored_watermark


def build_xpath(event_ids: List[int], watermark: Optional[int]) -> str:
    """
    The event-log XPath filter for the given event IDs and watermark.

    No watermark means no lower bound at all — every matching event
    within whatever ``-MaxEvents`` cap the caller applies.
    """

    id_filter = " or ".join(f"EventID={event_id}" for event_id in event_ids)

    if watermark is not None:
        return f"*[System[({id_filter}) and (EventRecordID > {watermark})]]"

    return f"*[System[({id_filter})]]"


# =============================================
# POWERSHELL SCRIPT BUILDERS (pure — string in, string out)
# =============================================
#
# Placeholders use tokens that can't collide with PowerShell's own
# syntax (unlike str.format(), which would need every literal brace in
# the script escaped). Values placed into these come only from our own
# config and our own previously-stored state — never from anything an
# attacker could shape — so no injection concern applies here.
# =============================================

_HEAD_SCRIPT = """
$e = Get-WinEvent -LogName '__LOG_NAME__' -MaxEvents 1 -ErrorAction SilentlyContinue
if ($e) { $e.RecordId } else { 0 }
"""

_FETCH_SCRIPT = """
$xpath  = '__XPATH__'
$events = Get-WinEvent -LogName '__LOG_NAME__' -FilterXPath $xpath -MaxEvents __MAX_EVENTS__ __OLDEST_FLAG__ -ErrorAction SilentlyContinue
if ($events) {
    $events | Sort-Object RecordId | ForEach-Object { $_.ToXml() }
}
"""


def build_head_script(log_name: str = LOG_NAME) -> str:
    """Script to find the log's current newest record ID."""

    return _HEAD_SCRIPT.replace("__LOG_NAME__", log_name)


def build_fetch_script(
    xpath: str, max_events: int, oldest: bool, log_name: str = LOG_NAME
) -> str:
    """
    Script to fetch matching events, one ``ToXml()`` document per line.

    *oldest* controls traversal direction, and the choice matters for
    correctness, not just style. Incremental collection (a watermark is
    set) uses ``-Oldest`` so a backlog bigger than *max_events* drains
    in order across successive runs — without it, ``-MaxEvents`` takes
    the *newest* N matches, which for a large backlog would skip every
    older-but-still-unseen event in between and silently lose them.
    Bootstrap collection (no watermark) wants exactly the opposite: the
    most recent events are the useful starting point, not whatever the
    log happens to have retained from years ago.
    """

    script = _FETCH_SCRIPT

    script = script.replace("__XPATH__", xpath.replace("'", "''"))
    script = script.replace("__LOG_NAME__", log_name)
    script = script.replace("__MAX_EVENTS__", str(int(max_events)))
    script = script.replace("__OLDEST_FLAG__", "-Oldest" if oldest else "")

    return script


def parse_record_ids(output: str) -> List[int]:
    """Every EventRecordID present in collected XML output."""

    return [int(match) for match in _RECORD_ID.findall(output)]


def _parse_single_int(raw: bytes) -> Optional[int]:

    try:
        return int(raw.decode("utf-8", errors="ignore").strip())

    except (ValueError, AttributeError):
        return None


# =============================================
# COLLECTION (the only part that touches the network)
# =============================================


def collect(config) -> Optional[Path]:
    """
    Pull new Windows Security events since the last collection.

    Returns the path of the collected file, or None. None covers three
    different situations, distinguished only by log level rather than
    return value, since the return type here doesn't carry a reason:
    nothing configured (debug), a real failure to connect, authenticate,
    or run the query (error), or a perfectly normal "nothing new since
    last time" (info). Giving the CLI's exit code its own opinion about
    which of those should count as a pipeline failure is Stage 8's job,
    once pipeline health monitoring exists to act on it.
    """

    host = config.windows_host

    if not host:
        logger.debug("No Windows endpoint configured, skipping")
        return None

    username = config.get("collection.windows.username")

    password = config.windows_winrm_password

    if not username or not password:

        logger.error(
            "Windows collection needs credentials — set "
            "collection.windows.username in config.yaml and the "
            "HOMESOC_WINRM_PASSWORD environment variable"
        )
        return None

    try:
        import winrm

    except ImportError:

        logger.error("pywinrm is not installed — run: pip install pywinrm")
        return None

    port = config.get("collection.windows.winrm_port")

    transport = config.get("collection.windows.transport")

    timeout = config.get("collection.windows.timeout_seconds")

    event_ids = config.get("collection.windows.event_ids")

    max_events = config.get("collection.windows.max_events")

    target = f"http://{host}:{port}/wsman"

    stored_watermark = store.read_watermark(config.windows_watermark_state, host)

    try:
        session = winrm.Session(
            target,
            auth=(username, password),
            transport=transport,
            operation_timeout_sec=timeout,
            read_timeout_sec=timeout + 10,
        )

        head_result = session.run_ps(build_head_script())

    except Exception as error:

        # pywinrm raises several distinct exception types depending on
        # what went wrong (refused connection, TLS, timeout) — all of
        # them mean "collection didn't happen", which is what matters
        # here; there's no different recovery for one versus another.

        logger.error("Could not reach %s over WinRM: %s", host, error)
        return None

    head_id = None

    if head_result.status_code == 0:
        head_id = _parse_single_int(head_result.std_out)

    else:
        logger.warning(
            "Could not determine %s's current log position (exit %d) — "
            "proceeding without log-clear detection this run",
            host,
            head_result.status_code,
        )

    effective_watermark = decide_watermark(stored_watermark, head_id)

    if stored_watermark is not None and effective_watermark is None:

        logger.warning(
            "%s's Security log head (record %s) is behind the stored "
            "watermark (%s) — the log appears to have been cleared or "
            "replaced. Resuming from a bounded recent window; events "
            "between the old watermark and now may have been missed.",
            host,
            head_id,
            stored_watermark,
        )

    xpath = build_xpath(event_ids, effective_watermark)

    script = build_fetch_script(
        xpath, max_events, oldest=effective_watermark is not None
    )

    logger.info(
        "Collecting Windows events from %s (%s)",
        host,
        f"watermark={effective_watermark}"
        if effective_watermark is not None
        else "bootstrapping",
    )

    try:
        result = session.run_ps(script)

    except Exception as error:

        logger.error("WinRM call to %s failed: %s", host, error)
        return None

    if result.status_code != 0:

        stderr = result.std_err.decode("utf-8", errors="ignore").strip()

        logger.error(
            "PowerShell exited %d on %s: %s",
            result.status_code,
            host,
            stderr or "no error detail",
        )

        if "denied" in stderr.lower() or "unauthorized" in stderr.lower():

            logger.error(
                "Check that %s is a member of 'Event Log Readers' and "
                "'Remote Management Users' on %s",
                username,
                host,
            )

        return None

    output = result.std_out.decode("utf-8", errors="ignore").strip("\ufeff \r\n")

    if not output:
        logger.info("No new Windows events since the last collection")
        return None

    record_ids = parse_record_ids(output)

    if not record_ids:

        logger.warning(
            "Windows returned output with no recognisable EventRecordID "
            "— not advancing the watermark"
        )
        return None

    new_watermark = max(record_ids)

    config.ensure_directories()

    suffix = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    destination = config.log_dir / f"windows_{suffix}.log"

    destination.write_text(output + "\n", encoding="utf-8")

    # Only advance the watermark once the file is safely on disk — a
    # failure between the WinRM call and this write must not lose
    # events, the same principle homesoc.collect.linux follows for the
    # auth log copy.

    store.write_watermark(config.windows_watermark_state, host, new_watermark)

    logger.info(
        "Collected %d new Windows event(s) into %s (watermark now %d)",
        len(output.splitlines()),
        destination.name,
        new_watermark,
    )

    return destination
