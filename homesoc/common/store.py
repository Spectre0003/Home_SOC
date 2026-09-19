"""
Reading and writing the pipeline's data files.

Five of the v1.0 scripts opened these files themselves, each with its own
error handling. State-file loading appeared three times
(``correlate_events.py``, ``generate_incidents.py``,
``automated_response.py``); alert appending appeared three times; JSONL
reading twice. The implementations differed in small ways — some caught
``PermissionError``, some didn't; some filtered on ``[ALERT]``, some
counted every non-empty line as an alert (roadmap defect D7).

This module is the single place that touches those files.

Everything here is deliberately still flat-file. Stage 3 replaces the
whole module with SQLite; keeping the interface small now means that
swap touches one file rather than eight.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple

from homesoc.common import patterns
from homesoc.common.log import get_logger

logger = get_logger(__name__)


ALERT_MARKER = "[ALERT]"

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


# =============================================
# GENERIC FILE HELPERS
# =============================================


def read_lines(path: Path, missing_ok: bool = True) -> List[str]:
    """
    Non-empty, stripped lines from *path*.

    Returns an empty list when the file is missing and *missing_ok*, so
    callers do not each need their own try/except around a file that
    simply has not been created yet.
    """

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return [line.strip() for line in handle if line.strip()]

    except FileNotFoundError:

        if missing_ok:
            logger.debug("Not present yet: %s", path)
            return []

        raise

    except PermissionError:
        logger.error("Permission denied reading %s", path)
        raise


def append_line(path: Path, line: str) -> None:
    """Append a single line, creating parent directories as needed."""

    append_lines(path, [line])


def append_lines(path: Path, lines: Iterable[str]) -> None:
    """
    Append several lines in one open/close.

    v1.0 opened the alert log once per alert in some paths and once per
    batch in others. Batching is both faster and less likely to
    interleave badly if two stages ever run concurrently.
    """

    lines = [line for line in lines if line]

    if not lines:
        return

    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(path, "a", encoding="utf-8") as handle:

            for line in lines:
                handle.write(line.rstrip("\n") + "\n")

    except PermissionError:
        logger.error("Permission denied writing %s", path)
        raise


# =============================================
# JSONL RECORDS
# =============================================
#
# incidents.log and actions.log hold one JSON object per line.
# =============================================


def read_jsonl(path: Path) -> List[dict]:
    """
    Parse a JSONL file, skipping unparseable lines.

    A malformed line is logged rather than silently dropped. v1.0's
    bare ``except json.JSONDecodeError: continue`` meant a truncated
    write — an interrupted run, a full disk — vanished without trace.
    """

    records = []

    for number, line in enumerate(read_lines(path), start=1):

        try:
            records.append(json.loads(line))

        except json.JSONDecodeError:
            logger.warning(
                "Skipping malformed JSON at %s line %d", path.name, number
            )

    return records


def append_jsonl(path: Path, records: Iterable[dict]) -> int:
    """Append records as JSONL. Returns the number written."""

    lines = [json.dumps(record) for record in records]

    append_lines(path, lines)

    return len(lines)


# =============================================
# STATE FILES
# =============================================


class StateFile:
    """
    A set of fingerprints persisted one per line.

    Used for correlation state, incident state, and response state —
    three near-identical blocks of code in v1.0.

    Entries are held in memory and appended on ``flush()``, so a run
    that fails partway does not record work it did not complete.
    """

    def __init__(self, path: Path):
        self.path = path
        self._seen = set(read_lines(path))
        self._pending: List[str] = []

    def __contains__(self, fingerprint: str) -> bool:
        return fingerprint in self._seen

    def __len__(self) -> int:
        return len(self._seen)

    def add(self, fingerprint: str) -> None:
        """Mark a fingerprint as seen. Not written until flush()."""

        if fingerprint in self._seen:
            return

        self._seen.add(fingerprint)
        self._pending.append(fingerprint)

    def flush(self) -> int:
        """Append pending fingerprints to disk. Returns how many."""

        if not self._pending:
            return 0

        append_lines(self.path, self._pending)

        written = len(self._pending)
        self._pending = []

        logger.debug("Recorded %d new state entries in %s", written, self.path.name)

        return written


# =============================================
# ALERTS
# =============================================


def format_alert(message: str, timestamp: Optional[datetime] = None) -> str:
    """Render an alert line in the v1.0 on-disk format."""

    stamp = (timestamp or datetime.now()).strftime(TIMESTAMP_FORMAT)

    return f"{stamp} {ALERT_MARKER} {message}"


def append_alerts(
    path: Path, messages: Iterable[str], timestamp: Optional[datetime] = None
) -> int:
    """
    Append alert messages, all sharing one timestamp.

    A single timestamp per batch matches v1.0, where every alert from
    one analyzer run carried the same time.
    """

    messages = list(messages)

    if not messages:
        return 0

    stamp = timestamp or datetime.now()

    append_lines(path, [format_alert(message, stamp) for message in messages])

    logger.debug("Wrote %d alerts to %s", len(messages), path.name)

    return len(messages)


def read_alerts(path: Path) -> Iterator[Tuple[Optional[str], str]]:
    """
    Yield (timestamp, message) for each alert line.

    Lines without the ``[ALERT]`` marker are skipped. ``alert_summary.py``
    counted every non-empty line as an alert, so a blank line or a stray
    note in the file inflated its totals while the dashboard, which did
    filter, disagreed (defect D7).
    """

    for line in read_lines(path):

        if ALERT_MARKER not in line:
            logger.debug("Ignoring non-alert line in %s", path.name)
            continue

        yield patterns.split_alert_line(line)


def count_alerts(path: Path) -> int:
    """Number of alert lines in the alert log."""

    return sum(1 for _ in read_alerts(path))


# =============================================
# WATERMARKS
# =============================================
#
# A watermark is "the highest record ID collected so far", persisted
# per source so an incremental collector — homesoc.collect.windows, and
# any future one — can ask for only what's new since last time.
#
# Stored as a small JSON object keyed by source (a hostname, normally)
# rather than one value per file, so a second monitored endpoint later
# doesn't need a schema change — just a new key in the same file.
# =============================================


def _read_json_object(path: Path) -> dict:

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)

    except FileNotFoundError:
        return {}

    except (json.JSONDecodeError, OSError) as error:
        logger.warning("Could not read %s, treating as empty: %s", path, error)
        return {}

    return data if isinstance(data, dict) else {}


def read_watermark(path: Path, key: str) -> Optional[int]:
    """
    The stored watermark for *key* (normally a hostname), or None.

    None means "no prior watermark" — either this source has never
    been collected before, or the file is missing or unreadable. Both
    are treated identically: the caller should bootstrap rather than
    assume anything about what's already been seen.
    """

    value = _read_json_object(path).get(key)

    return value if isinstance(value, int) else None


def write_watermark(path: Path, key: str, record_id: int) -> None:
    """Persist the watermark for *key*, leaving any other keys intact."""

    data = _read_json_object(path)

    data[key] = int(record_id)

    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
