"""
Log discovery and cross-file deduplication.

``AuthEvent``, the lightweight stopgap record this module carried
through Stage 1, is retired here. It existed only because the real
event schema (``homesoc.parse.event.Event``) didn't exist yet — that
was flagged when it was written. Every detector now consumes ``Event``
directly, so the stopgap has nothing left to do.

What remains is genuinely still needed by every detector: finding the
right log files, reading them tolerantly, and — new in this pass —
collapsing the duplication that collection creates.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from homesoc.common.log import get_logger

logger = get_logger(__name__)


def find_linux_logs(config) -> List[Path]:
    """
    Every collected Linux auth log, oldest first.

    Matches only this pipeline's own naming convention
    (``auth_YYYY-MM-DD_HH-MM-SS.log``) rather than a bare ``auth_*.log``
    wildcard, so an unrelated file that happens to start with ``auth_``
    can't get pulled into detection. Order doesn't affect correctness
    here — ``gather_linux_text`` unions every file's lines regardless
    of which is read first — but a precise pattern costs nothing and
    closes off the same class of surprise that hit the Windows side
    below.
    """

    logs = sorted(
        config.log_dir.glob(
            "auth_[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]_"
            "[0-9][0-9]-[0-9][0-9]-[0-9][0-9].log"
        )
    )

    if not logs:
        logger.warning("No Linux auth logs found in %s", config.log_dir)

    return logs


def find_latest_windows_log(config) -> Optional[Path]:
    """
    The most recently collected Windows log.

    Two things matter here, both learned from a real directory rather
    than guessed at. First, the glob matches only this pipeline's exact
    naming convention (``windows_YYYY-MM-DD_HH-MM-SS.log``), not a bare
    ``windows_*.log`` wildcard — a log directory that ever held output
    from the old v1.0 push-based collector, which used a
    ``windows_security_*.log`` prefix, would otherwise have those
    unrelated leftover files considered at all. Second, "latest" is
    decided by file modification time, not filename string order —
    even with the precise glob, sorting by name alone is only correct
    because this pipeline's own timestamp format happens to be
    zero-padded; mtime doesn't depend on that holding.

    Only the newest file is analyzed, matching v1.0. Older Windows logs
    are never reprocessed once a newer one exists. This is a separate
    problem from the one this module's deduplication solves below —
    it's about collection pulling an overlapping *range* of events
    across runs (roadmap defect D10), fixed in pass 2e once the
    collector itself became incremental, not about multiple files on
    disk.
    """

    logs = list(
        config.log_dir.glob(
            "windows_[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]_"
            "[0-9][0-9]-[0-9][0-9]-[0-9][0-9].log"
        )
    )

    if not logs:
        logger.info("No Windows security logs found in %s", config.log_dir)
        return None

    logs.sort(key=lambda path: path.stat().st_mtime)

    if len(logs) > 1:
        logger.debug(
            "%d Windows logs present; analyzing only the newest (%s)",
            len(logs),
            logs[-1].name,
        )

    return logs[-1]


def read_text(path: Path) -> str:
    """Read a log file, tolerating undecodable bytes."""

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()

    except PermissionError:
        logger.error("Permission denied: %s", path)
        return ""

    except OSError as error:
        logger.error("Could not read %s: %s", path, error)
        return ""


def gather_linux_text(config) -> str:
    """
    Combined, line-deduplicated text of every currently collected Linux
    auth log.

    Collection copies the whole auth.log on every run, and nothing
    rotates old copies away yet (there is no retention policy — that's
    Stage 3). Every retained ``auth_*.log`` therefore overlaps heavily
    with every other one: a single real failed login can exist,
    identically, in a dozen files.

    This is the actual fix for roadmap defect D1. It works on exact
    line content, not event IDs — there's no need to parse a line
    before knowing whether it's a duplicate, and an identical line
    means an identical event by construction (the same content-address
    hashing ``Event`` uses). Deduplicating here, once, before anything
    downstream counts or parses a single thing, means the fix applies
    uniformly to Event-based counts and to the informational raw-line
    counts (sudo command execution) alike.

    Order is preserved for whichever copy a line is first seen in,
    which does not have to be chronological — collection files are
    processed oldest-collected first, but a line's position within one
    file still reflects when auth.log itself wrote it.
    """

    seen = set()

    lines: List[str] = []

    total_read = 0

    for logfile in find_linux_logs(config):

        for line in read_text(logfile).splitlines():

            stripped = line.strip()

            if not stripped:
                continue

            total_read += 1

            if stripped in seen:
                continue

            seen.add(stripped)
            lines.append(stripped)

    if total_read:
        logger.debug(
            "%d line(s) read across all collected auth logs, "
            "%d unique after deduplication",
            total_read,
            len(lines),
        )

    return "\n".join(lines)
