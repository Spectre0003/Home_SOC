"""
Authentication events and log discovery.

A small shared record for the correlation stage, plus the log-file
selection logic that ``analyze_windows_logs.py`` and
``correlate_events.py`` each implemented separately.

This is *not* the normalized event schema from Stage 2. It carries only
the four fields v1.0's correlation actually used. Building the full ECS
record here would mean designing it before the parser layer that
produces it, and rewriting both.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List, NamedTuple, Optional

from homesoc.common.log import get_logger

logger = get_logger(__name__)


# v1.0 used the string "unknown" for absent IPs and accounts, and the
# correlation matching, fingerprinting, and alert text all depend on
# that exact value. Keeping it means correlation state written by v1.0
# still matches after the refactor. Stage 3 moves to real nulls in the
# database, where a missing value and a value of "unknown" are properly
# distinguishable.

UNKNOWN = "unknown"


class AuthEvent(NamedTuple):
    """One authentication event, successful or failed."""

    timestamp: datetime
    source_ip: str
    account: str
    platform: str
    outcome: str

    @property
    def known_ip(self) -> bool:
        return self.source_ip != UNKNOWN

    @property
    def known_account(self) -> bool:
        return self.account != UNKNOWN


def normalize(value: Optional[str]) -> str:
    """Map a missing value onto the v1.0 sentinel."""

    if value is None:
        return UNKNOWN

    value = value.strip()

    return value if value and value != "-" else UNKNOWN


def find_linux_logs(config) -> List[Path]:
    """
    Every collected Linux auth log, oldest first.

    Note: because collection copies the whole auth.log each run, these
    files overlap heavily, and an event present in five of them is
    counted five times (roadmap defect D1). Preserved from v1.0 so that
    detection counts stay comparable until Stage 2 introduces
    content-addressed event IDs.
    """

    logs = sorted(config.log_dir.glob("auth_*.log"))

    if not logs:
        logger.warning("No Linux auth logs found in %s", config.log_dir)

    return logs


def find_latest_windows_log(config) -> Optional[Path]:
    """
    The most recently collected Windows log.

    Only the newest file is analyzed, matching v1.0. Older Windows logs
    are never reprocessed once a newer one exists, so events collected
    but not yet analyzed are lost if two collections happen between two
    analysis runs. Fixed in Stage 8 when collection becomes incremental.
    """

    logs = sorted(config.log_dir.glob("windows_*.log"))

    if not logs:
        logger.info("No Windows security logs found in %s", config.log_dir)
        return None

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
