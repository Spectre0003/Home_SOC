"""
Linux log collection.

Port of ``collect_linux_logs.sh``. Behaviour is unchanged: the auth log
is copied to a timestamped file and the journal is dumped alongside it.

Two things the shell version did not do, both of which cost a run's
worth of confusion when they happen:

  * ``cp`` failing on a permission error printed to stderr and the
    script carried on to report "Collection complete". Here a failed
    copy is an error and the caller is told the collection produced
    nothing.
  * ``journalctl`` not being present, or exiting non-zero, was invisible
    because its output was redirected into the target file regardless,
    leaving a zero-byte log that looked like a successful collection of
    an empty journal.

Known limitation, carried over deliberately: this copies the *entire*
auth log on every run, so a line already collected is collected again,
and the analyzers count it again (roadmap defect D1). Stage 2 fixes it
with content-addressed event IDs. Changing it here would alter detection
counts before there is anything in place to verify them against.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from homesoc.common.log import get_logger

logger = get_logger(__name__)


JOURNAL_TIMEOUT_SECONDS = 120


def timestamp_suffix(now: Optional[datetime] = None) -> str:
    """Filename suffix matching the v1.0 naming scheme."""

    return (now or datetime.now()).strftime("%Y-%m-%d_%H-%M-%S")


def collect_auth_log(config, suffix: str) -> Optional[Path]:
    """
    Copy the authentication log into the SOC log directory.

    Returns the destination path, or None if the copy failed.
    """

    source = config.linux_auth_log

    if not source.exists():
        logger.error("Authentication log not found: %s", source)
        logger.error(
            "On systems using journald only, there may be no auth.log at "
            "all — set collection.linux.auth_log in config.yaml."
        )
        return None

    destination = config.log_dir / f"auth_{suffix}.log"

    try:
        shutil.copy2(source, destination)

    except PermissionError:
        logger.error("Permission denied reading %s", source)
        logger.error(
            "auth.log is normally root:adm 0640 — add your user to the "
            "'adm' group, or run collection with sudo."
        )
        return None

    except OSError as error:
        logger.error("Could not copy %s: %s", source, error)
        return None

    size = destination.stat().st_size

    logger.info(
        "Collected auth log: %s (%s bytes)", destination.name, f"{size:,}"
    )

    if size == 0:
        logger.warning(
            "%s is empty — nothing will be detected from this collection",
            destination.name,
        )

    return destination


def collect_journal(config, suffix: str) -> Optional[Path]:
    """
    Dump the systemd journal into the SOC log directory.

    Note: nothing in the pipeline currently reads these files. They are
    collected because v1.0 collected them, and they are useful to have
    when investigating by hand — but they are the largest thing in the
    log directory and no detection depends on them. Disable with
    ``collection.linux.collect_journal: false`` if space matters.
    """

    destination = config.log_dir / f"journal_{suffix}.log"

    try:
        with open(destination, "w", encoding="utf-8") as handle:

            result = subprocess.run(
                ["journalctl", "--no-pager"],
                stdout=handle,
                stderr=subprocess.PIPE,
                timeout=JOURNAL_TIMEOUT_SECONDS,
                check=False,
            )

    except FileNotFoundError:
        logger.warning("journalctl not found — skipping journal collection")
        destination.unlink(missing_ok=True)
        return None

    except subprocess.TimeoutExpired:
        logger.warning(
            "journalctl timed out after %d seconds — skipping",
            JOURNAL_TIMEOUT_SECONDS,
        )
        destination.unlink(missing_ok=True)
        return None

    except PermissionError:
        logger.error("Permission denied writing %s", destination)
        return None

    if result.returncode != 0:

        message = result.stderr.decode("utf-8", errors="ignore").strip()

        logger.warning(
            "journalctl exited %d: %s", result.returncode, message or "no detail"
        )

        destination.unlink(missing_ok=True)
        return None

    size = destination.stat().st_size

    logger.info(
        "Collected journal: %s (%s bytes)", destination.name, f"{size:,}"
    )

    return destination


def collect(config) -> List[Path]:
    """
    Run Linux collection. Returns the files successfully collected.
    """

    config.ensure_directories()

    suffix = timestamp_suffix()

    logger.info("Collecting Linux logs into %s", config.log_dir)

    collected = []

    auth_log = collect_auth_log(config, suffix)

    if auth_log:
        collected.append(auth_log)

    if config.get("collection.linux.collect_journal"):

        journal = collect_journal(config, suffix)

        if journal:
            collected.append(journal)

    else:
        logger.debug("Journal collection disabled in config")

    if not collected:
        logger.error("Collection produced no files")

    else:
        logger.info("Collection complete: %d file(s)", len(collected))

    return collected
