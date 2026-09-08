"""
Logging setup.

The v1.0 scripts printed everything to stdout — status, findings, and
errors alike — with no way to raise or lower the detail and no record of
what a run did once the terminal scrolled. That is workable while you sit
and watch each run, and useless once the pipeline is on a timer.

Named ``log`` rather than ``logging`` deliberately: a module named
``logging`` inside the package still imports the standard library
correctly under absolute imports, but it confuses readers and some
tooling for no benefit.

Two output streams:

    console  — what an analyst watching the run wants to see
    file     — everything, rotated, at ``config.run_log``

Console verbosity is set per run with --verbose / --quiet. The file
always records DEBUG, because the run you need the detail from is
always the one that already happened.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from typing import Optional


CONSOLE_FORMAT = "%(message)s"

FILE_FORMAT = "%(asctime)s %(levelname)-8s %(name)-28s %(message)s"

MAX_BYTES = 5 * 1024 * 1024

BACKUP_COUNT = 3


_configured = False


class _ConsoleFormatter(logging.Formatter):
    """
    Console output in the v1.0 prefix style.

    The original scripts marked lines with [+], [!], [*] and [OK], which
    is genuinely readable at a glance. Mapping log levels onto those
    prefixes keeps that while making severity machine-filterable.
    """

    PREFIXES = {
        logging.DEBUG: "[.]",
        logging.INFO: "[+]",
        logging.WARNING: "[!]",
        logging.ERROR: "[!]",
        logging.CRITICAL: "[!!]",
    }

    def format(self, record: logging.LogRecord) -> str:

        prefix = self.PREFIXES.get(record.levelno, "[+]")

        return f"{prefix} {record.getMessage()}"


def setup_logging(
    config=None,
    verbose: bool = False,
    quiet: bool = False,
    to_file: Optional[bool] = None,
) -> logging.Logger:
    """
    Configure logging for a pipeline run. Call once, at startup.

    *config* is a ``Config``; when omitted, only console logging is set
    up, which is what tests and one-off scripts want.

    --verbose and --quiet adjust the console only. The file handler
    always records DEBUG.
    """

    global _configured

    root = logging.getLogger("homesoc")

    # Reconfiguring would stack duplicate handlers and print every line
    # twice, which is a confusing failure to diagnose.

    if _configured:
        return root

    if verbose and quiet:
        raise ValueError("verbose and quiet are mutually exclusive")

    if verbose:
        console_level = logging.DEBUG

    elif quiet:
        console_level = logging.WARNING

    elif config is not None:
        console_level = getattr(
            logging, config.get("logging.level"), logging.INFO
        )

    else:
        console_level = logging.INFO

    root.setLevel(logging.DEBUG)
    root.propagate = False

    console = logging.StreamHandler(stream=sys.stdout)
    console.setLevel(console_level)
    console.setFormatter(_ConsoleFormatter(CONSOLE_FORMAT))
    root.addHandler(console)

    if config is not None:

        if to_file is None:
            to_file = config.get("logging.to_file")

        if to_file:

            try:
                config.ensure_directories()

                file_handler = RotatingFileHandler(
                    config.run_log,
                    maxBytes=MAX_BYTES,
                    backupCount=BACKUP_COUNT,
                    encoding="utf-8",
                )

                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(logging.Formatter(FILE_FORMAT))
                root.addHandler(file_handler)

            except (PermissionError, OSError) as error:

                # A run log that cannot be written is worth reporting,
                # but it is not a reason to abandon the run — detection
                # still works without it.

                root.warning(
                    "Could not open run log %s: %s", config.run_log, error
                )

    _configured = True

    return root


def get_logger(name: str) -> logging.Logger:
    """
    Logger for a module.

    Call as ``get_logger(__name__)``. Names are namespaced under
    "homesoc" so the whole pipeline can be filtered as one unit.
    """

    if name.startswith("homesoc"):
        return logging.getLogger(name)

    return logging.getLogger(f"homesoc.{name}")


def reset_logging() -> None:
    """
    Tear down handlers so setup_logging() can run again.

    Needed by tests, which configure logging per test case. Not used by
    the pipeline itself.
    """

    global _configured

    root = logging.getLogger("homesoc")

    for handler in list(root.handlers):
        handler.close()
        root.removeHandler(handler)

    _configured = False
