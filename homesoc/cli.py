"""
Command-line interface.

Replaces the nine standalone scripts and ``run_soc.sh`` with one entry
point:

    homesoc collect
    homesoc run --verbose
    homesoc config --check

Stages are registered in COMMANDS and imported lazily inside their
handler, so a stage that fails to import — a syntax error while you are
editing it, a missing dependency — breaks that command rather than the
whole CLI. During a refactor this matters: you want ``homesoc config``
to keep working while ``homesoc correlate`` is half-rewritten.

Exit codes:

    0  success
    1  the stage ran and reported a problem
    2  usage or configuration error
    130 interrupted
"""

from __future__ import annotations

import argparse
import os
import sys

from homesoc import __version__
from homesoc.common.config import Config, ConfigError
from homesoc.common.log import get_logger, setup_logging

logger = get_logger(__name__)


EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130


# =============================================
# COMMANDS
# =============================================


def cmd_config(config, args) -> int:
    """Show the resolved configuration."""

    print(f"Source: {config.source or 'built-in defaults'}")
    print(f"Version: {__version__}")

    if config.unknown_keys:

        print("\nUnrecognised keys (typos?):")

        for key in config.unknown_keys:
            print(f"  {key}")

    print("\nPaths:")
    print(f"  home                {config.home}")
    print(f"  logs                {config.log_dir}")
    print(f"  alerts              {config.alert_log}")
    print(f"  incidents           {config.incident_log}")
    print(f"  actions             {config.action_log}")
    print(f"  dashboard           {config.dashboard_file}")
    print(f"  run log             {config.run_log}")
    print(f"  linux auth log      {config.linux_auth_log}")

    print("\nDetection:")
    print(f"  correlation window  {config.correlation_window}")
    print(f"  min failures        {config.get('correlation.min_failures')}")
    print(
        f"  linux failed/ip     "
        f"{config.get('detection.linux.bruteforce_per_ip_threshold')}"
    )
    print(
        f"  windows failed/acct "
        f"{config.get('detection.windows.failed_per_account_threshold')}"
    )

    print("\nResponse:")
    print(f"  severities          {sorted(config.response_severities)}")
    print(f"  windows timezone    {config.windows_timezone}")

    if args.check:

        problems = []

        # The log directory is created by logging setup before this
        # runs, so checking that it exists proves nothing. Whether it
        # can actually be written to is the useful question.

        if not os.access(config.log_dir, os.W_OK):
            problems.append(f"log directory is not writable: {config.log_dir}")

        if not config.linux_auth_log.exists():
            problems.append(
                f"auth log not found: {config.linux_auth_log}"
            )

        elif not os.access(config.linux_auth_log, os.R_OK):
            problems.append(
                f"auth log is not readable: {config.linux_auth_log} "
                "(add your user to the 'adm' group, or use sudo)"
            )

        if config.unknown_keys:
            problems.append(
                f"{len(config.unknown_keys)} unrecognised config key(s)"
            )

        print()

        if problems:

            for problem in problems:
                logger.warning(problem)

            return EXIT_FAILED

        logger.info("Configuration checks passed")

    return EXIT_OK


def cmd_collect(config, args) -> int:
    """Collect logs from configured sources."""

    from homesoc.collect import linux

    collected = linux.collect(config)

    return EXIT_OK if collected else EXIT_FAILED


def cmd_analyze(config, args) -> int:
    """Analyze collected logs and raise alerts."""

    platform = getattr(args, "platform", "all")

    alerts = 0

    if platform in ("all", "linux"):

        from homesoc.detect import linux

        logger.info("--- Linux analysis ---")
        alerts += len(linux.analyze(config).alerts)

    if platform in ("all", "windows"):

        from homesoc.detect import windows

        logger.info("--- Windows analysis ---")
        alerts += len(windows.analyze(config).alerts)

    logger.info("Analysis complete: %d alert(s) raised", alerts)

    return EXIT_OK


def cmd_correlate(config, args) -> int:
    """Correlate authentication events across platforms."""

    from homesoc.detect import correlate

    result = correlate.correlate(config)

    logger.info(
        "Correlation complete: %d alert(s) raised", len(result.alerts)
    )

    return EXIT_OK


def cmd_run(config, args) -> int:
    """Run the full pipeline."""

    stages = [
        ("collect", cmd_collect),
        ("analyze", cmd_analyze),
        ("correlate", cmd_correlate),
    ]

    # Reporting, response, and dashboard stages join this list as they
    # are ported (Stage 1, pass 3c).

    failures = 0

    for name, handler in stages:

        logger.info("=== %s ===", name)

        if handler(config, args) != EXIT_OK:
            logger.warning("Stage '%s' reported a problem", name)
            failures += 1

    if failures:
        logger.warning("Pipeline finished with %d failed stage(s)", failures)
        return EXIT_FAILED

    logger.info("Pipeline complete")

    return EXIT_OK


COMMANDS = {
    "config": (cmd_config, "Show and check the resolved configuration"),
    "collect": (cmd_collect, "Collect logs from configured sources"),
    "analyze": (cmd_analyze, "Analyze collected logs and raise alerts"),
    "correlate": (cmd_correlate, "Correlate authentication events"),
    "run": (cmd_run, "Run the full pipeline"),
}


# =============================================
# PARSER
# =============================================


def build_parser() -> argparse.ArgumentParser:

    # Shared options are attached to both the top-level parser and every
    # subparser, so `homesoc -v collect` and `homesoc collect -v` both
    # work. Without this, argparse only accepts global flags before the
    # subcommand — which is the correct-but-surprising behaviour that
    # makes people think a flag is unsupported.
    #
    # SUPPRESS keeps unspecified options out of the namespace entirely,
    # so a subparser's default cannot overwrite a value given globally.

    common = argparse.ArgumentParser(add_help=False)

    common.add_argument(
        "-c",
        "--config",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help="Path to config.yaml (default: search standard locations)",
    )

    verbosity = common.add_mutually_exclusive_group()

    verbosity.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Show debug output",
    )

    verbosity.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Show warnings and errors only",
    )

    parser = argparse.ArgumentParser(
        prog="homesoc",
        parents=[common],
        description="Home SOC — log collection, detection, and reporting",
    )

    parser.add_argument(
        "--version", action="version", version=f"homesoc {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    for name, (_, help_text) in COMMANDS.items():

        subparser = subparsers.add_parser(
            name, parents=[common], help=help_text
        )

        if name == "config":
            subparser.add_argument(
                "--check",
                action="store_true",
                help="Verify that configured paths exist and are usable",
            )

        if name == "analyze":
            subparser.add_argument(
                "--platform",
                choices=("all", "linux", "windows"),
                default="all",
                help="Which platform's logs to analyze (default: all)",
            )

    return parser


# =============================================
# ENTRY POINT
# =============================================


def main(argv=None) -> int:

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    # SUPPRESS means these are absent unless the user gave them.

    config_path = getattr(args, "config", None)
    verbose = getattr(args, "verbose", False)
    quiet = getattr(args, "quiet", False)

    # The mutually-exclusive group is enforced within each parser, so
    # `homesoc -v collect -q` slips past it.

    if verbose and quiet:
        print(
            "[!] --verbose and --quiet cannot be used together",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        config = Config.load(config_path)

    except ConfigError as error:
        # Logging is not configured yet, so write directly.
        print(f"[!] Configuration error: {error}", file=sys.stderr)
        return EXIT_USAGE

    setup_logging(config, verbose=verbose, quiet=quiet)

    if config.unknown_keys and args.command != "config":

        for key in config.unknown_keys:
            logger.warning("Unrecognised config key: %s", key)

    handler, _ = COMMANDS[args.command]

    try:
        return handler(config, args)

    except KeyboardInterrupt:
        logger.warning("Interrupted")
        return EXIT_INTERRUPTED

    except PermissionError as error:
        logger.error("Permission denied: %s", error)
        return EXIT_FAILED

    except Exception:
        logger.exception("Unhandled error in '%s'", args.command)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
