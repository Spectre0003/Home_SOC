#!/bin/bash
#
# Home SOC orchestrator.
#
# Kept as a thin wrapper so existing habits, cron entries, and the
# documented command in README.md keep working. Everything it used to do
# inline now lives in the homesoc package:
#
#     homesoc run              the whole pipeline
#     homesoc collect          one stage
#     homesoc --help           what is available
#
# Any arguments given here are passed through, so `run_soc.sh -v` works.

set -euo pipefail

if ! command -v homesoc > /dev/null 2>&1; then
    echo "[!] 'homesoc' not found on PATH."
    echo "[!] Activate the virtualenv, or run: pip install -e ."
    exit 2
fi

exec homesoc run "$@"
