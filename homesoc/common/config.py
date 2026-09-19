"""
Configuration loading for Home SOC.

Every path, threshold, and timezone that was previously hardcoded in the
v1.0 scripts lives here. Nothing else in the codebase should contain an
absolute path or a magic number.

Resolution order (first match wins):

    1. an explicit path passed to Config.load()
    2. $HOMESOC_CONFIG
    3. ./config.yaml
    4. ~/.config/homesoc/config.yaml
    5. built-in defaults only

A user config is deep-merged over the defaults below, so a partial file
containing only the keys you want to change is valid.
"""

from __future__ import annotations

import copy
import os
from datetime import timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import yaml


# =============================================
# ERRORS
# =============================================


class ConfigError(Exception):
    """Raised when a config file is missing, malformed, or invalid."""


# =============================================
# DEFAULTS
# =============================================
#
# These reproduce the v1.0 behaviour exactly, so a run with no config
# file present behaves the way the original scripts did — except that
# the paths are now relative to the invoking user's home directory
# rather than to /home/socadmin.
# =============================================

DEFAULTS: dict = {
    "paths": {
        "home": "~/homesoc",
        "logs": "{home}/logs",
        "dashboard": "{home}/dashboard.html",
    },
    "collection": {
        "linux": {
            "auth_log": "/var/log/auth.log",
            "collect_journal": True,
        },
        "windows": {
            # Populated in Stage 2 pass 2e, which inverts collection to
            # a pull over WinRM (ADR 0002). Windows Event XML's own
            # TimeCreated is always UTC, so there is no timezone
            # setting here any more — Stage 1's config.windows.timezone
            # existed only because the old rendered-text collector gave
            # local time with no offset attached.
            "host": None,
            "username": None,
            # Never required to live here — HOMESOC_WINRM_PASSWORD is
            # checked first. This key exists purely as a documented
            # fallback for a lab where that's more convenient.
            "password": None,
            "winrm_port": 5985,
            "transport": "ntlm",
            "timeout_seconds": 30,
            "event_ids": [4624, 4625, 4672],
            "max_events": 500,
        },
    },
    "detection": {
        "linux": {
            "failed_login_threshold": 5,
            "bruteforce_per_ip_threshold": 5,
        },
        "windows": {
            "failed_login_threshold": 5,
            "failed_per_account_threshold": 3,
        },
    },
    "correlation": {
        "window_minutes": 5,
        "min_failures": 3,
    },
    "response": {
        "severities": ["CRITICAL"],
        "action_type": "block_ip",
    },
    "reporting": {
        "recent_limit": 10,
    },
    "logging": {
        "level": "INFO",
        "to_file": True,
        "filename": "homesoc.log",
    },
}


VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

# pywinrm's supported auth/transport names. "ntlm" is the practical
# default for a workgroup lab with no domain — Kerberos needs one,
# "basic" sends credentials with essentially no protection, and
# "credssp" needs CredSSP enabled on the endpoint for no benefit here.
VALID_WINRM_TRANSPORTS = {
    "plaintext", "ssl", "kerberos", "ntlm", "credssp", "basic", "certificate",
}


# =============================================
# HELPERS
# =============================================


_UNSET = object()


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into a copy of *base*."""

    result = copy.deepcopy(base)

    for key, value in override.items():

        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge(result[key], value)

        else:
            result[key] = value

    return result


def _collect_unknown_keys(
    defaults: dict, user: dict, prefix: str = ""
) -> list:
    """
    Return dotted key names present in *user* but not in *defaults*.

    Typos in a config file are otherwise silent — the value is loaded,
    nothing reads it, and the setting appears to have no effect.
    """

    unknown = []

    for key, value in user.items():

        dotted = f"{prefix}{key}"

        if key not in defaults:
            unknown.append(dotted)
            continue

        if isinstance(value, dict) and isinstance(defaults[key], dict):
            unknown.extend(
                _collect_unknown_keys(defaults[key], value, f"{dotted}.")
            )

    return unknown


def _default_search_paths() -> list:
    """Config locations tried in order when no path is given."""

    paths = []

    env_path = os.environ.get("HOMESOC_CONFIG")

    if env_path:
        paths.append(Path(env_path))

    paths.append(Path.cwd() / "config.yaml")
    paths.append(Path.home() / ".config" / "homesoc" / "config.yaml")

    return paths


# =============================================
# CONFIG
# =============================================


class Config:
    """
    Loaded, validated Home SOC configuration.

    Access nested values with dotted keys:

        config.get("detection.linux.failed_login_threshold")

    Paths and typed values are exposed as properties, so callers never
    build paths by string concatenation.
    """

    # Filenames are derived from the log directory rather than being
    # configurable individually — one directory to point at, not nine.

    ALERT_LOG = "alerts.log"
    INCIDENT_LOG = "incidents.log"
    ACTION_LOG = "actions.log"
    CORRELATION_STATE = "correlation_state.txt"
    INCIDENT_STATE = "incident_state.txt"
    RESPONSE_STATE = "response_state.txt"
    WINDOWS_WATERMARK = "windows_watermark.json"

    def __init__(
        self,
        data: dict,
        source: Optional[Path] = None,
        unknown_keys: Optional[list] = None,
    ):
        self._data = data
        self.source = source
        self.unknown_keys = unknown_keys or []

        self._paths = self._resolve_paths(data["paths"])

        self._validate()

    # -----------------------------------------
    # Loading
    # -----------------------------------------

    @classmethod
    def load(cls, path=None) -> "Config":
        """
        Load configuration from *path*, or from the default search
        locations. Falls back to built-in defaults if nothing is found.
        """

        candidates = (
            [Path(path)] if path is not None else _default_search_paths()
        )

        for candidate in candidates:

            candidate = candidate.expanduser()

            if not candidate.is_file():
                continue

            try:
                with open(candidate, "r", encoding="utf-8") as handle:
                    user_data = yaml.safe_load(handle) or {}

            except yaml.YAMLError as exc:
                raise ConfigError(
                    f"Could not parse {candidate}: {exc}"
                ) from exc

            except PermissionError as exc:
                raise ConfigError(
                    f"Permission denied reading {candidate}"
                ) from exc

            if not isinstance(user_data, dict):
                raise ConfigError(
                    f"{candidate} must contain a YAML mapping at the top level"
                )

            return cls(
                data=_deep_merge(DEFAULTS, user_data),
                source=candidate,
                unknown_keys=_collect_unknown_keys(DEFAULTS, user_data),
            )

        # An explicit path that does not exist is an error; falling back
        # to defaults silently would hide a typo in --config.

        if path is not None:
            raise ConfigError(f"Config file not found: {path}")

        return cls(data=copy.deepcopy(DEFAULTS), source=None)

    # -----------------------------------------
    # Path resolution
    # -----------------------------------------

    @staticmethod
    def _resolve_paths(raw: dict) -> dict:
        """
        Expand ~ and the {home} / {logs} tokens, and make every path
        absolute. Tokens are substituted iteratively so that entries may
        reference each other in any order.
        """

        resolved = {}

        for key, value in raw.items():

            if not isinstance(value, str):
                raise ConfigError(f"paths.{key} must be a string")

            resolved[key] = value

        for _ in range(5):

            changed = False

            for key, value in resolved.items():

                if "{" not in value:
                    continue

                new_value = value.format(**resolved)

                if new_value != value:
                    resolved[key] = new_value
                    changed = True

            if not changed:
                break

        else:
            raise ConfigError(
                "Circular reference in paths: could not resolve "
                "{...} tokens after 5 passes"
            )

        return {
            key: Path(value).expanduser().resolve()
            for key, value in resolved.items()
        }

    # -----------------------------------------
    # Validation
    # -----------------------------------------

    def _validate(self) -> None:

        positive_ints = [
            "detection.linux.failed_login_threshold",
            "detection.linux.bruteforce_per_ip_threshold",
            "detection.windows.failed_login_threshold",
            "detection.windows.failed_per_account_threshold",
            "correlation.window_minutes",
            "correlation.min_failures",
            "collection.windows.max_events",
            "collection.windows.winrm_port",
            "collection.windows.timeout_seconds",
            "reporting.recent_limit",
        ]

        for key in positive_ints:

            value = self.get(key)

            if not isinstance(value, int) or isinstance(value, bool):
                raise ConfigError(f"{key} must be an integer, got {value!r}")

            if value < 1:
                raise ConfigError(f"{key} must be at least 1, got {value}")

        severities = self.get("response.severities")

        if not isinstance(severities, list) or not severities:
            raise ConfigError(
                "response.severities must be a non-empty list"
            )

        for severity in severities:

            if severity not in VALID_SEVERITIES:
                raise ConfigError(
                    f"Unknown severity {severity!r} in response.severities. "
                    f"Valid values: {', '.join(sorted(VALID_SEVERITIES))}"
                )

        winrm_port = self.get("collection.windows.winrm_port")

        if not (1 <= winrm_port <= 65535):
            raise ConfigError(
                f"collection.windows.winrm_port must be a valid port "
                f"(1-65535), got {winrm_port}"
            )

        transport = self.get("collection.windows.transport")

        if transport not in VALID_WINRM_TRANSPORTS:
            raise ConfigError(
                f"Unknown collection.windows.transport {transport!r}. "
                f"Valid values: {', '.join(sorted(VALID_WINRM_TRANSPORTS))}"
            )

        level = self.get("logging.level")

        if level not in VALID_LOG_LEVELS:
            raise ConfigError(
                f"Unknown logging.level {level!r}. "
                f"Valid values: {', '.join(sorted(VALID_LOG_LEVELS))}"
            )

        event_ids = self.get("collection.windows.event_ids")

        if not isinstance(event_ids, list) or not event_ids:
            raise ConfigError(
                "collection.windows.event_ids must be a non-empty list"
            )

        for event_id in event_ids:

            if not isinstance(event_id, int) or isinstance(event_id, bool):
                raise ConfigError(
                    f"collection.windows.event_ids entries must be integers, "
                    f"got {event_id!r}"
                )

    # -----------------------------------------
    # Generic access
    # -----------------------------------------

    def get(self, dotted_key: str, default: Any = _UNSET) -> Any:
        """Look up a nested value by dotted key."""

        node: Any = self._data

        for part in dotted_key.split("."):

            if not isinstance(node, dict) or part not in node:

                if default is _UNSET:
                    raise ConfigError(f"Unknown config key: {dotted_key}")

                return default

            node = node[part]

        return node

    def as_dict(self) -> dict:
        """A deep copy of the merged configuration."""

        return copy.deepcopy(self._data)

    # -----------------------------------------
    # Paths
    # -----------------------------------------

    @property
    def home(self) -> Path:
        return self._paths["home"]

    @property
    def log_dir(self) -> Path:
        return self._paths["logs"]

    @property
    def dashboard_file(self) -> Path:
        return self._paths["dashboard"]

    @property
    def alert_log(self) -> Path:
        return self.log_dir / self.ALERT_LOG

    @property
    def incident_log(self) -> Path:
        return self.log_dir / self.INCIDENT_LOG

    @property
    def action_log(self) -> Path:
        return self.log_dir / self.ACTION_LOG

    @property
    def correlation_state(self) -> Path:
        return self.log_dir / self.CORRELATION_STATE

    @property
    def incident_state(self) -> Path:
        return self.log_dir / self.INCIDENT_STATE

    @property
    def response_state(self) -> Path:
        return self.log_dir / self.RESPONSE_STATE

    @property
    def windows_watermark_state(self) -> Path:
        return self.log_dir / self.WINDOWS_WATERMARK

    @property
    def run_log(self) -> Path:
        return self.log_dir / self.get("logging.filename")

    @property
    def linux_auth_log(self) -> Path:
        return Path(
            self.get("collection.linux.auth_log")
        ).expanduser()

    @property
    def windows_host(self) -> Optional[str]:
        return self.get("collection.windows.host")

    @property
    def windows_winrm_password(self) -> Optional[str]:
        """
        The WinRM password, preferring the environment over the file.

        HOMESOC_WINRM_PASSWORD is checked first, so the password never
        has to live on disk as part of this project's own files at all
        — config.yaml being gitignored is not the same guarantee as it
        never touching disk. collection.windows.password exists purely
        as a documented fallback for a lab where that trade-off is
        acceptable.
        """

        env_value = os.environ.get("HOMESOC_WINRM_PASSWORD")

        if env_value:
            return env_value

        return self.get("collection.windows.password")

    def ensure_directories(self) -> None:
        """Create the directories the pipeline writes into."""

        self.log_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------
    # Typed values
    # -----------------------------------------

    @property
    def correlation_window(self) -> timedelta:
        return timedelta(minutes=self.get("correlation.window_minutes"))

    @property
    def response_severities(self) -> set:
        return set(self.get("response.severities"))

    def __repr__(self) -> str:
        origin = self.source or "built-in defaults"
        return f"<Config source={origin} home={self.home}>"


# =============================================
# MANUAL CHECK
# =============================================
#
#   python3 -m homesoc.common.config
#
# Prints the resolved configuration so you can confirm what the
# pipeline will actually use before any of it runs.
# =============================================


if __name__ == "__main__":

    import json
    import sys

    try:
        config = Config.load()

    except ConfigError as error:
        print(f"[!] {error}")
        sys.exit(1)

    print(f"[+] Source: {config.source or 'built-in defaults'}")

    if config.unknown_keys:
        print("[!] Unrecognised keys (typos?):")
        for key in config.unknown_keys:
            print(f"    {key}")

    print("\n[+] Resolved paths:")
    print(f"    home:              {config.home}")
    print(f"    logs:              {config.log_dir}")
    print(f"    alerts:            {config.alert_log}")
    print(f"    incidents:         {config.incident_log}")
    print(f"    actions:           {config.action_log}")
    print(f"    dashboard:         {config.dashboard_file}")
    print(f"    run log:           {config.run_log}")
    print(f"    linux auth log:    {config.linux_auth_log}")

    print("\n[+] Typed values:")
    print(f"    correlation window: {config.correlation_window}")
    print(f"    response severities:{sorted(config.response_severities)}")

    print("\n[+] Merged configuration:")
    print(json.dumps(config.as_dict(), indent=2, default=str))
