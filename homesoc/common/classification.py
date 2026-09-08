"""
Alert classification.

In v1.0, three files each carried their own copy of ``get_severity()``:
``alert_summary.py``, ``generate_incidents.py``, and
``generate_dashboard.py``. They agreed by coincidence rather than by
construction — the dashboard's version had no explicit MEDIUM branches
and relied on the fallthrough, so changing a severity in one place would
have silently disagreed with the other two.

Severity, detection reason, and platform are all derived from the same
substring match against the alert message, so they belong in one table
with one lookup rather than three parallel if-chains.

This module deliberately reproduces v1.0 classification exactly,
including its known gaps (see WINDOWS SEVERITY GAP below). Severity moves
into per-rule metadata at Stage 4; until then, behaviour is preserved so
that the refactor can be verified against existing alert data.
"""

from __future__ import annotations

from enum import IntEnum
from typing import NamedTuple, Optional


# =============================================
# SEVERITY
# =============================================


class Severity(IntEnum):
    """
    Ordered severity levels.

    Integer values allow direct comparison (``severity >=
    Severity.HIGH``) while ``.name`` gives the string form used in logs,
    incident records, and the dashboard.

    Values are spaced by ten so intermediate levels can be added later
    without renumbering anything already written to disk.
    """

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    def __str__(self) -> str:
        return self.name

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        """Parse a severity name, case-insensitively."""

        try:
            return cls[name.strip().upper()]

        except KeyError as exc:
            valid = ", ".join(level.name for level in cls)
            raise ValueError(
                f"Unknown severity {name!r}. Valid values: {valid}"
            ) from exc


# The severity assigned to any alert that matches no known signature.
# v1.0 used MEDIUM as its fallthrough in all three implementations.

DEFAULT_SEVERITY = Severity.MEDIUM

DEFAULT_REASON = "Unclassified alert"

DEFAULT_PLATFORM = "Linux"


# =============================================
# SIGNATURES
# =============================================


class Signature(NamedTuple):
    """One alert-message signature and everything derived from it."""

    match: str
    severity: Severity
    reason: str
    platform: str


# Order matters: the first signature whose ``match`` appears in the alert
# message wins. Windows-specific entries must precede their generic
# counterparts — "Multiple Windows failed login attempts detected"
# contains neither more nor less than the generic Linux wording, but
# keeping the specific ones first makes the precedence explicit rather
# than incidental.

SIGNATURES = (
    Signature(
        match="Authentication attack pattern detected",
        severity=Severity.CRITICAL,
        reason=(
            "Correlated authentication attack pattern "
            "(failed logins + successful login)"
        ),
        platform="Correlated",
    ),
    Signature(
        match="Brute-force activity detected",
        severity=Severity.HIGH,
        reason="Brute-force login activity from a single source IP",
        platform="Linux",
    ),
    Signature(
        match="Multiple Windows failed login attempts detected",
        severity=Severity.MEDIUM,
        reason="Multiple failed Windows login attempts",
        platform="Windows",
    ),
    Signature(
        match="Repeated failed Windows logins detected",
        severity=Severity.MEDIUM,
        reason="Repeated failed Windows logins against a single account",
        platform="Windows",
    ),
    Signature(
        match="Multiple failed login attempts detected",
        severity=Severity.MEDIUM,
        reason="Multiple failed Linux login attempts",
        platform="Linux",
    ),
    Signature(
        match="Sudo authentication failure detected",
        severity=Severity.MEDIUM,
        reason="Sudo authentication failure",
        platform="Linux",
    ),
)


# =============================================
# WINDOWS SEVERITY GAP
# =============================================
#
# Both Windows signatures classify as MEDIUM, because v1.0 had no
# Windows branches in get_severity() and they fell through to the
# default. A repeated-failure detection against a single Windows account
# is arguably the same finding as "Brute-force activity detected" on
# Linux, which is rated HIGH.
#
# This is left as-is deliberately. Changing it here would alter the
# severity of alerts already written to incidents.log and make the
# refactor impossible to verify against existing data. Stage 4 moves
# severity into each rule's YAML, which is the right place to correct it.
# =============================================


# =============================================
# LOOKUP
# =============================================


def find_signature(message: str) -> Optional[Signature]:
    """Return the first signature matching *message*, or None."""

    if not message:
        return None

    for signature in SIGNATURES:

        if signature.match in message:
            return signature

    return None


def classify(message: str) -> Severity:
    """
    Severity of an alert message.

    Replaces the three copies of ``get_severity()`` from v1.0.
    """

    signature = find_signature(message)

    return signature.severity if signature else DEFAULT_SEVERITY


def detection_reason(message: str) -> str:
    """
    Analyst-readable explanation of why an alert fired.

    Replaces ``get_detection_reason()`` from ``generate_incidents.py``.
    """

    signature = find_signature(message)

    return signature.reason if signature else DEFAULT_REASON


def platform(message: str) -> str:
    """
    Originating platform of an alert.

    Replaces ``get_platform()`` from ``generate_incidents.py``. The v1.0
    version tested for the literal substring "Windows" anywhere in the
    message, which would have misfired on any future alert mentioning a
    Windows account or hostname in passing. Matching against explicit
    signatures avoids that.
    """

    signature = find_signature(message)

    return signature.platform if signature else DEFAULT_PLATFORM


def classify_all(message: str) -> Signature:
    """
    Severity, reason, and platform in one call.

    Callers building an incident record need all three; this avoids
    walking the signature table three times.
    """

    signature = find_signature(message)

    if signature is None:

        return Signature(
            match="",
            severity=DEFAULT_SEVERITY,
            reason=DEFAULT_REASON,
            platform=DEFAULT_PLATFORM,
        )

    return signature
