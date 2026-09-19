"""
Windows Security event parsing.

Parses structured Windows Event XML into normalized :class:`Event`
objects, reading named ``EventData`` fields — ``TargetUserName``,
``IpAddress``, ``LogonType``, ``Status``, ``SubStatus`` — rather than
the rendered English message text v1.0 parsed.

That is the actual fix for the account-anchoring fragility (roadmap
defect D12), not a better-anchored version of the old approach. v1.0's
bug was taking the first "Account Name:" line in rendered prose, when
an event's message contains several under different headings
("Subject:", "New Logon:", "Account For Which Logon Failed:"). The fix
shipped in Stage 1 anchored to the right heading per event ID —
``windows_account(event_text, event_id)`` in ``common/patterns.py``.
That anchoring function does not exist here at all: ``TargetUserName``
means the same specific thing on both a 4624 and a 4625, so there is
nothing to anchor to and no event-ID branch needed to get the right
field. The bug's entire class — a rendering that can put the meaningful
line in a different place depending on event type or locale — is gone
because there is no rendering to parse.

Input contract: one Windows Event XML document per line — the format
``$event.ToXml()`` produces natively, since it returns a compact,
single-line string with no embedded newlines. Stage 2 pass 2e rewrites
the PowerShell collector to emit exactly this; this parser is written
against the XML schema itself, so it does not depend on that rewrite
landing first.

As with the Linux parser, one event type is deliberately left out of
the Event stream. 4672 (special privileges assigned) is not a logon
attempt — it has no TargetUserName, no LogonType, no outcome in any
sense this schema models. v1.0 only ever used it as an informational
count; :func:`count_privileged_logons` preserves that without stretching
the schema to fit something that isn't an authentication outcome.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

from homesoc.common.log import get_logger
from homesoc.parse.event import (
    ACTION_WINDOWS_LOGON,
    CATEGORY_AUTHENTICATION,
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    PLATFORM_WINDOWS,
    Event,
)

logger = get_logger(__name__)


EVENT_SUCCESSFUL_LOGON = "4624"
EVENT_FAILED_LOGON = "4625"
EVENT_SPECIAL_PRIVILEGES = "4672"

# Only these produce an Event. See the module docstring for why 4672
# does not.
_LOGON_EVENT_IDS = {EVENT_SUCCESSFUL_LOGON, EVENT_FAILED_LOGON}

_OUTCOME_BY_EVENT_ID = {
    EVENT_SUCCESSFUL_LOGON: OUTCOME_SUCCESS,
    EVENT_FAILED_LOGON: OUTCOME_FAILURE,
}

# A cheap, no-DOM way to find an event's ID for lines this parser will
# skip anyway — used only by count_privileged_logons, which has no
# reason to build a full element tree just to count occurrences.
_EVENT_ID_TAG = re.compile(r"<EventID>(\d+)</EventID>")


# =============================================
# XML HELPERS
# =============================================


def _local_name(tag: str) -> str:
    """
    Strip the namespace URI ElementTree prefixes onto every tag.

    Windows Event XML declares one default namespace on the root
    element; ElementTree represents every tag as
    ``{namespace-uri}TagName``, and matching against the bare name is
    simpler than carrying the namespace map through every lookup below.
    """

    return tag.rsplit("}", 1)[-1]


def _find_child(parent: ET.Element, name: str) -> Optional[ET.Element]:

    for child in parent:

        if _local_name(child.tag) == name:
            return child

    return None


def _event_data_fields(root: ET.Element) -> Dict[str, str]:
    """
    Every ``<Data Name="...">value</Data>`` entry under ``<EventData>``.

    A ``<Data>`` element with no ``Name`` attribute exists for a small
    number of event types and is skipped rather than raising.
    """

    event_data = _find_child(root, "EventData")

    if event_data is None:
        return {}

    fields = {}

    for elem in event_data:

        if _local_name(elem.tag) != "Data":
            continue

        name = elem.get("Name")

        if name:
            fields[name] = (elem.text or "").strip()

    return fields


def _parse_system_time(raw: str) -> Optional[datetime]:
    """
    Parse a ``TimeCreated SystemTime`` attribute.

    Always UTC, always ``Z``-suffixed, and carries up to seven
    fractional digits (100-nanosecond ticks) — more precision than
    ``datetime.fromisoformat`` accepts on Python versions before 3.11.
    Truncated to microseconds explicitly rather than depending on the
    interpreter version this happens to run on.
    """

    if not raw:
        return None

    value = raw.rstrip("Z")

    if "." in value:

        whole, _, frac = value.partition(".")
        value = f"{whole}.{frac[:6]}"

    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)

    except ValueError:
        return None


def _clean(value: Optional[str]) -> Optional[str]:
    """Treat Windows's own empty-value marker as no value."""

    if value is None:
        return None

    value = value.strip()

    return value if value and value != "-" else None


def _as_int(value: Optional[str]) -> Optional[int]:

    if value is None:
        return None

    try:
        return int(value)

    except ValueError:
        return None


# =============================================
# PARSING
# =============================================


def parse_event_xml(xml_line: str) -> Optional[Event]:
    """
    Parse one Windows Event XML document into an Event.

    Returns None for a line that is not well-formed XML, has no
    ``<System>`` section, or carries an event ID this pipeline does not
    act on (anything other than 4624 or 4625 — see
    :func:`count_privileged_logons` for 4672).
    """

    xml_line = xml_line.strip()

    if not xml_line:
        return None

    try:
        root = ET.fromstring(xml_line)

    except ET.ParseError as error:
        logger.debug("Not parseable as event XML, skipping: %s", error)
        return None

    system = _find_child(root, "System")

    if system is None:
        logger.debug("Event XML has no <System> section, skipping")
        return None

    event_id_elem = _find_child(system, "EventID")

    event_id = (event_id_elem.text or "").strip() if event_id_elem is not None else None

    if event_id not in _LOGON_EVENT_IDS:
        return None

    time_created = _find_child(system, "TimeCreated")

    timestamp = (
        _parse_system_time(time_created.get("SystemTime"))
        if time_created is not None
        else None
    )

    if timestamp is None:

        logger.warning(
            "Event %s has no parseable TimeCreated, skipping", event_id
        )
        return None

    computer_elem = _find_child(system, "Computer")

    host = _clean(computer_elem.text if computer_elem is not None else None)

    fields = _event_data_fields(root)

    return Event.create(
        timestamp=timestamp,
        platform=PLATFORM_WINDOWS,
        category=CATEGORY_AUTHENTICATION,
        action=ACTION_WINDOWS_LOGON,
        outcome=_OUTCOME_BY_EVENT_ID[event_id],
        raw=xml_line,
        user=_clean(fields.get("TargetUserName")),
        source_ip=_clean(fields.get("IpAddress")),
        host=host,
        logon_type=_as_int(fields.get("LogonType")),
        status=_clean(fields.get("Status")),
        sub_status=_clean(fields.get("SubStatus")),
    )


def parse_windows_security(text: str) -> List[Event]:
    """
    Parse a collected Windows Security log into a list of Events.

    Expects one Windows Event XML document per line. Lines that do not
    parse, or that carry an event ID outside 4624/4625, are silently
    dropped from the returned list — call :func:`count_privileged_logons`
    separately for the 4672 count.
    """

    if not text:
        return []

    events: List[Event] = []

    for line in text.splitlines():

        event = parse_event_xml(line)

        if event is not None:
            events.append(event)

    return events


def count_privileged_logons(text: str) -> int:
    """
    Number of 4672 (special privileges assigned) events in *text*.

    Not modelled as an Event — see the module docstring. A regex count
    rather than a full parse, since nothing here needs more than the
    event ID for a purely informational number.
    """

    if not text:
        return 0

    return sum(
        1
        for line in text.splitlines()
        if (match := _EVENT_ID_TAG.search(line))
        and match.group(1) == EVENT_SPECIAL_PRIVILEGES
    )
