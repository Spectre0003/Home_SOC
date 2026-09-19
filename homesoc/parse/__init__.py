"""
Log parsing and normalization.

Parsers here are pure functions: given raw text, they return Event
objects. No file I/O, no detection logic, no state. That separation is
the point of Stage 2 — homesoc.detect consumes Events, and never touches
a raw log line directly.
"""
