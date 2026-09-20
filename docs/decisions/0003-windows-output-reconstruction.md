# 3. Delimiter-based reconstruction for Windows event output, not just a transport swap

Date: 2026-09-20
Status: Accepted — verified against the real Windows endpoint

## Context

The first working version of `homesoc/collect/windows.py` used `pywinrm`, joining
collected events with newlines and relying on "one event per line" as the wire
contract `homesoc.parse.windows` expects.

Against the real endpoint, a bootstrap pull of 500 events came back as 3022 lines,
of which roughly 2500 failed to parse as valid XML at all — not duplicated content,
corrupted content. The working hypothesis was that `pywinrm`'s `run_ps`, which
doesn't speak true PowerShell Remoting Protocol but instead base64-encodes the
script and captures output through the older WinRS raw-command-shell transport,
was splitting the large response across internal fragments and reassembling them
incorrectly.

## Decision (as first made, and revised)

The initial decision was to replace `pywinrm` with `pypsrp`, which implements true
PSRP — the protocol `Invoke-Command` itself uses, with message-level framing built
for bulk structured output. This was a reasonable diagnosis given the evidence at
the time, and it was wrong on its own.

**Swapping the library alone did not fix it.** A second live test, with `pypsrp` in
place, reproduced the exact same 3022-line corruption. Identical output corruption
across two structurally different transport implementations is strong evidence the
damage isn't happening at the transport layer at all — it's happening earlier, on
the Windows side, before either library ever sees the bytes.

The actual cause: PowerShell's default output formatter word-wraps long strings to
whatever console width a session reports — commonly around 80 columns, even in a
headless remote session with no real terminal attached. Every event's XML is
several hundred characters; the formatter was chopping each one into multiple
wrapped fragments before returning anything, regardless of which library received
it.

**The fix that actually worked**, kept alongside the `pypsrp` swap rather than
replacing it: join events with `[char]0x1E` (ASCII Record Separator) instead of a
newline, and reconstruct on the Python side by stripping every `\r`/`\n` the
formatter inserted — safe because the collector's own content never legitimately
contains one — then splitting on the delimiter instead. 0x1E was chosen because the
XML 1.0 `Char` production explicitly excludes it, so it is guaranteed, not merely
unlikely, never to collide with real event content.

## Consequences

The on-disk file format `homesoc.parse.windows` expects — one XML document per
line — is unchanged; reconstruction happens before the file is ever written, so
nothing downstream of collection needed to change for this fix.

The `pypsrp` swap was kept even though it wasn't sufficient alone, because it is
still the more correct choice on its own terms — real PSRP framing over WinRS
command-shell wrapping — and because reverting it back to `pywinrm` would have
meant re-introducing a documented, previously-observed failure mode for no reason.

Verified live against the real endpoint after both changes: the collected file's
line count matched its unique-`EventRecordID` count, and both landed at the
configured `max_events` cap — the corruption is gone, not merely reduced.

## Alternatives rejected

**Reduce `max_events` to stay under whatever size triggers the corruption.** Never
implemented. It would only have moved an unknown, unverified threshold rather than
removed it, and gives no confidence it wouldn't reappear at a different payload
size on a busier endpoint.

**Trust `pypsrp` alone.** Tested directly, live, and falsified — see above. Recorded
here specifically so the reasoning isn't lost: the first fix looked complete on
paper before it was tested against a real box, and wasn't.
