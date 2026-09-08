# 2. Pull-based Windows collection

Date: 2026-09-08
Status: Accepted — implemented in Stage 2

## Context

v1.0 collects Windows Security events with a PowerShell script run by hand on
the endpoint, which `scp`s the result to the SOC server. This means:

- The monitored endpoint holds an SSH key with shell-capable access to the
  monitoring host (D13).
- Collection state — what has already been sent — lives on the endpoint, or
  nowhere. The script pulls the latest 500 events regardless, so consecutive
  collections overlap (D10).
- Every endpoint needs its own scheduling.

## Decision

Invert the direction. The SOC server initiates collection. The endpoint holds no
credential for the SOC and stores no collection state.

Transport is either WinRM (agentless, no script on the endpoint) or OpenSSH
Server on Windows with a key-based pull. Either way the credential lives on the
SOC side, against a dedicated account in **Event Log Readers**, not an
administrator.

The `EventRecordID` watermark is persisted on the SOC server and passed as an
XPath filter, so each collection returns only new events.

## Consequences

The endpoint becomes stateless: nothing to schedule, nothing to configure, no
credential to protect. Collection state has one home, which is also where it
needs to be once it moves into the database in Stage 3.

Collection failures become visible. A push that stops arriving is
indistinguishable from an endpoint with nothing to report; a pull that fails is
an error the SOC can raise.

**This is not unconditionally safer.** Pull gives the SOC server an
authenticated path *into* the host it monitors, so compromising the monitoring
host now reaches the monitored one. Many production deployments prefer push for
exactly this reason. The decision rests on the architectural argument —
stateless endpoint, single watermark, no per-host scheduling — not on a claim
that pull is more secure.

## Alternatives considered

**Keep the push, restrict the key.** A forced command in the endpoint's
`authorized_keys` (`command="internal-sftp",restricted,no-pty`) against an
unprivileged SOC account with a chrooted, append-only drop directory. This
solves D13 completely and preserves the safer trust direction: a compromised
endpoint can deliver a file and nothing else.

Rejected because it does not address D10 or the scheduling problem — collection
state stays on the endpoint, and each new endpoint needs its own scheduled task.
Worth reconsidering if the lab ever grows an endpoint that should not be
reachable from the SOC server.
