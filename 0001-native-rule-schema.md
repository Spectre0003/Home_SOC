# 1. Native rule schema rather than Sigma

Date: 2026-09-08
Status: Accepted

## Context

Stage 4 of the roadmap replaces hardcoded Python detections with data-driven
rules. Sigma is the established open format for exactly this, with a large
public rule corpus.

A separate detection-engineering project is planned around Sigma, Atomic Red
Team, and CI. Two options existed:

1. Keep this engine on a small native schema; the other project owns Sigma.
2. Make this a Sigma backend, consuming upstream Sigma rules directly, with the
   other project acting as its validation half.

## Decision

Option 1. HomeSOC uses its own minimal rule schema.

## Consequences

The two projects stay independently useful. Neither needs the other to be
cloned, run, or understood, which matters because both exist to be read as
standalone portfolio work.

The condition grammar stays deliberately minimal — field equality, `in`, and
negation. A rule needing more than that is either a sequence rule or belongs in
code. Growing the grammar toward Sigma's expressiveness would recreate the
coupling this decision avoids, one feature at a time.

ATT&CK technique IDs are the shared vocabulary between the two projects. Both
map detections to the same namespace, so coverage across both can be discussed
without either importing the other.

Rules may carry a free-text `references:` entry pointing at an equivalent public
Sigma rule. That is documentation; nothing loads it.

The cost is the public Sigma corpus. HomeSOC's detections are written by hand,
and there is no path to importing community rules without revisiting this.

## Alternatives rejected

Building a Sigma-shaped abstraction now "in case" of a later switch. That
abstraction *is* the coupling, deferred and disguised. If the decision is
revisited, it should be revisited honestly rather than pre-paid for.
