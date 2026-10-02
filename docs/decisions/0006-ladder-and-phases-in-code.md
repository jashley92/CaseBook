# 0006. The classification ladder and the phase set are fixed in code

- **Status:** Accepted
- **Recorded:** 2026-10-02

## Context

Organizations want CaseBook to match their own incident response plan, and most of it can be data: templates,
gates, data elements, roles. The classification ladder (Adverse Event → Incident → Breach) and the phases
(New → Triage → Containment → Eradication → Recovery → Post-Incident → Closed) are different, because code
depends on specific members.

## Decision

The members stay as enums. Administrators can **rename, hide or reorder their display labels**
(Administration → Taxonomy). These are stored as display overrides that don't touch stored values or hashes.

Code that depends on specific members includes:

- escalation to `Breach` fires notifications and the breach stage gate;
- entering `Containment` and `Recovery` stamps the times the response SLAs measure;
- stage-gate triggers map one-to-one onto specific moves (`PromoteToAdverseEvent`, `EscalateToIncident`,
  `EscalateToBreach`, `CloseCase`).

## Alternatives considered

A data-driven ladder and phase list. Rejected: deleting or renaming "Breach" would silently stop breach
notifications and gates, with no error.

## Consequences

- Adding a rung or a phase is a code change. Enum values are stored and hashed, so append new members and
  never renumber existing ones.
- Before making any other dimension data-driven, check whether code branches on a specific member. If it
  does, offer configurable labels only.
