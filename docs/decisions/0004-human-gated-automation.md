# 0004. Human-gated: no job or API changes case state

- **Status:** Accepted
- **Recorded:** 2026-10-02

## Context

An examiner may ask of any state change in an investigation record (a classification, a phase, a closure, a
finding) "who decided this, and when?" An automated change has no good answer.

## Decision

- Background jobs **read** case data and send reminders, digests and alarms. The only database write any job
  makes is an integrity seal. "Reminder already sent" is tracked in memory, not stored.
- The inbound API (`POST /api/import/cases`) never writes to a case. It stages a **pending import**, which a
  person reviews, edits and confirms in *Import → Pending imports*.
- Stage gates block or warn; they don't move a case on their own. A person applies the transition, or
  overrides a gate with a written justification.

## Alternatives considered

SOAR-style rules that close or escalate cases automatically. Rejected: they make the record say something no
person decided.

## Consequences

- New automation produces a suggestion, a draft or a notification, never a write to the case.
- Every transition in the audit trail and on the timeline has a human actor.
