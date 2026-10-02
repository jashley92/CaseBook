# 0010. Record work after the fact

- **Status:** Accepted
- **Recorded:** 2026-10-02

## Context

In a real incident, people act first and write it down later. If the record only knew when something was
typed, the timeline and the response-time metrics would be wrong. An examiner would see a contained-at time
hours after containment actually happened.

## Decision

- Transitions (phase, classification, severity) take a **"when it happened"** time, which defaults to now.
  The time the entry was made is kept too, and is shown when the two differ ("recorded …").
- A transition's effective time can be **corrected later, with a reason**. The correction is its own audited
  record (`TransitionTimeCorrection`), and the original value stays in the audit trail.
- Notes and investigation entries are **append-only**. An edit adds a new version that supersedes the old
  one, so what was believed at each point stays readable.

## Consequences

- Metrics and SLA clocks use effective times, not entry times.
- Don't fix an effective time by editing a row. Use the correction flow, which keeps the reason.
- The model has no shifts. Handoffs are between people and are recorded when they happen.
