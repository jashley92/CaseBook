# 0011. The timeline derives milestones from the case record

- **Status:** Accepted
- **Recorded:** 2026-10-02

## Context

The timeline is the chronology the report prints. Many of the events on it already exist as records
elsewhere: classification and phase changes, gate passages, the materiality determination, a completed task,
a handoff, evidence being added. Copying each into a timeline table would create two sources of truth that
could disagree.

## Decision

Only the things people write as timeline content are stored as timeline entries:

- **event steps**: what the adversary or vendor did;
- **investigation entries**: what the team did, including **decisions** with their rationale.

Everything else is a **milestone derived when the timeline is read**, from the record it comes from, and is
labelled with that source ("from severity change", "from task").

## Consequences

- To show something new as a milestone, extend the derivation; don't add rows.
- Correcting a source record (a transition time, for example) corrects the timeline automatically.
- The report's timeline is assembled the same way, so the screen and the report agree.

See [architecture/timeline.md](../architecture/timeline.md).
