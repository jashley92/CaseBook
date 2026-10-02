# 0014. No chat thread in the record

- **Status:** Accepted (v1.2.0 removed case Discussion)
- **Recorded:** 2026-10-02

## Context

Earlier releases had a per-case Discussion thread. Teams already talk in their own chat tool. A chat thread
inside the record of a breach is discoverable conversation, and it rarely adds to the findings.

## Decision

The record keeps **conclusions**: decisions with their rationale, the brief, notes, handoffs. A note can
@mention people who can see the case, which emails them a link. An optional chat webhook (Slack or Teams)
broadcasts selected case events to a team channel.

## Consequences

- The v1.2.0 upgrade dropped the `CaseComments` table. Its audit entries remain, and the chain still verifies.
- Don't reintroduce free-form threads. A request for one usually points to a missing structured field: a
  decision, a question in the brief, a task comment.
