# Architecture decision records

Short records of choices a future developer might otherwise question and reverse. Each one says what was
decided, why, and what it costs. They describe decisions already reflected in the code; a decision that is
later reversed gets a new record that supersedes the old one (the old one stays, marked *Superseded*).

| # | Decision | Status |
|---|---|---|
| [0001](0001-blazor-server-on-prem.md) | Blazor Server, on-prem, single-tenant | Accepted |
| [0002](0002-integrity-spine.md) | Tamper evidence: row hashes, a hash-chained audit log and signed seals | Accepted (chain keying deferred) |
| [0003](0003-permissions-as-code-atoms.md) | Permissions are code-defined; roles are bundles; need-to-know is one query filter | Accepted |
| [0004](0004-human-gated-automation.md) | Human-gated: no job or API changes case state | Accepted |
| [0005](0005-no-outbound-ai.md) | CaseBook never calls an AI; AI help is bring-your-own via a prompt and a reviewed import | Accepted |
| [0006](0006-ladder-and-phases-in-code.md) | The classification ladder and the phase set are fixed in code; only their labels are configurable | Accepted |
| [0007](0007-settings-split.md) | Operational settings in the database (audited); security and infrastructure settings in server files | Accepted |
| [0008](0008-blobs-on-disk.md) | Evidence and report files on disk; hashes and metadata in the database | Accepted |
| [0009](0009-migrations-two-providers-immutable.md) | Two migration sets (SQLite dev, SQL Server prod); shipped migrations are immutable | Accepted |
| [0010](0010-after-the-fact-recording.md) | Record work after the fact: effective times, kept entry times, append-only history | Accepted |
| [0011](0011-timeline-derived-milestones.md) | The timeline derives milestones from the case record instead of storing them twice | Accepted |
| [0012](0012-discovery-conscious-records.md) | Discovery-conscious records: neutral wording, notes out of the report, a separate lessons report | Accepted |
| [0013](0013-word-only-reports.md) | Reports are Word documents only | Accepted |
| [0014](0014-no-discussion-thread.md) | No chat thread in the record; @mentions live on notes | Accepted |
| [0015](0015-entity-tags-double-bracket.md) | Entity tags in Markdown start with `[[`, not `#` | Accepted |
| [0016](0016-key-custody-and-seal-copies.md) | Integrity keys from a file, the certificate store or CyberArk; seal copies to the SIEM | Proposed |

## Template

```markdown
# NNNN. Title

- **Status:** Accepted | Superseded by NNNN
- **Date:** YYYY-MM-DD

## Context
What situation forced a choice.

## Decision
What we do.

## Alternatives considered
What else was on the table and why it lost.

## Consequences
What this costs, what it makes easy, what must never be done because of it.
```
