# Business rules and assumptions

The rules a developer could break without noticing, why each exists, and where it's enforced. If a change you're
making touches one of these, read the linked page first and add a test that would fail if the rule broke.

## The record

| # | Rule | Why | Where |
|---|---|---|---|
| R1 | **Every change goes through the app and is audit-chained.** No raw SQL against business tables; no direct file edits in the stores. | The audit chain, seals and ledger make any out-of-band change look like tampering, and raise a Critical alarm. | `AuditChainInterceptor`; [integrity.md](../architecture/integrity.md) |
| R2 | **History is append-only.** Classification, phase, severity, materiality and team changes, corrections, task comments, custody events and audit rows are never updated or deleted. Notes, investigation entries and briefs are versioned by supersede. | "What was known, and when" must survive. A record that can be quietly rewritten isn't evidence. | `Case.cs`, history entities |
| R3 | **Cases, timeline entries, notes, evidence, tasks and comments are never deleted.** Cancel a task; archive a case. | Same as R2. | No delete paths exist |
| R4 | **Recorded time never moves; effective time is separate.** A transition's "when it happened" is validated (not future, not before detection, in order with its neighbours of the same kind) and needs a reason when backdated by more than an hour. Correcting it later adds a `TransitionTimeCorrection` with a reason. | Work is often recorded after the fact; the record must show both times, and metrics use the real time. [Decision 0010](../decisions/0010-after-the-fact-recording.md) | `Case.CheckEffective`, `Case.CorrectTransitionTime`, `CaseService.RequireReasonIfBackdated` |
| R5 | **Milestones are derived, never stored.** | One source of truth; corrections flow through automatically. [Decision 0011](../decisions/0011-timeline-derived-milestones.md) | `CaseMilestones` |
| R6 | **A Decision always has a rationale**, and can only be created as a Decision entry (not by promoting a note or completing a task). | A decision without its why is useless to an examiner. | `TimelineEntry`, `CaseService` |
| R7 | **Hash canonicals only grow, conditionally.** New fields are appended only when non-default; preferences and workflow state stay out. | Otherwise every existing row fails verification. | every `BuildCanonicalContent` |
| R8 | **Enums are append-only; `Permission` names never change.** | Stored as numbers (and names) in rows, hashes and audit JSON. | `Domain/Enums` |
| R9 | **Shipped migrations are immutable.** | Databases installed from a release must keep upgrading. [Decision 0009](../decisions/0009-migrations-two-providers-immutable.md) | CI script |
| R10 | **`Case.Summary` equals the current brief's summary.** | The report prints the summary; the brief versions it. | `Case.ReviseBrief`, `UpdateDetails` |

## People and permissions

| # | Rule | Why | Where |
|---|---|---|---|
| P1 | **Every mutating service method has a permission entry**; a missing entry fails closed. | Authorization for actions is structural, so a new entry point (API, job) inherits it. | `CaseActionPermissions`, `AdminActionPermissions` |
| P2 | **UI hiding is not enforcement.** | Anyone can call a circuit method by crafting events; only server checks count. | [security.md](../architecture/security.md) |
| P3 | **Every case query goes through `ForUser`**, including writes, exports, counts and suggestions; "hidden" and "missing" must look the same. | A restricted case's existence is itself sensitive. | `CaseQueryExtensions`; `LoadTrackedAsync` |
| P4 | **The restricted-case audience also limits mentions, handoffs, notifications and campaign walks.** | Otherwise an email or a campaign view leaks the case. | `CaseAudience`, `CampaignService` |
| P5 | **Permissions are code-defined; roles are bundles.** Visibility keys on `ViewAllCases`/`ViewRestricted`, never on a role name. | Custom roles must work without code changes. [Decision 0003](../decisions/0003-permissions-as-code-atoms.md) | `RoleDefinitions`, `ForUser` |
| P6 | **The last role with `Administer` can't lose it.** | Prevents locking everyone out. | `RoleService` |
| P7 | **Security and infrastructure settings are never editable in-app or overridable from the database.** | A database writer must not be able to redirect the SIEM, swap keys or turn off authentication. [Decision 0007](../decisions/0007-settings-split.md) | `SettingsCatalog`, `DbSettingsConfiguration` |
| P8 | **Production requires Windows authentication.** | The development handler signs everyone in as an administrator. | `Program.cs` |

## Automation

| # | Rule | Why | Where |
|---|---|---|---|
| A1 | **No job or API changes case state.** Jobs read and notify; the API stages a pending import for a person to confirm; gates block or warn. | Every transition must be an attributable human act. [Decision 0004](../decisions/0004-human-gated-automation.md) | Scanners; `CaseImportService.SubmitAsync` |
| A2 | **No calls to AI services.** | Regulated data stays inside. [Decision 0005](../decisions/0005-no-outbound-ai.md) | — |
| A3 | **Side effects never fail the user's action.** Email, chat, SIEM, access log and seal export are best effort. | A slow collector mustn't block an incident response. The audit chain is the system of record. | Notifiers, transports |
| A4 | **Suggestions never act on their own** (related cases, duplicate checks, entity review, brief freshness, narrative drafts). | Same as A1. | |
| A5 | **Multi-step flows are resumable** (creating a case with its setup, applying an import). | A retry after a partial failure must not duplicate. | `CreateCase.razor`, `CaseImportService` |

## Case lifecycle

| # | Rule | Why | Where |
|---|---|---|---|
| L1 | **Classification members and phases are fixed in code**; only labels are configurable. | Breach notifications, SLA stamps and gate triggers key on specific members. [Decision 0006](../decisions/0006-ladder-and-phases-in-code.md) | Enums; `TaxonomyCatalog` |
| L2 | **A null classification is a Complex Event**, and there's no way back to it. Promotion renumbers unless the number is custom. | Complex Events aren't on the ladder and mustn't use IRP sequence numbers. | `Case.Reclassify`, `RenumberToIrp` |
| L3 | **Only upward classification moves and closing are gated**; the gate is chosen by the target. | De-escalation should never be harder than escalation. | `CaseService.ReclassifyAsync`, `ChangePhaseAsync` |
| L4 | **Gates judge saved state; attestations count only when ticked at transition time; unknown checks never pass.** | Gate results must be reproducible and can't be satisfied by stale data. | `StageGateEvaluator`, `GateCheckRegistry` |
| L5 | **Contained, resolved and closed times are set on first entry** (at the effective time), move only with a correction, and closed is cleared on reopen. | SLA and MTTR metrics depend on them. | `Case.ChangePhase` |
| L6 | **Legal hold blocks archiving**; releasing needs a reason and, when configured, a second person. | Records under hold must not be put away. | `Case.Archive`, legal-hold methods |
| L7 | **Exercise cases are fixed at creation** and excluded from every aggregate, reminder, feed and correlation, but kept in the audit chain. New aggregate queries must call `ExcludingExercises()`. | Tabletops mustn't distort metrics or trigger real follow-up. | `Case.IsExercise`, `CaseQueryExtensions.ExcludingExercises` |
| L8 | **One reported time stops all jurisdictions' notification clocks.** Closing doesn't stop them. | Current design; see [known issues](known-issues.md). | `Case.MarkReported`, `NotificationDeadlineService` |
| L9 | **Materiality is recorded only on Incidents and Breaches**, and a final status needs who decided, when and why. CaseBook records determinations; it doesn't make them. | The decision is Legal's or a committee's. | `Case.RecordMateriality` |
| L10 | **A closed case isn't locked; changes after closure are marked.** The header says "N changes after closure" (counted per save from the audit trail, leaving out the post-incident review and improvement actions); timeline entries added or edited after closure say so; the report's Outcome section and timeline note them. | Records are completed after the fact (late evidence, a vendor's answer); an examiner sees what changed and when, instead of a lock that pushes the work elsewhere. | `AfterClosure`, `Case.ClosureRecordedAtUtc` |

## Content

| # | Rule | Why | Where |
|---|---|---|---|
| C1 | **Entities are unique per case by type and value** (case-insensitive); adding again updates. Network values are refanged; hashes, file names and accounts are kept exactly. | Correlation depends on canonical values. | `Case.AddEntity`, `IocObservable` |
| C2 | **One link per pair of cases**, in either direction. | Avoids contradictory link types. | `CaseService.LinkCaseAsync` |
| C3 | **Evidence is hashed on the way in and never rewritten.** Passive views (thumbnails) don't create custody events; transfers are also chained. | Custody must reflect deliberate handling, not page renders. | `EvidenceService` |
| C4 | **Discovery-conscious wording**; notes and the working brief are off in the case report by default; the post-incident review is never in the case report. | These records can be discovered. [Decision 0012](../decisions/0012-discovery-conscious-records.md) | `ReportSection`, `ReportService` |
| C5 | **Report approval is a separate, permission-gated, one-way step.** Generating never approves; maker-checker is optional. | Separation of duties. | `ReportService.ApproveAsync` |
| C6 | **CSV exports neutralize formula characters.** | A malicious indicator value mustn't execute in a spreadsheet. | `Csv.Escape` |
| C7 | **Indicator values never go in URLs.** | URLs are logged by proxies and browsers. | UI conventions |

## Assumptions

| Assumption | Consequence if it's false |
|---|---|
| **One app instance.** | The audit-chain lock, live refresh, presence, reminder trackers and SIEM queue are in-process. Two instances would race on the chain (the unique index is the only backstop), double-send reminders and miss live updates. |
| The data root, database and seal exports are backed up together. | Restored evidence or seals don't match the database. |
| The seal key is provisioned out of band before first start. | The app generates its own, which proves less. |
| Database administrators don't edit data. | Detected (chain, seals, ledger), but costly. |
| Users' AD groups are maintained. | Access drifts; revalidation only reflects mapping changes and new logons. |
| Case volume is a single SOC's (hundreds to low thousands of cases a year). | See [performance.md](performance.md). |
| The `Production` environment name is used on servers. | Other names fall back to development sign-in. |
