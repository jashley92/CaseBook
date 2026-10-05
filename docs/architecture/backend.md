# Backend: services, endpoints and jobs

How server-side behavior is organized: the write path every change follows, the HTTP endpoints, the services
and what they're for, the background jobs, and error handling. Security rules are in
[security.md](security.md); integrations in [operations/integrations.md](../operations/integrations.md).

## The write path

Every change to a case follows the same pattern, mostly in `Application/Cases/CaseService.cs`:

```csharp
public async Task ChangeSeverityAsync(Guid id, Domain.Enums.Severity severity, string? reason = null,
    DateTimeOffset? effectiveAtUtc = null, CancellationToken ct = default)
{
    Require();                                          // 1. permission for this method, from CaseActionPermissions
    RequireReasonIfBackdated(effectiveAtUtc, reason);   // 2. service-level validation
    using var db = _factory.CreateDbContext();          // 3. a short-lived context for this operation
    var c = await LoadTrackedAsync(db, id, ct);         // 4. loaded through the need-to-know filter
    c.ChangeSeverity(severity, reason, _user.UserId, _clock.UtcNow, effectiveAtUtc); // 5. domain rules
    await db.SaveChangesAsync(ct);                      // 6. row hashes + audit chain, one transaction
}
```

(The real method, with comments added. Methods with side effects call `ICaseNotifications` or
`ISecurityEventSink` after step 6.)

1. **`Require()`** finds the caller's method name in `CaseActionPermissions` and checks the user holds that
   permission. A method with no entry throws, so a new write can't ship unguarded; a unit test checks the map
   covers every mutating method. A refusal raises SIEM 5202 and `ForbiddenException`.
2. **Validation** in the service: lengths, "a reason is required when backdated by more than an hour",
   optimistic concurrency stamps for long-lived editors (details, impact, legal referral, materiality, brief,
   review).
3. **`IAppDbContextFactory`** gives a fresh `DbContext` per operation. Never inject a context into a component or
   hold one in a field: a Blazor circuit is a single DI scope that lives as long as the tab, and contexts aren't
   thread-safe.
4. **`LoadTrackedAsync`** loads the case through `ForUser`, so writing to a case you can't see reads as "Case
   not found or not accessible."
5. **The domain method** on `Case` enforces the invariants and appends history rows.
6. **`SaveChangesAsync`** runs `AuditChainInterceptor` ([integrity.md](integrity.md)). A service can set
   `db.PendingChangeReason` to attach a reason to the audit entries for that save.
7. **Side effects** after commit: `ICaseNotifications` (email, chat), `ISecurityEventSink` (SIEM). Failures are
   logged and swallowed.

Multi-step flows (creating a case with its indicators, links and playbook tasks; applying an import) are
separate saves, each made **resumable**: progress is tracked so a retry after a partial failure doesn't
duplicate anything.

## HTTP endpoints

Besides the Blazor UI (`MapRazorComponents`), all HTTP endpoints are minimal APIs in `Web/Program.cs`. Unless
noted they use the interactive scheme (Windows or Dev), require the listed permission, and are rate-limited per
user by the `downloads` policy.

| Method and route | Permission | Returns | Side effects |
|---|---|---|---|
| `GET /health/live` | anonymous | `Healthy` (no checks) | — |
| `GET /health`, `/health/ready` | anonymous | `Healthy` 200 or `Unhealthy` 503 (database reachable, evidence folder exists) | — |
| `GET /branding/logo` | anonymous | The report and email logo, or 404 | — |
| `GET /agenda/agenda.ics` | ViewCases (not rate-limited) | Your open dated tasks as an ICS file | — |
| `GET /agenda/feed.ics?token=` | anonymous; the signed token is the credential | Personal ICS subscription feed; 404 if `Agenda:FeedKey` is blank or the token is invalid, reset or expired | — |
| `GET /evidence/{id}` | ViewCases | The file, as an attachment | Custody "Downloaded"; access log; SIEM 5302 |
| `GET /evidence/{id}/inline` | ViewCases (not rate-limited) | Image thumbnail, only if the bytes are PNG, JPEG, GIF or WebP; else 404 | none (deliberately) |
| `GET /reports/{id}` | ViewCases | The stored report | Access log; SIEM 5303 |
| `GET /cases/{id}/graph.stix.json` | ViewCases | The case graph as a STIX 2.1 bundle | Access log; SIEM 5304 |
| `GET /campaigns/{id}/rollup.json` | ViewCases | Campaign rollup | Access log; SIEM 5304 |
| `GET /export/metrics.csv` | ViewCases | Dashboard metrics with monthly and quarterly rollups | Access log; SIEM 5304 |
| `GET /export/legal-register.csv` | ViewCases | Legal and regulatory obligations register | Access log; SIEM 5304 |
| `GET /export/program-report.csv?year=&quarter=&exercises=` | ViewCases | Program report; 400 "Unknown quarter." | Access log; SIEM 5304 |
| `GET /export/improvement-actions.csv?scope=&exercises=` | ViewCases | Improvement-action register | Access log; SIEM 5304 |
| `GET /export/iocs.csv` | ViewCases | Malicious IOCs across visible cases (a blocklist feed) | Access log; SIEM 5304 |
| `GET /export/case-audit.csv?case=&actor=&action=&entity=&from=&to=` | ViewCases + can see the case | One case's audit trail (up to 100,000 rows) | Access log; SIEM 5304 |
| `GET /export/access-log.csv?…` | Administer | The access log (up to 100,000 rows) | none |
| `GET /export/compliance-bundle.zip?from=&to=` | Administer | Compliance evidence bundle | Audit entry; access log; SIEM 5304 |
| `GET /export/config-bundle.json` | Administer | Signed configuration bundle | Audit entry |
| `GET /export/report-template-starter.docx`, `…-lessons.docx` | Administer | Starter Word templates | — |
| `GET /export/report-templates/{id}` | Administer | An uploaded template | — |
| `GET /export/report-templates/{id}/preview?caseId=` | Administer | The template filled with a real case (not stored) | Access log |
| `POST /api/import/cases` | **API token** + EditCases | 201 with a pending-import id; 400, 401, 403, 413 (over 5 MB), 429 | Stores a pending import |
| `GET /api/import/cases/schema` | anonymous | The import JSON Schema | — |

Behavior to know:

- **Errors in production redirect.** An unhandled exception redirects to `/Error?ref=<request id>`, including on
  download and API routes, so an API caller gets a 302 to an HTML page rather than a JSON error.
- **Unknown or hidden evidence and report ids aren't 404s.** The services throw "not found" (the same message
  for hidden and missing, so nothing leaks), which surfaces as a 500 and then the error page.
- A **403 on a page GET** redirects to `/access-denied` (SIEM 5201). An **HTML GET to an unknown path**
  redirects to `/not-found`.
- **Anonymous endpoints aren't anonymous under IIS** unless you carve them out, because the site has anonymous
  authentication disabled except under `/api` ([troubleshooting](../operations/troubleshooting.md#health-probe-returns-401)).

The import API is documented for callers in [API.md](../API.md).

## Services

All registered in `Application/DependencyInjection.cs` and `Infrastructure/DependencyInjection.cs`. "Reusable"
means it has no UI coupling and could back another entry point.

| Service | Responsibility | Notes |
|---|---|---|
| `CaseService` | Every case use case: create, number, classify, phase, severity, assignment, handoff, timeline, entities, relationships, graph layout, techniques, notes, tasks, brief, links, supersede, legal, restriction, materiality, reported, archive; reads: list, detail, preview, overlaps, mentionable users, gate evaluation | Reusable, but large. Add new case use cases here (or split by area) and register the permission. |
| `ActionItemCommentService` | Append-only task comments | Needs only `ViewCases` |
| `CaseShortcutService` | Pinned and recent cases | |
| `EvidenceService` | Upload (hash, custody), open (custody on download), view and transfer custody | |
| `ReportService` | Generate drafts, approve, verify hash, preview, template preview | |
| `LessonsService` | Post-incident review, improvement actions and register | |
| `CaseImportService` | Parse, preview, apply; pending-import queue | Goes through `CaseService` writes |
| `IntegrityService` | Verify chain, seal, audit queries | |
| `EvidenceIntegrityVerifier` | Re-hash evidence | Read-only |
| `ComplianceBundleService`, `ConfigBundleService`, `LegalRegisterService` | Bundles and register | |
| `NotificationDeadlineService` | Regulatory deadline evaluation per case, open headlines | Pure policy in `NotificationDeadlinePolicy` |
| `StageGateEvaluator` + `GateCheckRegistry` | Evaluate a gate against persisted case state | |
| `DashboardService`, `ProgramReportService`, `AttackCoverageService`, `IndicatorService`, `IocFeedService`, `StixExportService`, `CampaignService`, `ActivityFeedService` | Read models | Need-to-know scoped; most exclude exercises |
| `MyWorkService`, `AgendaService`, `AgendaFeedService`, `TeamWorkloadService` | Personal and team work views; calendar | |
| `SavedViewService`, `UserDisplayPreferenceService`, `UserNotificationPreferenceService` | Per-user state | Not audited |
| `ApiTokenService` | API tokens | |
| Admin services (`AdminSettingsService`, `RoleService`, `CaseTemplateService`, `StageGateService`, `DataElementService`, `NotificationRuleService`, `ReportProfileService`, `ReportTemplateService`, `TaxonomyAdminService`, `EmailTemplateAdminService`, `AccessReviewService`) | Administration | Writes guarded by `AdminActionPermissions` |
| Scanners (`OverdueActionItemScanner`, `DueSoonActionItemScanner`, `NotificationDeadlineScanner`, `StaleCaseScanner`, `DigestScanner`, `ExecutiveReportScanner`) | Decide who to remind; used by the background jobs | Read-only |
| `MarkdownService` | Markdown to sanitized HTML and plain text | |

Infrastructure implementations of the ports include `EmailSender`, `EmailComposer`, `CaseNotifications`,
`SecurityEventQueue`, `SyslogTransport`, the CyberArk secret provider, file stores, `RsaSealSigner`,
`HashChainService`, `ReportGenerator`, `WordTemplateEngine`, `SkiaReportDiagrams`, `RoleDirectory`,
`UserDirectory`, `CaseChangeNotifier`, `CasePresenceService` and the configuration-backed providers (SLA
targets, deadlines, labels, time zone). Web-only services: `CurrentUser`, the auth handlers, the webhook and
Event Log SIEM transports, the chat notifier, and the per-circuit UI services.

### Who gets notified about what

From `Infrastructure/Notifications/CaseNotifications.cs`. All email requires `Email:Enabled`; chat requires the
chat webhook and the matching `Notifications:Chat:*` switch.

| Event | Email to | Chat |
|---|---|---|
| Escalated to Breach | `Email:LegalDistribution` | yes (redacted for restricted cases) |
| Assigned to a case (not self) | the assignee, if `Email:AssignmentNotifications` | optional |
| @mentioned in a note (new mentions only) | each person mentioned who can see the case | optional |
| Handoff with "Email it to them" | the recipient, if they can see the case | — |
| Task overdue / due soon (background) | the owner, else the IC; escalation tiers to the IC, then managers | optional |
| Notification deadline at risk / passed (background) | the IC and assignees | optional |
| Stale case (background) | the IC and assignees | optional |
| Digest (background) | each opted-in user | — |
| Quarterly executive report (background) | users holding the built-in Manager role | — |
| Audit-chain break / evidence drift | `Email:IntegrityAlertDistribution` | — |

Users can opt out of assignment, overdue and due-soon emails unless an administrator makes them mandatory.

## Background jobs

Each job is a `BackgroundService` in `Web/BackgroundJobs/`. They share a shape: re-read options every poll (so
in-app setting changes apply within minutes), run the first cycle at startup when enabled, create a fresh DI
scope per cycle, and log and continue on failure. In a background scope the "user" is `system`.

| Job | Does | Poll / default interval | Settings | Default |
|---|---|---|---|---|
| `IntegritySealHostedService` | Verify the chain and latest seal; alarm on a break; seal when due | verify every 10 min; seal every 6 h (24 h in the production template) | `Integrity:AutoSeal:*` | verify always on; sealing on |
| `EvidenceIntegrityHostedService` | Re-hash stored evidence; alarm 5003 on drift | 5 min poll; 24 h | `Integrity:EvidenceVerify:*` | off |
| `OverdueActionItemHostedService` | Overdue task reminders and escalation | 5 min poll; 24 h | `Notifications:OverdueScan:*` | off |
| `DueSoonActionItemHostedService` | Due-soon reminders | 5 min poll; 6 h | `Notifications:DueSoonScan:*` | off |
| `NotificationDeadlineHostedService` | Regulatory deadline reminders | 5 min poll; 1 h | `Notifications:DeadlineScan:*` (+ deadline clock on) | off |
| `StaleCaseHostedService` | Quiet-case nudges | 5 min poll; 12 h | `Notifications:StaleScan:*` | off |
| `DigestHostedService` | Per-user digest | 5 min poll; 1 h | `Notifications:DigestScan:*` | off |
| `ExecutiveReportHostedService` | Quarterly figures to managers, first 7 days of a quarter | hourly | `Notifications:ExecutiveReport:Enabled` | off |
| `SecurityEventDispatcher` | Drain the SIEM queue to each enabled transport | continuous | `Siem:*` | idle unless a transport is enabled |

**No job changes case state** (verified: no scanner saves; the only job write is the integrity seal).

Caveats:

- "Already reminded" trackers are in memory. After a restart, the first cycle sends one reminder again for each
  item that still qualifies. Two instances would double-send.
- The executive report marks a quarter as sent before sending, so a failed send isn't retried until a restart.

## Real-time

`CaseChangeNotifier` (singleton) publishes "case X changed by Y" after each commit; the workspace, the activity
bell and the case list subscribe. The event also carries what changed (`CaseChange.Items`: each row's entity type,
id, and added, modified or deleted), collected by the audit interceptor from the same tracked entries it audits.
`CaseRegionMap` turns that into the parts of a case to re-read (record, notes, tasks, things, evidence, brief,
paperwork, or the whole case), and `CaseService.RefreshPartsAsync` re-reads only those, need-to-know scoped. `CasePresenceService` tracks who's viewing which case; a circuit handler
removes a closed tab. Both are in-process. Writes made outside EF tracking, or by another process, aren't
broadcast.

## Error handling and logging

| Where | Behavior |
|---|---|
| HTTP, production | `UseExceptionHandler` → redirect to `/Error?ref=<id>`; the exception is logged by ASP.NET Core |
| HTTP, development | Developer exception page |
| Blazor | `ErrorBoundary` around each page and each workspace tab; `UserFacingError.Describe` turns known exceptions into messages and logs the rest at Error |
| Domain and services | Throw `ArgumentException` or `InvalidOperationException` with user-readable messages; `ForbiddenException`, `StaleEditException`, `GateNotSatisfiedException`, FluentValidation's `ValidationException` |
| Best-effort paths | Email, chat, SIEM, access log, user mirror, presence and change broadcasts, seal export, the database settings provider: failures are logged (except seal export) and never fail the user's action |

Logging uses the ASP.NET Core default providers. Stable event ids: 5001 (chain broken) and 5003 (evidence drift),
both Critical. Named categories: `Security.Settings` (rejected setting, Critical), `Security.RateLimit`.

## Reuse guidance

- **Safe to reuse anywhere:** the domain methods, `CaseService` writes (they carry their own permission and
  need-to-know checks), the read models, policies (`SlaPolicy`, `NotificationDeadlinePolicy`,
  `StageGateEvaluator`), `IocObservable`, `MarkdownService`, `Csv.Escape`.
- **Coupled to the UI:** anything in `Web/Services`, the workspace's dialog logic (gate fragments, "when it
  happened"), `CaseCommandRegistry`.
- **A new entry point** (another API, a job that writes) gets the permission checks for free by calling
  `CaseService`. It must also authenticate a real user or an API token, because `system` holds no permissions,
  and it must follow [decision 0004](../decisions/0004-human-gated-automation.md).
