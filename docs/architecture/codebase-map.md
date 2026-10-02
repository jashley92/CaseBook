# Codebase map

Where things are, what belongs where, and how careful to be. Paths are relative to the repository root.
Layering and dependencies are described in [overview.md](overview.md).

**Safety key:** 🟢 routine changes · 🟡 read the linked doc first · 🔴 changes affect tamper evidence,
security or upgrades: add a test that would fail if the guarantee broke, and get a second review.

## Repository layout

```
IncidentManager.sln
Directory.Build.props          .NET 10, nullable, analyzers (latest-recommended). Warnings don't fail the build.
.github/workflows/             ci.yml (build, test, migration guards, SQL Server upgrade test) · release.yml (bundle)
deploy/                        PowerShell install / upgrade / ledger scripts, SQL, production config template
docs/                          This documentation set
integrations/xsiam/            XSIAM automation that elevates an incident through the import API
src/
  IncidentManager.Domain/      Entities and business rules. No dependencies.
  IncidentManager.Application/ Use cases, permissions, policies, ports
  IncidentManager.Infrastructure/  EF Core, audit chain, files, crypto, email, SIEM, config, report rendering
  IncidentManager.Migrations.SqlServer/  Production migrations
  IncidentManager.Web/         Host, UI, auth, endpoints, background jobs
tests/
  IncidentManager.UnitTests/         ~490 tests: domain rules, policies, hashing, rendering, parsing
  IncidentManager.IntegrationTests/  ~495 tests: services against SQLite, a few against SQL Server, one host boot
tools/
  ci/check-migrations-immutable.sh   Fails CI if a shipped migration changed
  upgrade-test/upgrade-path.sh       Installs an old release on SQL Server and upgrades it to this tree
  screenshots/capture.mjs            Regenerates every image in docs/screenshots
```

Internal planning files (`BACKLOG.md`, `*-BACKLOG.md`) are git-ignored and not part of the repository.

## `src/IncidentManager.Domain`

| Path | Holds | Safety |
|---|---|---|
| `Entities/Case.cs` | **The `Case` aggregate root** (~1,300 lines): every state change on a case is a method here (`Open`, `Reclassify`, `ChangePhase`, `Assign`, `AddEntity`, `AddEventStep`, `EditInvestigationEntry`, `ReviseBrief`, `CorrectTransitionTime`, `Archive`, …), plus the canonical hash and case numbering | 🔴 |
| `Entities/CaseHistory.cs` | Append-only history rows: classification, phase, severity, materiality, assignment changes | 🔴 |
| `Entities/TimelineEntry.cs` | Event and investigation entries, decision fields, the canonical hash | 🔴 |
| `Entities/*.cs` (others) | One class per table. Each `IHashableEntity` has a `BuildCanonicalContent()` | 🔴 for canonicals, 🟢 otherwise |
| `Enums/*.cs` | Every enum. **Values are stored and hashed: append only, never renumber** | 🔴 |
| `ValueObjects/` | `LegalReferral`, `MaterialityDetermination`, `ThirdPartyDetails` (stored in the `Cases` row) | 🟡 |
| `Observables/IocObservable.cs` | Indicator parsing: refanging (`hxxp`, `[.]`), type detection, splitting pasted lists | 🟢 |
| `Common/` | `Entity` (client-generated Guid id), `AuditableEntity`, `IHashableEntity` | 🔴 |

Put **rules that must always hold** here, as methods on the entity that throw `ArgumentException` or
`InvalidOperationException` with a user-readable message. The UI shows these messages verbatim.

## `src/IncidentManager.Application`

| Folder | Holds | Safety |
|---|---|---|
| `Cases/CaseService.cs` | **Most use cases** (~2,000 lines): create, reclassify, phase, timeline, entities, notes, tasks, brief, handoff, legal, restriction. Every write calls `Require()` | 🟡 |
| `Cases/CaseActionPermissions.cs` | The permission each `CaseService` write needs. A missing entry fails closed; a test checks coverage | 🔴 |
| `Cases/CaseQueryExtensions.cs` | `ForUser()`: **the need-to-know filter** applied to every case query | 🔴 |
| `Cases/CaseRestrictionPolicy.cs`, `CaseAudience.cs` | Who may lift a restriction; who may be mentioned or notified about a case | 🔴 |
| `Cases/CaseMilestones.cs` | Derives timeline milestones from the case record | 🟡 [timeline.md](timeline.md) |
| `Cases/CaseNext.cs`, `BriefFreshness.cs`, `EntityMentions.cs`, `HandoffDraft.cs` | "What's next", brief staleness, entity reference counts, handoff prefill | 🟢 |
| `Cases/ActionItemCommentService.cs`, `CaseShortcutService.cs` | Task comments; pinned and recent cases | 🟢 |
| `Cases/CreateCaseValidator.cs` | FluentValidation rules for case creation | 🟢 |
| `StageGates/` | `GateCheckRegistry` (the machine checks), `StageGateEvaluator`, gate models | 🟡 |
| `Evidence/` | Upload, open, custody, transfer; `ImageSniffer` (only real raster images are shown inline) | 🔴 |
| `Reporting/` | `ReportService` (generate, approve, verify), `CaseReportModel`, sections, template fields, defanging | 🟡 |
| `Lessons/` | Post-incident review, improvement actions, the template-based "what happened" draft | 🟢 |
| `Import/` | Case-import document model, parser, preview, apply, JSON Schema, AI prompt, STIX/CSV conversion | 🟡 (the schema is a public contract) |
| `Integrity/` | Chain verification, sealing, the alarm monitors, evidence re-hash, audit queries and CSV | 🔴 |
| `Compliance/` | Notification-deadline policy and service, legal register, compliance bundle | 🟡 |
| `Security/` | `Permission` policies, `RoleDefinitions` (system roles), `AdminActionPermissions`, SIEM event ids and factories, idle-timeout policy | 🔴 |
| `Admin/` | Settings catalog (the in-app whitelist), roles, templates, gates, data elements, notification rules, report profiles and templates, taxonomy, email templates, access review | 🟡 (`SettingsCatalog` is 🔴) |
| `Config/` | Signed configuration-bundle export and import | 🟡 |
| `Notifications/` | Reminder scanners and their in-memory "already sent" trackers; per-user notification preferences | 🟢 |
| `Dashboards/`, `Sla/`, `Work/`, `Intel/`, `Campaigns/`, `Mitre/`, `Export/`, `Activity/`, `Views/` | Read models: dashboard, program report, SLA math, My work, agenda and ICS, team workload, indicators, campaigns, ATT&CK catalog and coverage, IOC feed and STIX, activity feed, saved views | 🟢 |
| `Content/` | Markdown → sanitized HTML, and to plain text | 🟡 (sanitization) |
| `Abstractions/` | Ports: `IAppDbContextFactory`, `ICurrentUser`, `IClock`, stores, notifier, email, hash chain, seal signer… | 🟡 |
| `DependencyInjection.cs` | Registers Application services | 🟢 |

Put **use cases** here: load through the need-to-know filter, call domain methods, save once. Put reusable
calculations (SLA, deadlines, gates) here as pure functions so they can be unit-tested.

## `src/IncidentManager.Infrastructure`

| Folder | Holds | Safety |
|---|---|---|
| `Persistence/AppDbContext.cs` | DbSets, SQLite date handling (UTC ticks), the `PendingChangeReason` hook | 🔴 |
| `Persistence/Configurations/` | EF mapping: keys, lengths, indexes, foreign keys | 🔴 (changes need migrations) |
| `Persistence/Interceptors/AuditChainInterceptor.cs` | **Writes the audit chain** on every save; the `NotAudited` list; post-commit change broadcast | 🔴 |
| `Persistence/Migrations/` | SQLite (development) migrations | 🔴 never edit a shipped one |
| `Persistence/DevDataSeeder.cs` | Migrate on startup; reference data in every environment; demo data in Development | 🟡 |
| `Persistence/RoleSeeder.cs` | System roles synced to code on every start; AD mappings seeded on first run | 🔴 |
| `Persistence/AppDbContextFactory.cs` | Design-time factory for `dotnet ef` (reads `IM_MIGRATIONS_PROVIDER`) | 🟢 |
| `Security/` | `HashChainService`, `RsaSealSigner`, `AuditWriter`, `AuditChainGate`, `RoleDirectory`, `UserDirectory`, AD group mapper | 🔴 |
| `Storage/` | File stores for evidence, reports, branding, templates and seals | 🔴 (path handling) |
| `Reporting/` | `ReportGenerator` (built-in Word layout), `WordTemplateEngine` (fill `{{fields}}`), `SkiaReportDiagrams`, embedded fonts | 🟡 |
| `Notifications/` | `CaseNotifications` (who gets emailed or chatted about what), `EmailSender`, `EmailComposer`, alarm notifiers | 🟡 |
| `Siem/` | Event queue, syslog CEF transport, JSON shape, webhook URL validation | 🟡 |
| `Secrets/` | CyberArk CCP provider and the `@cyberark:` reference parser | 🔴 |
| `Configuration/` | The database settings provider (whitelist on load) and the reloader | 🔴 |
| `Access/` | Access-log recording and coalescing | 🟡 |
| `Realtime/` | In-process case-change notifier and presence registry | 🟢 |
| `Sla/`, `Severities/`, `Taxonomy/`, `Time/`, `Compliance/`, `Agenda/` | Configuration-backed providers; clock; ICS feed tokens | 🟢 |
| `DependencyInjection.cs` | Provider switch (SQLite or SQL Server), store and service registration | 🟡 |

## `src/IncidentManager.Migrations.SqlServer`

The production migration set, plus the model snapshot. Generated with `IM_MIGRATIONS_PROVIDER=SqlServer`
([recipes](../development/recipes.md#add-or-change-a-database-column)). 🔴: never edit, rename or delete a
migration that shipped in a release tag.

## `src/IncidentManager.Web`

| Path | Holds | Safety |
|---|---|---|
| `Program.cs` | **Composition root and HTTP surface**: data protection, auth, policies, rate limiter, health checks, startup seeding, the middleware pipeline, every minimal-API endpoint | 🔴 |
| `Components/App.razor` | The host page: CSS and script tags (with `?v=` cache busters), theme attributes, reconnect UI | 🟡 bump `?v=` when the file changes |
| `Components/Routes.razor` | Router, `AuthorizeRouteView`, not-found page | 🟢 |
| `Components/Layout/` | `MainLayout` (shell, error boundary, toasts, palette, idle guard), `NavMenu`, `AdminLayout` (admin rail) | 🟢 |
| `Components/Pages/` | One component per route (`@page`) | 🟢 |
| `Components/Pages/CaseWorkspace.razor` | The case workspace shell: header, Actions menu, all case dialogs, tab host, live refresh (~2,500 lines) | 🟡 |
| `Components/Pages/CaseTabs/` | One component per workspace tab, plus the context rail, entity panel and brief card | 🟢 |
| `Components/Shared/` | Reusable components and `Ui.cs` (badge and label helpers) — see [frontend.md](frontend.md#shared-components) | 🟢 |
| `Security/` | Dev and API-token authentication handlers, `RoleClaimsTransformer`, permission revalidation, security headers, user mirror | 🔴 |
| `BackgroundJobs/` | Hosted services and their options | 🟡 |
| `Services/` | Per-circuit UI services: toasts, display time zone, command palette, case-list memory, error-message mapping | 🟢 |
| `Siem/`, `Notifications/` | Webhook and Windows Event Log SIEM transports; Slack/Teams webhook notifier | 🟡 |
| `HealthChecks/`, `Ops/` | Readiness checks; backup-status file reader | 🟢 |
| `wwwroot/app.css` | All styling and design tokens | 🟢 bump `?v=` in `App.razor` |
| `wwwroot/js/` | Small CSP-safe JS modules (see [frontend.md](frontend.md#javascript)) | 🟢 bump `?v=` |
| `wwwroot/lib/`, `wwwroot/bootstrap/` | Vendored libraries | 🟡 update `THIRD-PARTY-NOTICES.md` |
| `appsettings.json` | Base configuration for every environment, including production | 🟡 [configuration](../operations/configuration.md) |

## `deploy/`

| File | Purpose |
|---|---|
| `New-CaseBookConfig.ps1`, `casebook.config.template.psd1` | Create the answers file both installers read |
| `Verify-Install.ps1` | Pre-install readiness check and post-install smoke test |
| `Install-Database.ps1`, `sql/01-Create-Database.sql` | Create the database and the app login |
| `Install-CaseBook.ps1`, `appsettings.Production.template.json` | Publish (or copy), write production config, create the IIS site, set ACLs |
| `Upgrade-CaseBook.ps1` | Preflighted, backed-up upgrade with rollback |
| `sql/casebook-schema-sqlserver.sql` | Idempotent schema script for DBAs (regenerate with every migration) |
| `Enable-Ledger.ps1`, `Export-LedgerDigest.ps1`, `Verify-LedgerDigests.ps1`, `sql/02-Enable-Ledger.sql`, `lib/CaseBookSql.ps1` | SQL Server ledger |

## Where do I find…

| Question | Answer |
|---|---|
| Where is authentication handled? | `Web/Program.cs` (mode selection), `Web/Security/AuthModeGuard.cs` (fail-safe), `Web/Security/DevAuthenticationHandler.cs`, `RoleClaimsTransformer.cs`, `ApiKeyAuthenticationHandler.cs` |
| Where are permissions checked? | Pages: `@attribute [Authorize(Policy = …)]`. Actions: `CaseService.Require()` with `CaseActionPermissions`; `AdminActionPermissions.Require<T>()`; direct `_user.Has(...)` in other services. Visibility: `CaseQueryExtensions.ForUser`. See [security.md](security.md) |
| Where are roles defined? | `Application/Security/RoleDefinitions.cs` (system roles); custom roles in the `Roles` table via `Admin/RoleService.cs` |
| Where is the incident model defined? | `Domain/Entities/Case.cs` and `Domain/Enums/CaseEnums.cs` |
| Where is the timeline logic? | Stored entries: `Domain/Entities/TimelineEntry.cs`, `Case.AddEventStep` / `EditInvestigationEntry`. Milestones: `Application/Cases/CaseMilestones.cs`. Merge and display: `Web/Components/Pages/CaseTabs/CaseTimelineTab.razor`. Report: `ReportService.InvestigationTimeline` |
| Where are tasks created? | `CaseService.AddActionItemAsync`, `ApplyTemplateAsync` (playbooks), `Case.RaiseTaskFromQuestion` (from the brief); UI in `CaseTasksTab.razor` and `Shared/QuickTask.razor` |
| Where are notes stored? | Table `AnalystNotes` (`Domain/Entities/AnalystNote.cs`); written by `CaseService.AddNoteAsync` / `EditNoteAsync` |
| Where are evidence files written? | `Infrastructure/Storage/FileEvidenceStore.cs` (path `EvidenceStore:RootPath`), via `Application/Evidence/EvidenceService.cs` |
| Where are API calls made? | Inbound: `Web/Program.cs` (`/api/import/cases`). Outbound: `Web/Siem/WebhookTransport.cs`, `Web/Notifications/ChatWebhookNotifier.cs`, `Infrastructure/Secrets/CyberArkCcpSecretProvider.cs`, `Infrastructure/Notifications/EmailSender.cs` (SMTP), `Infrastructure/Siem/SyslogTransport.cs` |
| Where are database queries defined? | Inline LINQ in each Application service, each on a short-lived context from `IAppDbContextFactory`. There's no repository layer |
| Where is the schema defined? | Entity classes plus `Infrastructure/Persistence/Configurations/*.cs`; the migrations are the history |
| Where are shared UI components? | `Web/Components/Shared/` and the helpers in `Shared/Ui.cs` |
| Where is validation performed? | Domain methods (always), `CreateCaseValidator` (FluentValidation, case creation), service guards (lengths, times, uniqueness), and form logic in components (UX only) |
| Where are integrations implemented? | See [operations/integrations.md](../operations/integrations.md) for each one's files |
| Where are environment variables consumed? | Only through `IConfiguration` (standard `Section__Key` mapping); the design-time `IM_MIGRATIONS_PROVIDER` in `AppDbContextFactory.cs`. See [configuration.md](../operations/configuration.md) |
| Where is error handling implemented? | `Web/Program.cs` (exception handler, status-code redirects), `MainLayout.razor` and `CaseWorkspace.razor` (`ErrorBoundary`), `Web/Services/UserFacingError.cs` (exception → message) |
| Where are emails written? | Wording: `Application/Admin/EmailTemplateCatalog.cs` (defaults; admins can override). Who and when: `Infrastructure/Notifications/CaseNotifications.cs`. Rendering: `EmailComposer.cs` |
| Where are SIEM events defined? | `Application/Security/SecurityEventIds.cs` (ids) and `SecurityEvents.cs` (factories) |
| Where are settings defined? | In-app: `Application/Admin/SettingsCatalog.cs`. Server-side: `*Options` classes and `appsettings.json` |
| Where is the report built? | Model: `Application/Reporting/ReportService.cs`. Word output: `Infrastructure/Reporting/ReportGenerator*.cs` or `WordTemplateEngine.cs` |
| Where is demo data created? | `Infrastructure/Persistence/DevDataSeeder.cs` (Development only) |
| Where are the stage-gate checks? | `Application/StageGates/GateCheckRegistry.cs` |
| Where is the IOC parser? | `Domain/Observables/IocObservable.cs` |
