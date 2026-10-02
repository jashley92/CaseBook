# Recipes for common changes

Step-by-step guides for the changes people make most, in the order the layers need touching. Before starting
any of them, read [reference/business-rules.md](../reference/business-rules.md).

## Add or change a database column

Example: a new optional field on a case.

1. **Domain** (`src/IncidentManager.Domain/Entities/<Entity>.cs`): add the property. If only the domain should
   change it, give it a private setter and a method that validates and sets it (and calls `Touch`).
2. **Hash** (only for `IHashableEntity` types): decide whether the field is part of the record. If it is, append
   it to `BuildCanonicalContent()` **only when it has a non-default value**, so existing rows hash exactly as
   before:
   ```csharp
   if (NewField is { Length: > 0 }) sb.Append("|newfield|").Append(NewField);
   ```
   Preferences and workflow state stay out of the hash.
3. **Mapping** (`src/IncidentManager.Infrastructure/Persistence/Configurations/*.cs`): max length, required,
   index. Remember that lengths over 4000 become `nvarchar(max)`, so validate in code.
4. **Migrations, both providers** (from the repo root, after `dotnet tool restore`):
   ```powershell
   # SQLite (development)
   dotnet ef migrations add <Name> --project src/IncidentManager.Infrastructure `
     --startup-project src/IncidentManager.Web --context AppDbContext

   # SQL Server (production)
   $env:IM_MIGRATIONS_PROVIDER = 'SqlServer'
   dotnet ef migrations add <Name> --project src/IncidentManager.Migrations.SqlServer `
     --startup-project src/IncidentManager.Web --context AppDbContext
   dotnet ef migrations script --idempotent --project src/IncidentManager.Migrations.SqlServer `
     --startup-project src/IncidentManager.Web --context AppDbContext `
     --output deploy/sql/casebook-schema-sqlserver.sql
   Remove-Item Env:\IM_MIGRATIONS_PROVIDER
   ```
   A new **NOT NULL** column on existing tables needs a default for existing rows. On the ledger tables
   (`AuditLog`, `IntegritySeals`, `ChainOfCustodyEvents`) new columns **must be nullable**, and
   `deploy/sql/02-Enable-Ledger.sql` must list them (`LedgerScriptModelTests` checks both).
5. **Never edit a migration that's in a release tag.** CI fails if you do. Add another migration instead.
6. **Service** (`Application/...`): read and write the field; add validation (lengths, ranges) and a
   concurrency stamp if it's edited in a long-lived form.
7. **DTOs and read models** (`Application/Cases/CaseDtos.cs` and others): expose it where the UI needs it.
8. **UI** (`Web/Components/...`): show and edit it; use `Ui.Label` for enums.
9. **Report or export**, if it belongs there (`Application/Reporting/ReportService.cs`, `ReportTemplateFields.cs`
   for a Word `{{field}}`).
10. **Import schema**, if it should be importable (`Application/Import/CaseImport.cs`), then regenerate
    `docs/case-import.schema.json` (a test compares them).
11. **Configuration bundle**, if it's admin reference data that should travel between instances
    (`Application/Config/`).
12. **Tests**: domain rule tests; a persistence round-trip; a hash-stability test if you touched a canonical.
13. **Docs**: [data-model.md](../architecture/data-model.md); [UPGRADE.md](../UPGRADE.md) *Notes* if upgrades
    behave visibly differently.

CI checks: `dotnet ef migrations has-pending-model-changes` for both providers, the immutability script, and an
upgrade from older releases on real SQL Server.

## Add a page

1. Create `src/IncidentManager.Web/Components/Pages/<Name>.razor`:
   ```razor
   @page "/my-page"
   @attribute [Authorize(Policy = Policies.ViewCases)]
   @inject SomeService Service

   <PageTitle>My page · CaseBook</PageTitle>
   <PageHeader Title="My page" Subtitle="@_asOf" />

   @if (_items is null) { <LoadingBlock /> }
   else if (_items.Count == 0) { <p class="text-muted">Nothing here yet. Add the first one above.</p> }
   else { … }
   ```
2. **Authorization**: always set a policy (the fallback only requires sign-in). Use the narrowest permission.
3. **Data**: call an Application service. Never query the database from a component; never hold a `DbContext`.
   If the page shows cases, the service must apply `ForUser` (and `ExcludingExercises` for aggregates).
4. **States**: `LoadingBlock` while loading; an empty state that says what would be there and what to do; errors
   through `UserFacingError.Describe` and a toast. The layout's `ErrorBoundary` catches the rest.
5. **URL state**: filters and sort in the query string (`[SupplyParameterFromQuery]`), so the view is
   bookmarkable. Never put an indicator value in a URL.
6. **Navigation**: add a link to `Layout/NavMenu.razor` inside the matching `AuthorizeView`, and, if useful, a
   command in `Shared/CommandPalette.razor`. For an admin page, use `@layout AdminLayout` and add it to the rail
   in `Layout/AdminLayout.razor`.
7. **Style**: follow [STYLE-GUIDE.md](../STYLE-GUIDE.md) (page header, tokens, `im-list` tables, sentence
   case, no em-dashes). Check light and dark, and phone width.
8. **Docs**: the route table in [frontend.md](../architecture/frontend.md#routing); a screenshot entry in
   `capture.mjs` if it's a main screen.

## Add a new case use case (a workflow step)

1. **Domain**: a method on `Case` that enforces the rule and appends whatever history is needed. Throw
   `ArgumentException` or `InvalidOperationException` with a message a user can act on.
2. **Service**: a method on `CaseService` (or a new service for a separate area) following
   [the write path](../architecture/backend.md#the-write-path): `Require()`, validate, new context, load
   through `LoadTrackedAsync`, call the domain method, save, then notifications or SIEM.
3. **Permission**: add `[nameof(CaseService.YourMethodAsync)] = Permission.X` to `CaseActionPermissions`.
   Without it the method throws at runtime, and `CaseActionPermissionsTests` fails.
4. **Reason on the audit entry**: if the user gives a reason for an edit, set `db.PendingChangeReason` before
   saving.
5. **Timeline**: if it should appear there, either it's content (a `TimelineEntry`) or a milestone derived from
   a record ([below](#change-the-timeline)).
6. **Human-gated**: it must be triggered by a person. Jobs and APIs may suggest, draft or notify, but not call
   it ([decision 0004](../decisions/0004-human-gated-automation.md)).
7. **UI**: a dialog in `CaseWorkspace.razor` (for header actions) or the tab. Disable Apply until the input is
   valid; catch `ForbiddenException`, `GateNotSatisfiedException`, `StaleEditException` and argument errors as
   the existing dialogs do. Add the action to the command palette through `BuildPaletteActions`.
8. **Tests**: the domain rule, the service (including a permission refusal and a need-to-know miss), and any
   gate or notification side effect.
9. **Docs**: the workflow page, [business-rules.md](../reference/business-rules.md), SIEM catalog if you added
   an event.

## Add a new entity (table)

1. Domain class deriving from `Entity` or `AuditableEntity`; implement `IHashableEntity` if it's part of the
   record. Give it a `CaseId` property if it belongs to a case (the audit chain uses that name to attach the
   case number and to trigger live refresh).
2. Decide whether it hangs off the `Case` aggregate (a navigation collection, created through `Case` methods)
   or stands alone (its own service). Case content belongs in the aggregate.
3. `DbSet` in `AppDbContext`, mapping in `Configurations/`, foreign key to `Cases` if case-scoped (cascade is the
   convention; a second cascade path to the same table is refused by SQL Server, so use a plain indexed column
   there).
4. Leave it out of `NotAudited` unless it's genuinely telemetry or per-user state.
5. Migrations for both providers; services; permissions; UI; tests; [data-model.md](../architecture/data-model.md)
   (tables and the ERD).

## Add a permission

Only when no existing permission fits; permissions are deliberately few.

1. Append a member to `Domain/Enums/Permission.cs` (never rename existing ones; roles store them by name).
2. Add a policy constant and an entry in `Application/Security/Policies.cs`. `Program.cs` registers one
   policy per entry automatically.
3. Decide which system roles get it in `Application/Security/RoleDefinitions.cs` (SysAdmin gets everything
   automatically). System roles are re-synced on the next start.
4. Find every `switch` over permissions and add the new member: search for `Permission.ManageLegal`
   (`ForbiddenException` wording, `Shared/AccessSummary.razor` labels and descriptions, and so on).
5. Enforce it:
   - pages: `@attribute [Authorize(Policy = Policies.YourPermission)]`;
   - endpoints: `.RequireAuthorization(Policies.YourPermission)`;
   - case actions: entries in `CaseActionPermissions`; admin actions: `AdminActionPermissions`; other services:
     `_user.Has(Permission.YourPermission)` plus `ForbiddenException`;
   - UI: `AuthorizeView` to hide controls (convenience only).
6. If it changes **visibility** of cases, change `CaseQueryExtensions.ForUser`, `CaseRestrictionPolicy` and
   `CaseAudience` together, with tests.
7. Docs: [security.md](../architecture/security.md) tables and the role table in the product overview.

## Change the timeline

| Goal | Change |
|---|---|
| A new investigation entry type | Append to `TimelineEntryType` (never renumber). Add the label in `Ui.Label` / `TaxonomyCatalog`, a glyph and color in `Ui.TimelineGlyph` / `TimelineColor`, the composer's type list in `CaseTimelineTab.razor`, the import mapping in `CaseImportService` and the prompt (`CaseImportPrompt`), and the report label. |
| A new milestone | Add a `MilestoneKind` and a projection in `Application/Cases/CaseMilestones.cs` with a stable `Key` (`kind:<id>`). Decide whether it's a "key entry" (`CaseTimelineTab`) and whether the report includes it (`ReportService.InvestigationTimeline`). If it duplicates a stored entry, add a de-duplication rule like the existing task and evidence ones. |
| New data on entries | Follow [Add or change a database column](#add-or-change-a-database-column); append it to `TimelineEntry.BuildCanonicalContent` only when set; copy it forward in `Case.EditInvestigationEntry` if it should survive edits. |
| Ordering | `CaseTimelineTab.razor` (merge and sort) and `ReportService` (report order). Keep them consistent. |
| Brief freshness | `Application/Cases/BriefFreshness.cs` decides which changes prompt a brief update. |

Then update [timeline.md](../architecture/timeline.md) and the timeline screenshot.

## Add an in-app setting

1. Add a `SettingDefinition` to `Application/Admin/SettingsCatalog.cs`: key, label, group (which admin section
   shows it), kind (bool, int, text, multi-line text), default, range or options, description.
2. Read it through `IConfiguration` (per request) or bind an options class and inject `IOptionsMonitor<T>` so it
   updates live. Give it a sensible code default.
3. Add the default to `appsettings.json` (so the file and catalog agree), and to the production template only if
   production needs a different value.
4. A **security or infrastructure** setting (a URL that receives data, a secret, a path, anything an attacker
   with database access shouldn't change) must **not** be in the catalog. Bind it from server-side config only.
5. Docs: [configuration.md](../operations/configuration.md).

## Add a SIEM event

1. Append an id to `Application/Security/SecurityEventIds.cs` (ids are a contract: never renumber or reuse).
2. Add a factory to `SecurityEvents.cs`. Include ids, labels and outcomes only; never case content or personal
   data.
3. Emit it at the one place the action is decided: `_sink.Emit(SecurityEvents.YourEvent(...))`.
4. Add it to the catalog in [OPERATIONS.md §5](../OPERATIONS.md#event-id-catalog).

## Add a stage-gate check

1. Add a key to `GateCheckKeys` and a predicate, label and parameter description to `GateCheckRegistry`. Keys
   are stored in gates and configuration bundles, so never rename one.
2. If it needs a fact the evaluator doesn't load yet, add it to `GateCaseFacts` and compute it in
   `StageGateEvaluator` from **saved** state.
3. If existing installs should get it on a default gate, ship a data migration (see
   `20261001005306_ClosureGateNotificationsRecorded` and its SQL Server twin) and a migration test like
   `ClosureGateMigrationTests`.
4. Add a "Fix" target in `CaseWorkspace.razor` if there's an obvious place to fix it.
5. Update the check table in [governance.md](../workflows/governance.md#stage-gates).

## Add a notification email

1. Add a template id with default subject and body in `Application/Admin/EmailTemplateCatalog.cs` (tokens are
   HTML-encoded).
2. Add the trigger in `Infrastructure/Notifications/CaseNotifications.cs`: decide the audience (respect
   `CaseAudience` for restricted cases), the opt-out (per-user preference unless mandatory) and chat routing.
3. If a background job sends it, put the decision in a scanner with a tracker so each item is reminded once, and
   keep the job read-only.
4. Update the notification table in [backend.md](../architecture/backend.md#who-gets-notified-about-what).

## Change styling or a script

Edit `wwwroot/app.css` or `wwwroot/js/*.js`, then bump the matching `?v=` in `Components/App.razor` in the same
commit. Follow [STYLE-GUIDE.md](../STYLE-GUIDE.md). Recapture affected screenshots.
