# Testing

What's tested, how to run it, what isn't covered, and what to check by hand before shipping.

## Test projects

| Project | Tests | References | Runs against |
|---|---|---|---|
| `tests/IncidentManager.UnitTests` | ~490 test methods (plus ~160 `InlineData` rows) | Domain, Application, Infrastructure | Plain objects |
| `tests/IncidentManager.IntegrationTests` | ~495 test methods | Application, Infrastructure, Web | In-memory SQLite per test class; 4 tests on SQL Server; one boots the real host |

Packages: xUnit 2.9, FluentAssertions 8, coverlet (coverage isn't collected in CI), and
`Microsoft.AspNetCore.Mvc.Testing` for the host test. There's no mocking library; fakes are hand-written. There
are **no** browser end-to-end tests and **no** Razor component (bUnit) tests.

### Helpers (`tests/IncidentManager.IntegrationTests/TestDoubles.cs` and nearby)

| Helper | Use |
|---|---|
| `TestDbContextFactory` | A new `AppDbContext` per call over a shared SQLite connection, like production's per-operation contexts |
| `FixedClock` | Settable time, so SLA, deadline and seal-cadence tests are deterministic |
| `TestCurrentUser` | Default `analyst1` with the Analyst role; override permissions for custom roles |
| `CapturingSecurityEventSink` | Assert SIEM events |
| `NoOpAuditWriter`, `NoOpCaseNotifications`, `TestSlaTargets`, `TestOptionsMonitor` | Stub out side effects and live settings |
| `[SqlServerFact]` | Runs only when `CASEBOOK_TEST_SQL` is set |

The usual setup: open `SqliteConnection("Data Source=:memory:")` in the test class constructor, build options
with `UseSqlite`, often add the real `AuditChainInterceptor`, call `EnsureCreated()`, and frequently seed the three
demo cases with `DevDataSeeder.SeedAsync`. Because of `EnsureCreated`, most tests don't run migrations.

## Running tests

```bash
dotnet test                                                     # everything (SQL Server tests skip)
dotnet test tests/IncidentManager.UnitTests                     # one project
dotnet test --filter "FullyQualifiedName~StageGate"             # by class or namespace fragment
dotnet test --filter "DisplayName~audit"                        # by test name
```

There are no `[Trait]` categories.

**SQL Server tests** (the production engine):

```bash
docker run -d --name casebook-sql -e ACCEPT_EULA=Y -e 'MSSQL_SA_PASSWORD=Local!Test2026' -p 14333:1433 mcr.microsoft.com/mssql/server:2022-latest
export CASEBOOK_TEST_SQL='Server=localhost,14333;User Id=sa;Password=Local!Test2026;TrustServerCertificate=True;Encrypt=False'
dotnet test tests/IncidentManager.IntegrationTests --filter "FullyQualifiedName~SqlServerTests"
```

Each test creates and drops its own database.

### Upgrade-path test

`tools/upgrade-test/upgrade-path.sh <from-tag> [<to-ref>]` installs an old release into a fresh SQL Server
database (migrated and seeded with demo cases and an audit chain), then starts your working tree against the same
database. It passes when the new build comes up healthy with every migration applied and every case and audit row
intact.

```bash
export CASEBOOK_TEST_SQL='Server=localhost,14333;User Id=sa;Password=Local!Test2026;TrustServerCertificate=True;Encrypt=False'
export SQLCMD='docker exec casebook-sql /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P Local!Test2026'
tools/upgrade-test/upgrade-path.sh v1.0.0
```

Run it from Git Bash on Windows (`MSYS_NO_PATHCONV=1` may be needed for the docker paths).

## Continuous integration

`.github/workflows/ci.yml` runs on pushes to `main` and on pull requests, **except** when only Markdown, `docs/`,
`LICENSE` or `.gitignore` changed.

| Job | Step | Guards against |
|---|---|---|
| `build-test` | `dotnet build -c Release`, `dotnet test` | Regressions (SQLite) |
| | `tools/ci/check-migrations-immutable.sh` | Editing, deleting, renaming or squashing a migration that shipped in a `v*` tag |
| | `dotnet ef migrations has-pending-model-changes` (SQL Server and SQLite) | A model change without a migration, which would stop the upgraded app from starting |
| | `dotnet list package --vulnerable --include-transitive` | Known-vulnerable packages (fails the build) |
| | deprecated package report | Information only |
| `upgrade-path` (SQL Server 2022 service container) | SQL Server tests | Provider-specific behavior |
| | `upgrade-path.sh` from the three newest release tags **and** the first release (v1.0.0) | Upgrades breaking existing databases |

CodeQL runs through GitHub's default setup, not a workflow file. Dependabot proposes weekly NuGet and GitHub
Actions updates (EF Core and `Microsoft.Extensions.*` majors are held back).

`.github/workflows/release.yml` runs on a `v*` tag: it re-checks migration immutability, publishes the app and
builds `casebook-<tag>.zip` (`app/`, `deploy/`, `migrations-sqlserver.txt`, `VERSION.txt`) with a `.sha256`, then
creates the GitHub release. **It doesn't run the tests**; it relies on CI having passed for that commit, so only
tag commits that went through CI on `main`.

## What is covered

| Area | Unit | Integration | Notes |
|---|---|---|---|
| Integrity: hash chain, seals, tamper detection, evidence re-hash, ledger script, compliance bundle | 42 | 23 | Includes direct-database tampering and a "competent rewrite" only the seal catches |
| Authorization, need-to-know, roles, API tokens, access log | 27 | 56 | `CaseActionPermissionsTests` checks every mutating method is mapped |
| Case lifecycle: numbering, classification, reopen, concurrency, legal hold, materiality, exercises, templates, transition times | 87 | 78 | |
| Stage gates | 12 | 15 | Including the close-gate data migration |
| Timeline, narrative, entities, mentions, citations | 21 | 8 | |
| Tasks | 4 | 21 | |
| Import (case documents, STIX, CSV) | 7 | 21 | Including that the committed schema matches the code |
| Threat intel: IOCs, STIX, ATT&CK, campaigns, TLP | 30 | 24 | |
| Reporting: Word, templates, diagrams, defanging, Markdown, CSV, lessons, program report | 67 | 42 | |
| Dashboards, SLA, workload | 35 | 16 | Includes SQLite/SQL Server parity |
| Settings, configuration bundle, secrets, taxonomy, data elements, preferences | 33 | 82 | |
| SIEM | 15 | 15 | |
| Deadlines and reminder scanners | 19 | 36 | |
| Notifications (email, chat) | 52 | 9 | |
| Real-time, activity, agenda and ICS | 20 | 21 | |
| Evidence upload, search | 8 | 19 | |
| Health, host startup, error messages | 9 | 9 | `HostStartupSmokeTests` boots the real host and fetches `/health/live` and `/cases` |

## What is not covered

- **The browser.** No end-to-end tests; no component tests. UI logic in `.razor` files (dialogs, forms, the
  workspace) is exercised only through its services.
- **HTTP endpoints.** Downloads, exports, the import API (token scheme, 5 MB limit), rate limiting, security
  headers and the 403/404 redirects have no request-level tests; their services do.
- **Windows authentication** and real AD group resolution (CI runs on Linux).
- **Background-service wrappers** (the scanners they call are tested).
- **SQL Server** beyond four tests and the upgrade test; most tests use SQLite with `EnsureCreated`, not the SQL
  Server migrations.
- **PowerShell deploy scripts** (no Pester tests).

## Manual checks before a release

Work through these in the browser against a freshly seeded demo database (and, ideally, SQL Server):

1. Create a case with indicators that match an open case; confirm the duplicate prompt, then link.
2. Promote a Complex Event; check the gate, the renumbering and the milestone.
3. Add an investigation entry, a decision and an event step with actor and target; edit the entry and check the
   version history; correct a transition time.
4. Upload evidence, preview it, download it, record a transfer; check the custody list.
5. Add a note with an @mention and a `[[` tag; put it on the timeline.
6. Add, complete (with result to the timeline) and comment on a task; apply a playbook.
7. Close the case through the gate with an override; check the flagged milestone; reopen it.
8. Restrict a case; confirm it disappears for a second identity (`?as=`) without the clearance, and reappears
   when assigned.
9. Generate a report draft, approve it, verify its hash; generate with a Word template.
10. Integrity → Verify now reports VALID; the compliance bundle downloads.
11. Administration: change a setting and see it take effect; edit a role and see a signed-in tab update within
    two minutes.
12. Light and dark themes, and phone width, on the pages you changed.

## Critical paths: always test when touching

| If you touch | Make sure a test covers |
|---|---|
| `AuditChainInterceptor`, `HashChainService`, any `BuildCanonicalContent` | Chain verification still passes on existing data; tampering is still detected |
| `CaseQueryExtensions`, `CaseRestrictionPolicy`, `CaseAudience` | A restricted case stays invisible to an unassigned, uncleared user, including in exports, search and campaigns |
| `CaseActionPermissions`, `AdminActionPermissions`, `RoleDefinitions` | The permission each action needs; a refusal |
| `DbSettingsConfiguration`, `SettingsCatalog` | A non-whitelisted row is still rejected on load |
| Evidence endpoints and `ImageSniffer` | Non-images aren't served inline |
| `Csv` | Formula-injection characters are still neutralized |
| Migrations | Both providers; the upgrade test; a data-migration test if you change existing rows |
| `CaseMilestones`, report timeline | Screen and report agree |
