# Getting started (developers)

From a fresh clone to a running app, a passing test suite, and a first safe change.

## Prerequisites

| Tool | Version | Why |
|---|---|---|
| .NET SDK | 10.0.x | Build, run, test. `Directory.Build.props` targets `net10.0`. |
| Git | any recent | Tags matter: CI compares migrations against release tags. Clone with full history. |
| Node.js | 18+ (optional) | Only for `tools/screenshots/capture.mjs` and regenerating the MITRE catalog |
| Chrome or Edge | (optional) | For the screenshot tool |
| Docker | (optional) | SQL Server 2022 for the SQL Server tests and the upgrade test |
| IDE | Visual Studio 2022+, Rider or VS Code with C# Dev Kit | |

Nothing else is needed: development uses SQLite and a built-in development sign-in.

## First 30 minutes

```bash
git clone https://github.com/jashley92/CaseBook.git
cd CaseBook
dotnet run --project src/IncidentManager.Web --launch-profile http
```

Open <http://localhost:5103>. On first start the app:

1. creates `src/IncidentManager.Web/App_Data/incidentmanager.db` and applies the SQLite migrations;
2. seeds reference data (case templates, stage gates, report profiles, 13 data elements, NY and US notification
   rules, the five system roles);
3. because the environment is Development and there are no cases, seeds **demo data**: seven people, three
   detailed cases (`2026-01_Phishing_Wave`, `2026-02_Vendor_SaaS_Breach`, `2026-03_Anomalous_VPN_Logins`),
   about 30 historical cases for the dashboard trends, a campaign link, and a stored evidence file;
4. generates a seal-signing key in `App_Data/keys/` and starts sealing.

Then:

```bash
dotnet test                       # ~980 tests; SQL Server tests skip without CASEBOOK_TEST_SQL
```

Spend the rest of the half hour in the app with the phishing case open next to these docs:

1. [product/overview.md](../product/overview.md): what CaseBook is and what it isn't.
2. [product/screens.md](../product/screens.md): the screens, with callouts.
3. [architecture/overview.md](../architecture/overview.md): how it fits together.
4. [reference/business-rules.md](../reference/business-rules.md): what you must not break.
5. [architecture/codebase-map.md](../architecture/codebase-map.md): where to find things.

## The development user

`Auth:Mode` is `Dev` in `appsettings.json`, so every request is signed in as **Dev Analyst**
(`S-1-5-21-DEV-1001`) with **all five roles** (`DevAuth:Roles`).

| To… | Do this |
|---|---|
| Act as a second person (presence, assignment, need-to-know, mentions) | Add `?as=Robin` to any URL. A cookie keeps you as `dev:robin` until you clear it. **Same roles as the dev user.** |
| Test with fewer permissions | Edit `DevAuth:Roles` in `src/IncidentManager.Web/appsettings.json` locally (don't commit it), e.g. `["Analyst"]`, and restart. An override in `appsettings.Development.json` or an environment variable can't shorten the list, because configuration lists merge by index. Permissions refresh in open tabs within two minutes. |
| See the demo team's view | The seeded people are `ic1` (Ivy Commander), `analyst1` (Alex Analyst), `analyst2` (Robin Reyes), `mgr1` (Morgan Manager), `legal1` (Lee Privacy), `admin1` (Sam Admin). `?as=` creates `dev:<name>` ids, which are different users from these. |

Never deploy with `Auth:Mode=Dev`. Production refuses to start that way, but other environment names don't
([known issues](../reference/known-issues.md)).

## Local data

All under `src/IncidentManager.Web/` (git-ignored):

| Path | Holds |
|---|---|
| `App_Data/incidentmanager.db` (+ `-shm`, `-wal`) | The SQLite database |
| `App_Data/incidentmanager-design.db` | Used only by `dotnet ef` |
| `App_Data/evidence-store/`, `report-output/`, `report-templates/`, `branding/` | File stores |
| `App_Data/keys/seal-signing.pem` | Generated seal key |
| `seals/` | Exported seal files |

**Reset to fresh demo data:** stop the app, delete `App_Data/incidentmanager.db*` (and the stores and `seals/`
if you want), start again.

**Use a throwaway database** without touching yours:

```bash
ConnectionStrings__Default="Data Source=/tmp/cb.db" EvidenceStore__RootPath=/tmp/cb-evidence \
  ReportOutput__RootPath=/tmp/cb-reports dotnet run --project src/IncidentManager.Web --launch-profile http
```

**Run against SQL Server** (closer to production):

```bash
docker run -d --name casebook-sql -e ACCEPT_EULA=Y -e 'MSSQL_SA_PASSWORD=Local!Test2026' -p 14333:1433 mcr.microsoft.com/mssql/server:2022-latest
Database__Provider=SqlServer \
ConnectionStrings__Default='Server=localhost,14333;Database=CaseBookDev;User Id=sa;Password=Local!Test2026;TrustServerCertificate=True;Encrypt=False' \
  dotnet run --project src/IncidentManager.Web --launch-profile http
```

## Launch profiles

`src/IncidentManager.Web/Properties/launchSettings.json`:

| Profile | URL | Notes |
|---|---|---|
| `http` | http://localhost:5103 | The usual one |
| `https` | https://localhost:7085 and http://localhost:5103 | Needs the dev certificate (`dotnet dev-certs https --trust`) |
| `IIS Express` | http://localhost:31152 | Windows auth off |

All set `ASPNETCORE_ENVIRONMENT=Development`. `appsettings.Development.json` only adjusts logging.

## Building, formatting and analyzers

```bash
dotnet build                                    # Debug
dotnet build -c Release                         # what CI builds
dotnet list package --vulnerable --include-transitive
```

- Analyzers run at `latest-recommended`; a few noisy rules are suppressed in `Directory.Build.props`.
  **Warnings don't fail the build**, but don't add new ones.
- There's no formatter configuration beyond `.editorconfig` (which only relaxes naming rules for tests). Match
  the surrounding code.
- There's no frontend build: Razor, CSS and JS are served as-is. After changing `app.css` or a script, bump its
  `?v=` in `Components/App.razor`.

## Everyday workflow

1. Pull, run, reproduce in the browser.
2. Find the code with [the codebase map](../architecture/codebase-map.md#where-do-i-find).
3. Make the change in the right layer (rules in the domain, use cases in Application, UI in Web). Follow a
   [recipe](recipes.md) if one fits.
4. Add or extend a test ([testing.md](testing.md)). Anything touching integrity, permissions or need-to-know needs
   a test that would fail if the guarantee broke.
5. If you changed the model, add migrations for **both** providers ([recipes](recipes.md#add-or-change-a-database-column)).
6. `dotnet test`. Check the page in the browser, in light and dark, and at phone width if it's UI.
7. Update the docs ([MAINTAINING-DOCS.md](../MAINTAINING-DOCS.md)) and, for visible UI changes, the screenshots.
8. One commit per change. CI runs on push to `main` and on pull requests (doc-only changes skip CI).

## Debugging

| Situation | Approach |
|---|---|
| A page throws | In Development the error is shown in place (`ErrorFallback`), with details in the console log. Set a breakpoint in the service; Blazor Server runs it in your process. |
| "A second operation was started on this context" | A `DbContext` is shared across awaits or components. Create one per operation from `IAppDbContextFactory`. |
| A button does nothing | Check the browser console for a JS interop error and that the script's `?v=` was bumped. |
| A change doesn't appear for another user | Live refresh is in-process: both tabs must hit the same app instance. |
| Permission refused | The message names the permission. Check `CaseActionPermissions` and the dev user's roles. |
| Audit chain broken in dev | You edited the SQLite file directly, or ran SQL against it. Reset the database. |
| Time looks off by hours | Display is in the profile menu's UTC/Local setting; storage is UTC. |
| Migrations fail at startup | See [troubleshooting](../operations/troubleshooting.md#migration-failures). |

Useful places for breakpoints: `CaseService.Require`, `CaseQueryExtensions.ForUser`,
`AuditChainInterceptor.SavingChangesAsync`, `CaseMilestones.Project`, `StageGateEvaluator.EvaluateAsync`.

## Other tools

- **Screenshots**: `node tools/screenshots/capture.mjs` against a freshly seeded app
  ([tools/screenshots/README.md](../../tools/screenshots/README.md)).
- **MITRE catalog**: [src/IncidentManager.Application/Mitre/README.md](../../src/IncidentManager.Application/Mitre/README.md).
- **Upgrade test**: [testing.md](testing.md#upgrade-path-test).
