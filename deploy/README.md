# CaseBook — deploy/

First-install tooling for an on-prem **Windows Server 2022 + IIS + SQL Server 2022** host.
Follow the full runbook in **[../docs/INSTALL.md](../docs/INSTALL.md)** (which includes the
**server sizing specs**); this folder is the toolbox it uses.

| File | Purpose |
|---|---|
| `New-CaseBookConfig.ps1` | **Start here.** Interactive generator — prompts for every value and writes `casebook.config.psd1`. |
| `casebook.config.template.psd1` | Answers-file template to copy/fill by hand instead of running the generator. |
| `Install-Database.ps1` | Provision the SQL DB + app-pool login (Windows auth). Run first, as SQL sysadmin. |
| `Install-CaseBook.ps1` | Publish the app, create the IIS site/app-pool, write prod config, ACL the data dirs. Run as local admin. |
| `Verify-Install.ps1` | Readiness + smoke test: `-ConfigFile` validates the answers file resolves (account/groups/cert/paths/SQL) **before** installing; `-Url` is the post-install smoke test. |
| `appsettings.Production.template.json` | Production config template; the installer substitutes `__PLACEHOLDERS__`. |
| `sql/01-Create-Database.sql` | The DDL the DB installer runs (database, recovery model, login/user, grants). |
| `sql/casebook-schema-sqlserver.sql` | Idempotent full-schema script for DBAs who apply the schema by hand (`-SchemaMode DbaApplies`). |

## Simplest path: one answers file for both installers

Both installers take every setting as **parameters** *or* from a single **`-ConfigFile casebook.config.psd1`**
answers file (a parameter you also pass wins). Generate the file once, copy it to both hosts, and each step is a one-liner:

```powershell
.\New-CaseBookConfig.ps1                                    # prompts -> casebook.config.psd1
.\Verify-Install.ps1  -ConfigFile .\casebook.config.psd1    # readiness check, on each host before its step
.\Install-Database.ps1 -ConfigFile .\casebook.config.psd1   # on the SQL host (sysadmin)
.\Install-CaseBook.ps1 -ConfigFile .\casebook.config.psd1   # on the web host (elevated)
.\Verify-Install.ps1  -Url https://casebook.contoso.com/    # post-install smoke test
```

The answers file holds **no passwords** (a gMSA is passwordless; a normal service account's password is
prompted for at install time). It names AD groups/hosts/account, so treat it as sensitive and don't commit it.

## Two ways the schema gets created

1. **App applies migrations at startup** (default, `-SchemaMode AppMigrates`) — the app account gets
   `db_owner`; on first start `Database.MigrateAsync()` builds/updates the schema from the
   **`IncidentManager.Migrations.SqlServer`** migrations assembly. Simplest; keeps future upgrades automatic.
2. **DBA applies the schema** (`-SchemaMode DbaApplies -ApplySchema`) — the app account gets only
   datareader/datawriter/EXECUTE, and `sql/casebook-schema-sqlserver.sql` creates the schema. Use where
   app identities may not hold DDL rights.

## Dual-provider migrations (dev SQLite / prod SQL Server)

Dev uses **SQLite** (migrations in `src/IncidentManager.Infrastructure/Persistence/Migrations`).
Prod uses **SQL Server**, in a separate assembly so both can coexist:
`src/IncidentManager.Migrations.SqlServer`. The provider is chosen at runtime from
`Database:Provider`; the SQL Server set is bound via `MigrationsAssembly` in
`Infrastructure/DependencyInjection.cs`.

### Regenerate the SQL Server migration / DDL after a model change

```powershell
# From the repo root. The env var flips AppDbContextFactory to the SQL Server provider.
$env:IM_MIGRATIONS_PROVIDER = 'SqlServer'

# 1) add a migration to the SQL Server assembly
dotnet ef migrations add <Name> `
  --project src/IncidentManager.Migrations.SqlServer `
  --startup-project src/IncidentManager.Web --context AppDbContext

# 2) refresh the DBA schema script
dotnet ef migrations script --idempotent `
  --project src/IncidentManager.Migrations.SqlServer `
  --startup-project src/IncidentManager.Web --context AppDbContext `
  --output deploy/sql/casebook-schema-sqlserver.sql

Remove-Item Env:\IM_MIGRATIONS_PROVIDER
```

Add the matching SQLite migration the normal way (no env var) so dev and prod stay in step.
