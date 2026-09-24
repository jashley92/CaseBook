# CaseBook — Upgrading an existing deployment

How to move a running production instance to a newer build. For a first install see
**[INSTALL.md](INSTALL.md)**; for backup/DR and key handling see **[OPERATIONS.md](OPERATIONS.md)**.

> Development needs none of this — `git pull` and `dotnet run` against SQLite.

---

## How releases ship

Each version tag (`vX.Y.Z`) builds a **release bundle** attached to the matching
[GitHub Release](https://github.com/jashley92/CaseBook/releases): `casebook-<version>.zip` plus a
`.sha256`. The bundle contains the published app (`app/`), the deploy scripts (`deploy/`), a
migration manifest, and a `VERSION.txt`. Deploying from the bundle means **the server needs no .NET
SDK and no NuGet access** — the exact tested binaries are already built.

You can still build from source on a box that has the .NET 10 SDK (`-Build`), but the bundle is the
recommended path.

---

## The upgrade (happy path)

`deploy/Upgrade-CaseBook.ps1` does the whole thing safely: it resolves the live deployment from IIS
and `appsettings.Production.json`, preflights (including a **migration-compatibility check**), backs
up the DB + config + current binaries, swaps in the new binaries **without touching your config or
data root**, and warms the app so pending EF migrations apply — rolling back automatically if the
new build fails to start.

On the web host, **elevated**:

```powershell
# 1. Download casebook-<version>.zip from the GitHub Release and (optionally) verify it:
#    Get-FileHash .\casebook-<version>.zip -Algorithm SHA256   # compare to the .sha256

# 2. Run the upgrade from the version-matched script inside the bundle, or the repo's deploy folder:
.\Upgrade-CaseBook.ps1 -BundleZip .\casebook-<version>.zip
```

It auto-detects the site (default name `CaseBook`), database, and health URL. Override any of them
with `-SiteName`, `-SitePath`, `-SqlInstance`, `-DbName`, `-HealthUrl` if your names differ. Add
`-Force` to skip the confirmation prompt for an unattended run.

Alternatives to `-BundleZip`:
- `-AppSource <folder>` — a folder that already holds the published app.
- `-Build` — publish from this repo (needs the .NET 10 SDK on the host).

When it finishes: sign in, open **Integrity -> "Verify now"** (chain should read **VALID**), and
confirm a case opens and a report generates.

---

## The migration-compatibility preflight (why an old instance can fail to start)

CaseBook builds its schema with EF Core migrations. If the database's recorded migration history
(`__EFMigrationsHistory`) does not line up with the migration set in the new build, the app tries to
**recreate tables that already exist** and fails on startup with:

> `HTTP Error 500.30` … `There is already an object named 'AdGroupRoleMappings' in the database.`

This happens when the deployed version predates a change in the migration lineage (e.g. migrations
were regenerated between releases). It happened once, for real: before the repo went public (2026-09-09) the
13 SQL Server migrations `20260815005408_InitialCreate` … `20260909191659_X06GateCommentary` were squashed
into a single regenerated `20260909194827_InitialCreate`, so every database created before that could not
upgrade. CI now prevents a repeat (see [How upgrades stay safe](#how-upgrades-stay-safe-across-releases)).
The upgrade script **detects this before deploying** by comparing
the DB's applied migrations against the release manifest, and stops with a clear message instead of
leaving you with a dead site. You will see one of:

- **Schema present but no matching history** — the DB has tables but no (or unrelated) migration
  history for this release.
- **Different / newer lineage** — the DB records migrations this build does not contain.
- **Initial migration missing** — this build's baseline migration isn't in the DB's history.

### Resolving a mismatch

Pick based on whether you need the existing data:

**A. Keep the data — reconcile the history.** Restore the production DB to a **test** SQL instance,
work out the correct `__EFMigrationsHistory` baseline there (mark the already-present migrations as
applied so only the genuinely-new ones run), verify the app starts and the chain is VALID, then apply
the same reconciliation to production. Do this on a copy first — never experiment on the live DB.

**B. Discard the data — reset the database.** If the instance is disposable (e.g. a lab, or a
pre-production instance with no records worth keeping), drop all objects and let the app rebuild the
schema cleanly. With the app pool stopped, as a `db_owner`/sysadmin on the CaseBook database:

```sql
USE [CaseBook];
GO
DECLARE @sql NVARCHAR(MAX) = N'';
SELECT @sql += N'ALTER TABLE ' + QUOTENAME(SCHEMA_NAME(t.schema_id)) + N'.' + QUOTENAME(t.name)
             + N' DROP CONSTRAINT ' + QUOTENAME(fk.name) + N';' + CHAR(10)
FROM sys.foreign_keys fk JOIN sys.tables t ON fk.parent_object_id = t.object_id;
EXEC sp_executesql @sql;
SET @sql = N'';
SELECT @sql += N'DROP TABLE ' + QUOTENAME(SCHEMA_NAME(schema_id)) + N'.' + QUOTENAME(name) + N';' + CHAR(10)
FROM sys.tables;
EXEC sp_executesql @sql;
GO
```

Then start the app pool and browse to the site — the app migrates into the empty database and starts
clean. (Dropping the tables needs only `db_owner`; it avoids the sysadmin-only `DROP DATABASE` and the
single-user lock.)

---

## How upgrades stay safe across releases

Any release can upgrade in place to any later release (v1.0.0 → v1.4.0 directly, no stepping stones):
EF applies whichever migrations the database hasn't seen yet. That only works while the migration
lineage stays stable, so these checks enforce it on every push and before every release:

| Guard | Where | What it catches |
|---|---|---|
| **Released migrations are immutable** (`tools/ci/check-migrations-immutable.sh`) | CI + Release | A migration that shipped in any `v*` tag was edited, deleted, renamed, regenerated, or squashed, which would strand every database installed from that release. |
| **No un-migrated model changes** (`dotnet ef migrations has-pending-model-changes`, both providers) | CI | Someone changed the model without adding a migration. EF refuses to `Migrate()` in that state, so the upgraded app would fail to start. |
| **Upgrade path on real SQL Server** (`tools/upgrade-test/upgrade-path.sh`) | CI (`upgrade-path` job) | Installs each of the 3 newest releases into a fresh SQL Server 2022 database (migrated + seeded with demo cases and an audit chain), then starts the new build against the same database. It must come up healthy with every migration applied and every case/audit row intact. |

**Rule for schema changes:** only ever *add* migrations. Never edit, delete, or regenerate one that has
shipped in a tag. To undo or reshape something an old migration created, add a new migration that alters it.

To run the upgrade test locally (Git Bash + Docker Desktop):

```bash
docker run -d --name casebook-sql -e ACCEPT_EULA=Y -e 'MSSQL_SA_PASSWORD=Local!Test2026' -p 14333:1433 mcr.microsoft.com/mssql/server:2022-latest
export CASEBOOK_TEST_SQL='Server=localhost,14333;User Id=sa;Password=Local!Test2026;TrustServerCertificate=True;Encrypt=False'
export SQLCMD='docker exec casebook-sql /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P Local!Test2026'
tools/upgrade-test/upgrade-path.sh v1.0.0          # v1.0.0 -> your working tree
```

---

## Rollback

The script snapshots the current binaries to `…\casebook-upgrade-backups\<timestamp>\site-rollback\`
and takes a full DB backup to the SQL instance's default backup directory **before** it deploys. If
the new build fails to start, it restores the previous binaries and restarts the pool automatically.

If a failed upgrade had already begun applying migrations, restore that DB backup before retrying so
the schema and binaries match again. A 500.30 on startup means migrations almost certainly did **not**
run (the app never reached that point), so the DB is usually untouched — but the backup is there if
you need it.

---

## Notes

- The script never rewrites `appsettings.Production.json`, the data root (evidence / seals / reports /
  keys), or your IIS configuration. Manual config (e.g. the CyberArk `Secrets` block) is preserved.
- If your DB is in `DbaApplies` mode (the app account is **not** `db_owner`), the app cannot apply
  migrations itself — have a DBA apply `deploy/sql/casebook-schema-sqlserver.sql` (idempotent) before
  the first request, then run the upgrade with the app already schema-current.
- Match the runtime: a build targeting .NET 10 needs the **.NET 10 Hosting Bundle** on the server
  (the shared framework, not just the SDK). The preflight checks this and stops with guidance.
