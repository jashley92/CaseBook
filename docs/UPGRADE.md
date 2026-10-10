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
SDK and no NuGet access**. The release workflow rebuilds the app from the tagged commit; it doesn't rerun the
tests, so releases are only tagged on commits that passed CI on `main`.

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

It auto-detects the site (default name `CaseBook`), database, and health URL (the site root at its first
HTTPS binding's host name). Override any of them with `-SiteName`, `-SitePath`, `-SqlInstance`, `-DbName`,
`-HealthUrl` if your names differ. Add `-Force` to skip the confirmation prompt for an unattended run.

The script connects to SQL Server **as you** (Windows authentication), so your account needs to read the
CaseBook database and run `BACKUP DATABASE` on the instance. Warm-up counts any 2xx, 401 or 403 from the health
URL as "started"; if the health URL's host name isn't in `AllowedHosts` the site answers 400 and the upgrade
times out and rolls back.

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
| **Upgrade path on real SQL Server** (`tools/upgrade-test/upgrade-path.sh`) | CI (`upgrade-path` job) | Installs each of the 3 newest releases **and the first release (v1.0.0)** into a fresh SQL Server 2022 database (migrated + seeded with demo cases and an audit chain), then starts the new build against the same database. It must come up healthy with every migration applied and every case/audit row intact. |

**Rule for schema changes:** only ever *add* migrations. Never edit, delete, or regenerate one that has
shipped in a tag. To undo or reshape something an old migration created, add a new migration that alters it.

To run the upgrade test locally (Git Bash + Docker Desktop):

```bash
docker run -d --name casebook-sql -e ACCEPT_EULA=Y -e 'MSSQL_SA_PASSWORD=Local!Test2026' -p 14333:1433 mcr.microsoft.com/mssql/server:2022-latest
export CASEBOOK_TEST_SQL='Server=localhost,14333;User Id=sa;Password=Local!Test2026;TrustServerCertificate=True;Encrypt=False'
export SQLCMD='docker exec casebook-sql /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P Local!Test2026'
tools/upgrade-test/upgrade-path.sh v1.0.0          # v1.0.0 -> your working tree
```

The same `CASEBOOK_TEST_SQL` also runs the integration tests that need SQL Server itself (`[SqlServerFact]` tests
and the SQL Server rows of tests that run on both engines; skipped in a plain `dotnet test`). Each creates and drops its own database:

```bash
dotnet test tests/IncidentManager.IntegrationTests --filter "DisplayName~SqlServer"
```

---

## Rollback

The script snapshots the current binaries to `…\casebook-upgrade-backups\<timestamp>\site-rollback\`
and takes a full DB backup to the SQL instance's default backup directory **before** it deploys. If
the new build fails to start, it restores the previous binaries and restarts the pool automatically.

The database is **not** restored automatically. The app applies pending migrations at startup, before it
serves any request, and each migration commits on its own, so a startup failure (500.30) can leave the schema
partly upgraded. Compare `__EFMigrationsHistory` with the release's `migrations-sqlserver.txt`: if new
migrations were recorded, restore the pre-upgrade backup before retrying so schema and binaries match again.

---

## Notes

### v1.5.0

A routine upgrade: one additive migration, applied at startup. Attack steps can now record a time as it was stated, and
`Install-Database.ps1` is fixed.

- **One additive migration** (`AddStepTimePrecision`): three nullable columns on `TimelineEntries`
  (`OccurredPrecision`, `OccurredUntilUtc`, `StepOrder`) so an attack step can record its time as it was stated (a
  date, a range, on or before a date, or not stated) and its place in order. Existing rows keep their exact hashes.
  In `DbaApplies` mode the bundle's `deploy/sql/casebook-schema-sqlserver.sql` includes it.
- **Attack steps whose time wasn't given precisely** print the time as stated, in the Record, the briefing, the case
  report (with a note under the attack chain) and the narrative. A Word template's `{{step.when}}` prints the stated
  wording for such a step, and `{{case.activity_began}}` adds "(approximate)" when it comes from one. Existing steps
  are all exact, so nothing changes until someone records an approximate one.
- **Case import:** an `Event` timeline entry can carry `timePrecision` and `occurredUntilUtc` (see API.md). Existing
  import documents are unaffected.
- **`deploy/Install-Database.ps1`** checks the account's rights before changing anything, stops at the first SQL
  error (it used to report "Created database" after a failed create), and honors `-DbName`, `-SchemaMode` and the
  data/log paths (a `:setvar` default in `01-Create-Database.sql` used to override them). If you installed with
  `DbaApplies` on v1.4.0 or earlier and a non-default database name, check that the app account has `db_owner` on the
  database you meant.

### v1.4.0

A routine upgrade: two additive migrations, applied at startup. The visible changes are the rebuilt Program overview,
how third-party cases record the attack, and new, optional integrity hardening.

- **Two additive migrations.** `AddStepEnvironment`: a nullable `Environment` column on `TimelineEntries`, for where
  a third-party case's attack step happened. `AddAuditHashKeyId`: a nullable `HashKeyId` column on `AuditLog`, for
  the optional audit chain key (empty on every existing row). Existing rows keep their exact hashes. In `DbaApplies`
  mode the bundle's `deploy/sql/casebook-schema-sqlserver.sql` includes both. If you've turned on the SQL Server
  ledger, the new `AuditLog` column is nullable, which ledger tables allow; `02-Enable-Ledger.sql` knows it.
- **Third-party cases** separate the attacker's steps from the disclosure milestones, and an attack step can be in
  our environment after a pivot. Reports of vendor cases now print the disclosure milestones, which earlier releases
  built but left out.
- **Event steps and open questions are one line of inline Markdown**; the box says so under it.
- **The Program overview is rebuilt** around a Needs action list and notification clocks, median timings for a
  chosen period (`/program?period=30d|quarter|12m`, 12 months by default, or a custom `from`/`to` range), a case-activity chart with carry-over and
  closed cases, targets met by severity, phase aging, vendor cases, top techniques and the learning loop. No schema
  change. The red "Needs attention" banner and the origin tiles are gone; the metrics CSV is unchanged.
- **New seals and configuration bundles are signed with RSASSA-PSS** (was RSASSA-PKCS1-v1_5). Nothing to do: the
  same key signs, and seals and bundles made by earlier releases still verify, each by the algorithm it records.
  An examiner checking seals by hand uses the OpenSSL command in the compliance bundle's `VERIFY.txt`, which now
  covers both kinds. A tool that verifies seals outside CaseBook must use PSS (SHA-256, MGF1-SHA256, 32-byte salt)
  for the new ones.
- **Configuration-bundle imports over 64 MB are refused** with a message saying so (earlier releases broke
  the page with an error instead). The import page now states the limit under the file input.
- **Integrity key custody and seal copies** ([ADR 0016](decisions/0016-key-custody-and-seal-copies.md); all optional,
  in server configuration, OPERATIONS.md §2):
  - **Seals now also go to the SIEM** as event **5004** whenever a SIEM transport is on, so a copy is kept that
    CaseBook's administrators can't change. A failed seal copy is event **5005** and shows under *Integrity & audit →
    Keys and seal copies*. Add both to your SIEM rules (OPERATIONS.md §5 has the comparison query).
  - **The signing key can come from the certificate store or CyberArk** (`Integrity:SigningKey`), and retired public
    keys in `Integrity:RetiredPublicKeysPath` keep older seals verifying after a key change.
  - **An optional audit chain key** (`Integrity:ChainKey`, off by default) hashes new audit entries with a secret the
    database doesn't hold. It's one-way in practice: read OPERATIONS.md §2 and back the key up before turning it on.
  - **Optional extra seal copies** (`Integrity:SealCopies`): an email digest, and timestamps from an internal RFC 3161
    authority.
  - The upgrade doesn't add these settings to `appsettings.Production.json`; without them, CaseBook behaves as before
    (signing key from the file, chain key off, no extra copies). Copy the blocks from
    `deploy/appsettings.Production.template.json` when you want them.
- **The compliance bundle's `audit-chain.csv` has three more columns** (`Reason`, `EntityLabel`, `HashKeyId`), so an
  examiner can recompute every entry's hash; earlier bundles omitted the two fields that are hashed when present.
  A tool that reads the CSV by column position needs updating.
- **No required setting changes**, so `appsettings.Production.json` needs no edits to upgrade.

### v1.3.0

The upgrade itself is the usual one: seven migrations, applied at startup. People will notice more. Cases, the
home page and the cross-case pages are redesigned, and several pages have moved.

- **Schema: seven migrations, all additive.** They add the `CaseOutcomes`, `EntityVerdictChanges` and
  `OpenCaseTabs` tables, plus columns for a closed case's outcome, who completed a task, a brief confirmed as
  still accurate, and keyboard-shortcut preferences. Nothing is dropped and no existing record is rewritten. The
  only data changes are the seeded outcomes and the close-gate wording below. None of the seven touches a ledger
  table. In `DbaApplies` mode, `deploy/sql/casebook-schema-sqlserver.sql` in the bundle already includes them.
- **Dev sign-in stops outside Development.** A staging or QA site that runs without `Auth:Mode=Windows`
  signed everyone in with every role; it now refuses to start. Use Windows authentication there, or set
  `Auth:AllowDevSignInOutsideDevelopment=true` on a non-Production test site. Production never allows dev sign-in.
- **History starts at the upgrade.** Tasks completed before it show no "completed by". Verdict changes are
  recorded from the upgrade on, so an entity's earlier verdicts aren't in its history.
- **Closing asks for an outcome.** Closing a case needs an outcome and the closing brief (what happened and the
  conclusion). Six outcomes are seeded on upgrade and can be changed under Administration → Case outcomes. Cases
  closed before the upgrade keep their records unchanged and have no outcome. A task raised from a brief question
  now needs an answer to be marked done. Configuration bundles become schema v4 (they carry the outcomes); older
  bundles still import.
- **The close gate's checks change.** The shipped "Post-incident review complete" attestation becomes the
  "Post-incident review recorded" check (Incidents & Breaches; it was tickable with no review). An advisory
  "Every entity / IOC has a verdict" check is added. A close-gate attestation you worded yourself is left as it
  is; change either under Administration → Stage gates.
- **Pages have moved, with no redirects.** Bookmarks to the old addresses and links in emails sent before the
  upgrade open a "page not found". The sidebar is now Desk, Cases, Find, Intel and Program.

  | Was | Now |
  |---|---|
  | `/my`, `/work` (My work) | `/desk` (the Desk) |
  | `/agenda` | `/program/due` (Due work); your calendar feed link is under Account → Notifications |
  | `/team` | `/program/team` |
  | `/improvement-actions` | `/program/improvement-actions` |
  | `/program-report` | `/program/report` |
  | `/indicators` | `/intel/indicators` |
  | `/campaigns`, `/campaigns/{id}` | `/intel/campaigns`, `/intel/campaigns/{id}` |
  | `/attack-coverage` | `/intel/attack` |

  `/` now opens Program (the leadership dashboard) for roles that see every case, and the Desk for everyone else.
  New pages: `/find`, `/program/legal` (the legal register), `/account/keyboard`. Case addresses (`/cases/{id}`),
  the API and the calendar feed's own URL are unchanged, so integrations and calendar subscriptions keep working.
- **Tell your team before it lands.** A case has five views (Record, Things, Tasks, Briefing and Paper) instead
  of nine tabs. Working notes are a lens on the record, not a tab. Closing is a view of its own. Recently
  opened cases stay as tabs in the top bar. Reports generate in the background with a notice when ready. Single-key
  shortcuts can be changed or turned off under Account → Keyboard shortcuts.

- **Use the upgrade script from the bundle you're installing.** v1.2.1's script reported a false *MIGRATION
  MISMATCH* on every database (fixed in v1.2.2); before v1.2.3 the ASP.NET Core Module check could fail from a
  32-bit PowerShell even when the module was installed. v1.2.4's script adds missing storage settings (below).

- **After v1.2.4, a missing seal-signing key stops startup.** Outside Development the app no longer generates a
  key when `Integrity:SigningKeyPath` points at a missing file; it refuses to start. An existing install already
  has its key file there, so nothing changes unless the file was moved or deleted.

- **v1.2.1 adds a close-gate check.** The upgrade adds "Required regulatory notifications recorded" to every
  close-case stage gate that doesn't already have it, as a blocking check (overridable with a justification, like
  any gate). Closing a case whose notification clock is running with no report time recorded then needs an
  override. Remove or make it non-blocking in Administration → Stage gates if your process differs. The
  dashboard and deadline reminders now also keep watching closed cases until their notification is recorded,
  so older closed cases with an unrecorded notification may appear under "Awaiting report" after the upgrade.

- **v1.2.0 removes case Discussion.** The upgrade drops the `CaseComments` table, so discussion posts are
  deleted. Export any you need to keep before upgrading (for example with a `SELECT` against `CaseComments`).
  Their entries in the audit trail remain and the chain still verifies. @mentions now live on notes.

- The script never changes an existing setting in `appsettings.Production.json`, existing data under the data
  root (evidence / seals / reports / keys), or your IIS site and app pool settings. It does mirror the new
  binaries into the site folder, which **replaces `web.config`** (re-apply any hand edits such as stdout
  logging) and removes other files there that aren't part of the release; they're kept in the rollback
  snapshot. Manual config (e.g. the CyberArk `Secrets`
  block) is preserved. **One addition it does make:** a storage-folder setting a newer release introduced (e.g.
  `ReportTemplates:RootPath`) that your config lacks is added under your data root, with its folder created and
  the data root's permissions, after the config is backed up. Without it, that store falls back to `App_Data` in
  the read-only web root and fails with "Access to the path ... is denied". The data root is worked out from your
  existing paths (or pass `-DataRoot`). A missing `Integrity:SigningKeyPath` stops the upgrade instead, since a new
  location would orphan the seal signing key; other unset settings are listed as warnings.
- If your DB is in `DbaApplies` mode (the app account is **not** `db_owner`), the app cannot apply
  migrations itself — have a DBA apply `deploy/sql/casebook-schema-sqlserver.sql` (idempotent) before
  the first request, then run the upgrade with the app already schema-current.
- Match the runtime: a build targeting .NET 10 needs the **.NET 10 Hosting Bundle** on the server
  (the shared framework, not just the SDK). The preflight checks this and stops with guidance.
- **Sites with the SQL Server ledger on** (OPERATIONS.md §7): upgrades work unchanged. The ledger tables only
  accept new nullable columns, and the build enforces that for every release, so a migration can't fail on
  them. Take a ledger digest (`Export-LedgerDigest.ps1`) before and after the upgrade for your records.
