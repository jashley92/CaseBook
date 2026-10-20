# CaseBook — Upgrading an existing deployment

How to move a running production instance to a newer build. For a first install see
**[INSTALL.md](INSTALL.md)**; for backup/DR and key handling see **[OPERATIONS.md](OPERATIONS.md)**.

> Development needs none of this — `git pull` and `dotnet run` against SQLite.

---

## How releases ship

Each version tag (`vX.Y.Z`) builds a **release bundle** attached to the matching
[GitHub Release](https://github.com/jashley92/CaseBook/releases): `casebook-<version>.zip` plus a
`.sha256`. The bundle contains the published app (`app/`), the deploy scripts (`deploy/`), a
migration manifest, and a `VERSION.txt`. The release's description is the version's section of [Notes](#notes) below, and
from v1.6.0 the version is stamped into the app (Administration › Diagnostics shows it). Deploying from the bundle means **the server needs no .NET
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
new build fails to start. In IIS it changes only what a newer release needs and an older site lacks: the app pool's
recycle settings and the anonymous carve-outs (`/api`, `/health`, `/branding/logo`, `/agenda/feed.ics`), each checked
first and set only when it differs.

On the web host, **elevated**:

```powershell
# From v1.6.0: one command. The script downloads the release bundle and its .sha256 from GitHub itself, refuses a
# bundle whose hash doesn't match, and hands over to the upgrade script inside that bundle (from v1.6.3), so the
# upgrade always runs with the new release's own logic. Start it from the copy of the deploy scripts each upgrade keeps
# beside the site (<site parent>\<site folder>-deploy, e.g. C:\inetpub\CaseBook-deploy); Administration › Updates shows
# the exact line, with -SiteName when it knows the site.
& 'C:\inetpub\CaseBook-deploy\Upgrade-CaseBook.ps1' -Version v1.6.3      # or -Version latest; -Proxy <url> if needed

# Without outbound internet, or the first time (before v1.6.0 there's no kept copy):
# 1. Download casebook-<version>.zip from the GitHub Release and verify it:
#    Get-FileHash .\casebook-<version>.zip -Algorithm SHA256   # compare to the .sha256
# 2. Run the upgrade from the version-matched script inside the bundle:
.\Upgrade-CaseBook.ps1 -BundleZip .\casebook-<version>.zip
```

It auto-detects the site (default name `CaseBook`), database, and health URL (the site root at its first
HTTPS binding's host name). Override any of them with `-SiteName`, `-SitePath`, `-SqlInstance`, `-DbName`,
`-HealthUrl` if your names differ. Add `-Force` to skip the confirmation prompt for an unattended run.

The script connects to SQL Server **as you** (Windows authentication), so your account needs to read the
CaseBook database and run `BACKUP DATABASE` on the instance. Warm-up counts only CaseBook's own answer as "started":
a 200 with the JSON import schema from `<site>/api/import/cases/schema` (anonymous at the IIS level). A 5xx is a failed
start and rolls back. When IIS answers `/api` itself (401/403, or its own 404 page), the script says so and checks the
site root signed in as you instead. If the health URL's host name isn't in `AllowedHosts` the site answers 400 and the
upgrade times out and rolls back.

Alternatives to `-Version` and `-BundleZip`:
- `-AppSource <folder>` — a folder that already holds the published app.
- `-Build` — publish from this repo (needs the .NET 10 SDK on the host).

The hash check proves the bundle is the one published on the release, not who published it: the zip and its `.sha256`
come from the same GitHub release. Upgrade from the repository you trust, and read the release's notes first.

After an upgrade the site's `VERSION.txt` records the version, the version it replaced, when and by whom; Administration
› Updates shows that line. The kept scripts folder (`<site folder>-deploy`, holding the scripts and `site.txt` with the
IIS site's name) is writable only by Administrators and SYSTEM, so the app-pool account can read the scripts but never
change what an administrator later runs elevated. Each site has its own, so two sites under one parent don't share it.

When it finishes: sign in, open **Integrity -> "Verify now"** (chain should read **VALID**), and
confirm a case opens and a report generates.

---

## Knowing when a release is out (update check)

Administration › **Updates** can check GitHub for releases newer than the running one and list each of them with its
notes (every release between yours and the latest, since upgrades skip versions), plus the one command that upgrades.
A dot beside **Administration** in the sidebar shows when one is waiting. It's **off by default**:

- Turn on **Check for new releases** there (`Updates:CheckEnabled`); it checks a couple of minutes after start, then every
  `Updates:CheckIntervalHours` (default 24), or now with **Check now**.
- It's one anonymous `GET https://api.github.com/repos/jashley92/CaseBook/releases`: no token, and nothing about the
  installation is sent. The web host needs outbound HTTPS to `api.github.com`; the `-Version` upgrade also needs
  `github.com` and `objects.githubusercontent.com`. Behind a proxy, set `Updates:Proxy` in `appsettings.Production.json`
  (read at start-up) and pass `-Proxy` to the script.
- A failure (no route, a proxy refusal, GitHub rate-limiting) shows as "Couldn't check" with the reason, and is logged
  once until the reason changes. It never blocks a page or start-up.
- A local build (no release version) never checks.

The app only shows the command. It can't upgrade itself: its app-pool account can't write its own binaries, by design.

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
When the script sees that the new build recorded migrations, it restores the previous binaries but leaves the app
pool **stopped** until you've restored the backup.

Never roll back the binaries alone over a database a newer build has run against. From v1.5.2 on, row hashes and
seals are written in formats earlier builds don't read, so an earlier build reports them as tampered (critical log,
SIEM event, alarm email, banner), and a migration's `Down()` can't always undo one (a wider column holding longer
values). Restore the pre-upgrade database backup together with the previous binaries.

With evidence encryption on (v1.7.0), earlier builds can't read encrypted evidence or reports either: a rollback
after files were encrypted also needs the evidence and report stores from before the upgrade, or the files exported
first with `casebook-keytool export`.

---

## Notes

### v1.12.0

No migration. One new setting, `BackupStatus:LogBackupMaxAgeMinutes` (60). **Backups you can take, and prove, with the release's own scripts** (in `deploy\`;
OPERATIONS.md §1 has the procedures and a flow chart):

- **`Backup-CaseBook.ps1`** backs up the database (with checksums, then read back) and the folders that go with it as one
  set, with evidence in a mirror the sets share, and records it for Diagnostics. `-Register` makes it a nightly task.
  For a server without a backup product. It also takes **log backups** (`-Log`, every 15 minutes with `-Register`):
  the database is in the FULL recovery model, and without them its log grows until the disk is full. If you've had no
  log backups so far, check the log's size: after the first one, `DBCC SHRINKFILE` can give the space back.
- **`Update-CaseBookBackupStatus.ps1`**, for a server a backup product backs up: records the product's latest backup
  from SQL Server's own backup history. It takes no backup, so the product's chain is untouched.
- **`Test-CaseBookRestore.ps1`**, the monthly restore drill: restores a backup set (or checks a copy your product
  restored) into a scratch copy, runs DBCC CHECKDB and the new **`casebook-keytool verify-restore`** (the audit chain, every
  seal, every evidence file present and a sample re-hashed, the evidence key), and records the restore as verified only
  when everything passes.
- **Diagnostics** shows which backup set, its size and what recorded it, the drill's findings, and **Failed** with the
  reason when a backup or drill fails after the last success; *Needs attention* lists it.

To use them, set `BackupStatus:FilePath` (the installer sets it to `<DataRoot>\ops\casebook-backup-status.json`), then
follow OPERATIONS.md §1.1 and §1.3. Nothing runs until you schedule it.

### v1.11.1

A fix to v1.11.0, with no migration and no setting changes.

- **Administration search results opened from a settings page broke the page** ("Something went wrong. Reload the page
  to continue."), and so did a command palette (Ctrl+K) entry opened from one. They open the page now.
- **The rail's search results showed behind the page** beside it. They open over it now.

### v1.11.0

No migration and no setting changes: every setting keeps its key and value. **Administration is rearranged** so things
are where you'd look for them, and it tells you more:

- **An overview** opens Administration: *Needs attention* lists every problem the checks, deliveries, scheduled jobs,
  backups, keys and integrity checks found, worst first, each with a link to where it's fixed (Diagnostics opens with
  the same list), and a new install's *Getting started* steps.
- **Search** on the overview, at the top of the rail and in Ctrl+K finds a setting by its label, key, help text or an
  everyday word ("upload size", "timeout"), and opens it on its page, highlighted.
- **The rail is grouped by task.** *Governance & security* is gone: its settings are now under **Records & evidence**
  (Evidence storage, Retention with the retention review on the same page, Integrity) and **People & access** (Security
  & access logging). The taxonomy labels and severity labels share a page; the Notifications page has three cards
  (email delivery, email notifications, team chat); Search mode has a rail entry; the style guide shows in Development
  only. Old links and bookmarks land on the new pages.
- **Feedback while you edit:** a value that breaks its rules is said under it as you type and holds Save; a setting
  that waits for a background job or a new sign-in says so; each changed setting shows who changed it and when; a save
  says what changed. Settings only the server's configuration sets are shown read-only where they're used ("Set on the
  host"), and the SIEM webhook token moves to Integrations, beside the SIEM status.
- **Diagnostics** is in order: needs attention, service health, storage and keys, capacity, about this server. The
  *Feature flags* table, which repeated settings, is gone. Its *Seal signing key* check now reports the key in force: a
  key in the certificate store or CyberArk used to read as missing. A list setting in the server's settings file with a
  bad entry (a distribution list's address) is now caught by *Settings within limits*.
- **An upload refused by a limit** names it, and an administrator gets a *Change the limit* link to it.

### v1.10.3

A small release with no migration and no setting changes.

- **Clearer key instructions.** OPERATIONS.md §2 now says where the seal-signing key can live (and that a DPAPI key
  file and cloud key services aren't options), how to set up each with exact commands, and how to move from one to
  another. The evidence key section explains what the server certificate and the recovery certificates each do, with
  flow charts, numbered steps, and an offline copy of the envelope for each custodian.
- **New `casebook-keytool` commands** for what Windows PowerShell 5.1 can't do: `new-signing-key` (make a PEM key and
  its public half), `signing-key-pfx` (put an existing PEM key in a PFX for the certificate store, keeping its key id)
  and `signing-public-key` (write a key's public half for the retired keys folder).
- **Installer:** with evidence encryption and `EvidenceKeyThumbprint` set, it now grants the app account read on that
  certificate's private key, as it does for the signing and chain-key certificates. An install that set one by hand
  needs nothing.

### v1.10.2

A small release with no migration. **The upgrade now adds server-side settings your `appsettings.Production.json` is
missing**, so you can see and set them there: evidence encryption (`Storage:Encryption`), the signing and chain key
sources, seal copies, trusted bundle keys, CyberArk, the SIEM transports, the chat webhook, the update check's repository
and proxy, `Agenda:FeedKey`, download rate limits, the backup-age thresholds and the SMTP connection settings.

- Each is added at the value the app already uses without it, so **nothing changes until you edit one**. Settings
  already in the file are never changed, and in-app settings and the secrets entered in Administration aren't added.
- The preflight lists the sections it will add. The file is backed up first, as for the data-folder settings.
- The upgrade rewrites the file to add them, so its layout (indenting and spacing) changes; the values don't.
- Fresh installs get the same sections from the installer.

### v1.10.1

A small maintenance release with no migration and no setting changes. Upgrade as usual with `Upgrade-CaseBook.ps1`.

- **Evidence package download:** the zip is now written with asynchronous calls throughout, so a large package no longer
  holds a server thread while it streams. The package, its encryption and its recorded SHA-256 are unchanged.
- **Report integrity check:** releases its working copy asynchronously. No visible change.
- **Dependencies:** FluentValidation 12.2.0, and (for builds and tests only) dotnet-ef 10.0.13, Microsoft.NET.Test.Sdk
  18.11.0 and xunit.runner.visualstudio 4.0.1.

### v1.10.0

A large release: everything below lands at once. Eight migrations, applied on first start: `StoredSecrets`, `NoticeDetails`,
`EvidenceCollection`, `EvidenceWithdrawal`, `HandoffRecipient`, `AddCaseParties`, `AddTeams` and `FullTextSearch`
(its indexes only where SQL Server has Full-Text Search; a no-op on SQLite). DBA-applied installs run the
regenerated `deploy/sql/casebook-schema-sqlserver.sql`. Run `Upgrade-CaseBook.ps1` as usual: it now also checks and sets
the IIS anonymous carve-outs. **Tell the SOC** about the new SIEM events (5308, 5516) and the changed 5513 sequence; **back
up the Data Protection key folder** with the database (in-app secrets depend on it); and **fill in your organization's
domains** under Integrations if the server isn't on the domain. Things to check:

- **Per-jurisdiction notification clocks (CAP-38).** Each regulator's clock stops only at a notice recorded for it, and
  a case counts as reported only when every jurisdiction in play has one. Until then the case page, Briefing, report
  and legal register say **"Partly reported: NY notified …, CA due …"** instead of a single "Reported", and CA's clock,
  reminders, close-gate check and archive block keep running. Every view reads this one standing (`NoticeStanding`)
  rather than the stored reported time, so they can't disagree. *Mark reported* records a notice for each regulator in
  play not yet notified (each its own stop; it never stamps one time over a running clock); with nothing in play it
  records the case's time alone, as before. **Existing cases are read in place, not rewritten:** a case reported
  before notices were per jurisdiction (a reported time and no notice rows) counts each jurisdiction that was in play
  when it was reported (the kept `ReportedJurisdictions`, back-filled at start-up as before) as notified at that time,
  so it shows no overdue clock and sends no reminder; no notice rows are created, no hashed row changes, and the
  integrity check is unaffected. Other visible changes: the legal register CSV gains a last column,
  `notification_status`, and `reported_to_regulators_utc` is filled only for fully reported cases (a reader of columns
  by position is unaffected); the report's Business Impact adds the standing line, with template field
  `case.notification_standing`; a single notice on a partly reported case is its own "Notified NY" milestone; and
  SIEM 5513 sends `CaseReported` when the last regulator's notice is recorded (as well as that notice's
  `RegulatorNoticeRecorded`), and *Mark reported* sends one `RegulatorNoticeRecorded` per notice it records before
  its `CaseReported`. No migration and nothing to configure.
- **Per-jurisdiction clocks, review fixes (CAP-38).** *Mark reported* now names the regulators it will record ("Records
  a notice to CA, TX.") and records only those: if the set changed after the form opened (a colleague added an element
  that brings a regulator in, or removed a notice) the save is refused, the time typed stays, and the form shows who is
  owed now. The report's "Reported to regulators" stamp, `case.reported`, the timeline's reported milestone, the
  brief's and handoff's "since", the review's narrative draft and the Cases list CSV's `reported_utc` now read the same
  standing as the "Partly reported" line, so a reported time stored over a clock still running (an older build, a
  restore, a hand edit) no longer prints "Reported" there. SIEM 5513 `CaseReported` is now sent whenever a case becomes
  fully reported, also when the element that brought in the last regulator owed is removed, or a data element's
  jurisdictions change (the Data elements page or a configuration import); *Mark reported* that records nothing sends
  nothing. A case with too many data elements to keep beside its regulators is judged the same way by an impact edit as
  by every view (every element counts as had), so the edit can no longer blank its reported time while the clocks say
  reported. The dashboard's mean time to report, the program report's figures and period history still read the stored
  reported time and the audit trail as before. No migration and nothing to configure.
- **Teams, review fixes (CAP-36).** Retiring or restoring a team while editing it on the Teams page no longer makes the
  open edit unsaveable (and a save refused over a colleague's change can be saved again deliberately); giving a case a
  team, or filing a new case on one, checks the team is active inside the same gate a retire takes; team membership is matched ignoring case when a
  view is shared or listed (it was case-sensitive on SQLite); and **Program › Improvement actions** gains a team
  picker (`?team=`), which its CSV and the Program overview's link and tabs carry. Nothing to configure.
- **Full-text search on SQL Server, optional (CAP-22).** Where the SQL Server instance has the Full-Text Search
  feature, Find and the case-list search match words from full-text indexes instead of reading every row, so the
  command bar stays fast on a large database. A word then matches the words that **start with** it (`lsa` finds
  "LSASS", `sass` no longer does); indicators, case numbers and entities still match anywhere in the text, and without
  the feature everything searches by substring as before. The upgrade adds the migration `FullTextSearch` (SQL Server:
  catalog `CaseBookText` and indexes on the case, brief, record entry, note, task, task comment and evidence description text, made
  only when the instance has the feature and outside a transaction; SQLite: nothing). Indexes fill in the background
  after the upgrade, and search uses them once they're filled. Nothing to configure. **Administration › Diagnostics**
  shows a *Search* row with the mode; if the feature is added later, *Create full-text indexes* there (the app account
  needs `db_owner`), or in `DbaApplies` mode have the DBA run the new `deploy\sql\03-Enable-FullText.sql`.
  `Verify-Install.ps1` now reports whether the instance has the feature (information only). A future migration that
  alters one of the indexed columns must take it out of the full-text index first (docs/OPERATIONS.md §9).
- **Fixes from the CAP-22 and CAP-28 review.**
  - **Search by word and joined words.** SQL Server's word breaker keeps a word joined by `_` or `-` whole, so with
    full-text on, `dump` stopped finding the evidence file `lsass_dump.dmp`, `backup` the note text `svc_backup` and
    `mail` the text `e-mail`. Evidence file names are no longer full-text indexed (the unreleased `FullTextSearch`
    migration and `deploy\sql\03-Enable-FullText.sql` changed in place) and match anywhere again. In the other free
    text the part after the join still isn't a word by itself; that is documented (docs/workflows/find.md, OPERATIONS
    §9), and the new in-app setting **Search › How search matches words** (`Search:Mode`: `Auto`, the default, or
    `Substring`) turns full-text off for a site that needs it, at the cost of a scan per search. Diagnostics' *Search*
    row says when it's off, and now names a column with no index (and offers *Create full-text indexes*) even while the
    rest are still filling. A search cancelled during the full-text check no longer leaves search on substring for a
    minute, and a full-text failure during a check always has the next search check again.
  - **Related-indicator exclusions.** A list written as one string in a settings file or an environment variable
    (`RelatedIndicators__ExcludedRanges="10.0.0.0/8, ..."`) no longer beats the list saved in Administration, or a
    saved blank; an empty JSON array (`[]`) now means none rather than the default. IPv4 parts are read as decimal: a
    range or indicator written zero-padded (`010.0.0.0/8`, `192.168.010.000/24`, `010.0.0.1`) was read as octal
    (8.0.0.0/8, 192.168.8.0/24, 8.0.0.1), and now means 10.0.0.0/8, 192.168.10.0/24 and 10.0.0.1; a hex part
    (`0x0A.0.0.0/8`) is refused, and an indicator written so isn't read as an address. An IPv4-mapped range
    (`::ffff:10.0.0.0/104`) is stored as its IPv4 range, so it matches IPv4 indicators. A range a settings file gives
    in a form now refused is skipped and listed by Diagnostics as an invalid setting, as before. A URL's IPv4 host is
    read the same way (`http://010.0.0.5/x` is on 10.0.0.5, so a range covering 10.0.0.0/8 leaves it out, and
    `http://0x0a.0.0.5/` has no address to relate by); an address stored zero-padded (`010.0.0.9`) is now found from its
    canonical neighbours (`10.0.0.5`) as well as the other way round. An IPv6 address with a zone ID
    (`fe80::1%eth0.5`, `::ffff:1.2.3.4%3`) is read as an address again, as before this change. A value stored as written
    before this change (an IP `::ffff:010.0.0.1`, which now reads as 10.0.0.1) is still found by Find and by adding it
    again, and editing only its verdict or label no longer rewrites it. No migration.

- **An owning team on each case (CAP-36).** One migration, `AddTeams` (both providers): new `Teams` and `TeamMembers`
  tables, and a nullable `TeamId` on `Cases` and on `SavedViews` (both indexed); no data moves and no case gets a team.
  Administration › Workflow & taxonomy › **Teams** adds, renames, retires and restores teams, sets who is in each, an
  optional detection-source label and link template, and an optional chat webhook URL of the team's own (encrypted
  like the CAP-40 secrets; never shown again). A case's team is chosen on the New case form (a member of one team has
  it chosen), on the case record (*Change*), or by a v2 import's new `newCase.team` (by key or name; the schema stays
  v2). Chat posts about a team's case go to its webhook when it has one, else to the shared channel, as before; a scan's
  summary is posted once per channel. Cases, Find (`team:`), Program and Team workload gain a team filter (`team=` in
  the URL, carried by saved views and the CSV exports), applied after need-to-know: **a team never changes who can see a
  case.** A saved view can be shared with one of your teams. The cases CSV gains a last column, `team`. The case's team
  is in its row hash only when set (canonical format 5), so no existing hash changes. The configuration bundle moves to
  schema v5 and carries the teams (key, name, active, detection label and link), never their members or webhook URL;
  older bundles import as before. SIEM 5405 has a new target type, `Team`. Nothing to configure.

- **Fixes from the regression review (CAP-28, CAP-35, BUG-341).** Possibly related indicators now also find addresses
  not stored in canonical form: an IPv6 address in a URL written with leading zeros (`[2001:0db8:…]`), and an IP address
  recorded before v1.5.3 as IPv4-mapped (`::ffff:203.0.113.9`) or written out in full. An import apply whose release
  back to the queue failed can be retried from the same page once its claim is 30 minutes old, rather than being
  refused as stale. *Confirm all from this submitter* reports a submission it can't preview (unreadable saved
  progress) or claim, puts back a claim it took, and carries on with the rest. Pasting two or more screenshots into the
  Evidence tab stages the first and says so, instead of dropping the connection; every file picker reads only the
  first file however many arrive. No migration and nothing to configure.

- **Possibly related indicators (CAP-28).** The entity panel and the New case form's indicator check now also list
  indicators on other cases you can see that share a registrable domain, a /24 (or /48) or an email domain, clearly
  labelled as suggestions. Nothing is linked and gates and the Desk are unchanged. No migration; the registrable
  domain is a built-in approximation (no Public Suffix List is downloaded). Each shared part reads the newest 500
  candidates; when that limit is reached, the panel says only the newest 500 were checked. Under Administration ›
  Integrations › Related indicators, **your organization's domains** keep internal accounts and hosts from being
  suggested across cases. Until you save them, the organization's own domains found on the server's network are used:
  the AD domain it's joined to, its forest root and the forest's other domains, looked up once in the background after
  start-up (5 s limit), shown beside the field with their source, never stored and never exported in a config bundle.
  Trusted partners' domains are found too but only offered: **Use these** fills the field with all of them for you to
  review and save, and a saved value (blank included) always wins. A server not on a domain
  finds none (Diagnostics says why), so enter them yourself; **excluded address ranges** default to the
  private, loopback, link-local and unique local ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`,
  `169.254.0.0/16`, `::1/128`, `fe80::/10`, `fc00::/7`), editable; and free mail addresses stay left out unless you turn
  that off. What's left out is never suggested and suggests nothing, and the panel says why. The three settings travel
  in the config bundle and apply without a restart.
- **The note box takes any file, not only screenshots (CAP-26).** Paste a file, or drop one on the timeline composer,
  and it's stored as evidence with the entry and cited by it ("Evidence: file.csv"), checked as an Evidence tab upload
  is before anything is stored (the same file already on the case is refused). Up to 50 MB, or the evidence limit if
  lower; larger files still go through the Evidence tab. Pasted PNG, JPEG, GIF and WebP images (by their bytes) work
  as before; any other image (SVG, HEIC, TIFF) is attached as a cited file. A drop of many files takes the first. A file
  can't be attached to an entry being edited (the composer says so). No migration and nothing to configure.
- **Vendors are picked from a list, with their history (CAP-24).** On a third-party case, the New case form's vendor name
  offers the vendors on cases you can see, and a known one shows *Seen before*: how many earlier cases, how the last
  closed one ended, and a link to the case list filtered to that vendor (`?vendor=`, a new filter that saved views and
  the CSV export carry too). The name stays free text, so nothing existing changes. No migration and nothing to
  configure.
- **Indicators page through, and export, instead of stopping at 300 (CAP-27).** Intel › Indicators shows 300 a page
  with *Previous* and *Next*, paged by the row a page ends at, so indicators recorded meanwhile don't repeat or push
  others out of sight. *Export CSV* (`/export/indicators.csv`) downloads every indicator the filters match, of every
  verdict, with case and open-case counts and each case's number and verdict there, up to 50,000 (a cut file says so
  at the top and the end); a restricted case's occurrences stay out, as on the page. A search isn't put in the link:
  it's held for you for an hour, as the Cases export does. Recorded in the access log and as SIEM 5304, like every
  export. No migration and nothing to configure. The order now breaks ties between equally shared, equally recent
  indicators by value and type, so a few rows may sit in a different order than before.
- **Decided imports' stored documents are cleared after 90 days (CAP-31).** New setting
  `Retention:DecidedImportDays` (Administration › Retention, default **90**; `0` keeps every document). Nightly, as a
  second step of the access-log retention job, an import applied or rejected longer ago than that loses the JSON it
  was sent with (up to 5 MB each) and any saved part-way preview; who sent it, who decided, when, why and the case it
  went into stay, and the API's status call answers as before. Imports waiting for review or being applied are
  untouched. **On the first night after upgrading, and at the first start, documents of imports decided more than 90
  days ago are cleared**, recorded as one audit-trail entry. No migration. To keep them, set
  `"Retention": { "DecidedImportDays": 0 }` in `appsettings.Production.json` (or change it in Administration) before
  upgrading.
- **Audit and access-log CSVs stream, up to 1,000,000 rows (CAP-32).** `/export/audit.csv`, `/export/case-audit.csv`
  and `/export/access-log.csv` are written to the browser as they're read instead of built in memory, so the bound
  rises from 100,000 rows to 1,000,000 (what one spreadsheet sheet opens). A cut file says so on its second line and
  its last (the access-log CSV used to say it only at the top). A very long export stops after 15 minutes plus a
  second per 1,000 rows: its last line says the file is incomplete and the download shows as failed; narrow the range.
  The access log and SIEM 5304 entry are now written as the download begins. Scoping, permissions and the downloads
  rate limit are unchanged. No migration and nothing to configure. An export holds a database connection while it
  downloads; with read-committed snapshot on (the installer sets it) it doesn't hold up other work.
- **Historical and closed cases import, and a batch confirm (CAP-35).** No migration. The case-import schema is now v2
  (`docs/case-import.schema.json`, `GET /api/import/cases/schema`; `$id` `urn:casebook:schema:case-import:v2`):
  `schemaVersion` is 1 or 2, and v1 documents (the XSIAM script's included) are read exactly as before. v2 lets a new
  case carry its phase `history`, `outcome`, `conclusion`, `incidentCommander` and `assignments`; the API now refuses
  (400) a v2 history that's out of order, in the future or before detection. A producer validating against the
  published schema with `"const": 1` for `schemaVersion` should accept 2 as well. The Import queue gains *Confirm all
  from &lt;submitter&gt;…* (up to 25 at a time, each applied as its own confirm under the reviewer's name; SIEM 5515 per case).
  Nothing to configure.
- **Imported histories: checked as applying checks them, and batch confirm tightened (CAP-35 review).** No migration and
  nothing to configure. A v2 history is now replayed through the phase change's own checks before anything is written,
  so a `containedAt` or `resolvedAt` in the future, before detection, after its step or out of order (and the REV-11
  case, a step to PostIncident after a Containment that followed "not needed", which must give `resolvedAt` again) is
  refused in the preview and by the API (400), not half-way through applying. A closing step records its own `reason`,
  or the `conclusion`; when the close gate has a commentary minimum, a shorter one is refused in the preview, and an
  override's justification is "imported record: &lt;origin&gt;" followed by that reason when the minimum asks for more.
  *Confirm all from &lt;submitter&gt;* now leaves a history that closes its case for a confirm on its own (its close can
  override the close gate), and an import that fails in any way is put back in the queue while the batch carries on. A
  team member named by a UPN two users share is a warning and isn't added. Importing a history that closes the case no
  longer emails its team "you've been assigned"; one that stays open still does. A reviewer confirming from a page opened
  before another apply of the same import stopped part-way is told to reopen it, rather than creating the case twice.
- **Outside parties on a case (CAP-34).** One migration, `AddCaseParties`: a new `CaseParties` table (role, name,
  contact, reference, when engaged, notes), cascading from `Cases`; no data moves. Things › Connections lists them under
  *Outside parties* (*Add a party*, needing `EditCases`). Each row is audited and hashed from its first row, so the
  record check flags one without a hash. The case report prints them with the legal lines (Business Impact, or the case
  facts), Word templates get a `party` list (`party.role`, `name`, `contact`, `reference`, `engaged`, `notes`), and the
  legal register CSV gains a column, `outside_parties`, after `notice_references` (CAP-38 then adds
  `notification_status` last): a script reading the register by position still reads the columns before them as before. The configuration bundle is unchanged.
- **An offboarding page for a person who leaves (CAP-30).** In Administration › Roles & access, each name under *Known
  users* opens a page with their roles at last sign-in, the open cases they command or are on, their open tasks, their
  working API tokens and whether their calendar link works, with **Revoke** for the tokens and **Void the calendar link**
  (a new administrator action; the link is never shown). Both are confirmed and recorded in the audit trail; reassign
  their cases in Program › Team workload. The page's address carries an opaque reference, not the person's name or
  account. AD stays the source of roles. No migration and nothing to configure.
- **Syslog can go over TLS (CAP-33).** Set `Siem:Syslog:Protocol` to `Tls` (and usually `Port` to 6514) to send the
  SIEM stream per RFC 5425, with the collector's certificate checked against this server's trusted roots and its name,
  an optional pinned thumbprint (`ServerCertificateThumbprint`) and an optional client certificate from
  `LocalMachine\My` (`ClientCertificateThumbprint`). See OPERATIONS §5. **Check your `Protocol` value:** it's now read
  by name (`Udp`, `Tcp` or `Tls`, any case). Before, anything other than `Tcp` (a typo, a number) silently sent UDP;
  now it stops syslog and Diagnostics → Delivery health shows it **Stopped** with why. No migration.
- **Diagnostics lists the scheduled jobs (CAP-29).** Administration → Diagnostics → *Scheduled jobs* shows each
  background job's last run (when, how long, how it ended, items processed), when it's next due and its last error by
  type only. It's held in memory, so after the upgrade (a restart) every row starts at "Not run yet" and fills in as the
  jobs run. **Run now** is offered for the two read-only scans (the evidence re-verification and the retention review's
  count); it needs Administer, won't start while that job runs, and is recorded in the audit trail. No migration and
  nothing to configure.
- **A handoff remembers who it was handed to (CAP-20 review).** One migration, `HandoffRecipient`: a nullable
  `HandedToUserId` column on `TimelineEntries`; no data moves. The Now "watch for" card now finds the recipient by user
  id, so a renamed recipient's card still clears and a colleague with the same display name isn't taken for them.
  Handoffs recorded before the upgrade keep matching by the name in their text. The id is hashed only when set
  (canonical format 5), so existing rows keep their hashes.
- **Escalating a case offers the rung's playbook (CAP-11).** After an upward reclassification, or on a case filed at a
  rung, a notice under the case header offers the steps of each active template whose default classification is that
  rung and that aren't tasks yet; *Add them…* opens the Tasks tab's apply-playbook card with them ticked, and nothing
  is added until it's applied. No migration and nothing to configure; a site with no templates sees nothing. It's
  worked out from the case, so after the upgrade open cases already at a rung with a matching template show it too,
  until each person dismisses it (kept per browser, per case and rung).
- **The last handover's "watch for" stays on Now (CAP-20).** After a handoff with a *Watch for* part, Now shows it above
  the brief until the person it was handed to revises the brief or marks it still accurate. It's read from the handoff
  entries already on the timeline, so an open case handed off before the upgrade shows its card too. No migration and
  nothing to configure.
- **A finding can answer an open question directly (CAP-23).** In the timeline composer's *Finding* mode, *Then* →
  *Answers an open question* picks one of the brief's open questions; saving completes the question's task with the
  finding as its result, or raises and completes one when none followed it up, in the entry's save. No migration and
  nothing to configure. A question someone else answered or followed up while you were writing is refused, with your
  text kept.
- **Probes, the email logo and calendar feeds reach the app on IIS (CAP-37).** `Install-CaseBook.ps1` now carves
  `/health` (with `/health/live`, `/health/ready` and everything else below it), `/branding/logo` and
  `/agenda/feed.ics` out of Windows Authentication, as it always has `/api`; `Verify-Install.ps1 -Url` checks each
  answers anonymously. The app still decides what each gives away: a status word, the logo or a 404, and a feed only
  for a valid signed token. `/agenda/agenda.ics` and the rest of the site stay signed in. **`Upgrade-CaseBook.ps1`
  checks and configures the carve-outs on an existing site:** its preflight reads IIS's authentication settings for
  `<site>/api`, `<site>/health`, `<site>/branding/logo` and `<site>/agenda/feed.ics`, says which are already right
  (anonymous on, Windows off) and which it will change, and after the backup, before the new build starts, sets the
  ones that differ exactly as the installer does, logging each change. `-WhatIf` reports them and changes nothing. If
  IIS refuses a change the upgrade stops before deploying, with the current build still running, and says what to fix
  (run elevated; the IIS authentication role services: `Install-WindowsFeature Web-Server, Web-Windows-Auth
  -IncludeManagementTools`). The installer and the upgrade share the list (`deploy/lib/CaseBookIis.ps1`). Only as a
  fallback, by hand, elevated, for each path (with your site's name):
  `appcmd set config "CaseBook/health" /section:system.webServer/security/authentication/anonymousAuthentication /enabled:true /commit:apphost`
  and the same with `windowsAuthentication /enabled:false`. A load balancer that authenticated to reach `/health` can
  stop doing so.
- **`GET /health/alarms` for monitoring tools (CAP-18).** It answers `Healthy`, or `Degraded` while the audit chain is
  broken, evidence has drifted, the evidence key is unavailable, a seal copy is failing or the backup status file is
  stale or missing; always 200, with no detail. It is not part of `/health` and never takes a node out of rotation, so
  point a monitor (not the load balancer) at it and alert on `Degraded`. Anonymous on IIS through the `/health`
  carve-out above; no setting or migration.
- **Diagnostics lists the backup set, and `backup-manifest.json` gives it to backup jobs (CAP-19).** Administration →
  Diagnostics → *Backup set* shows the database's name and every path OPERATIONS.md §1 says to back up (evidence,
  report output, seal exports, the keys folder, the Data Protection keys, report templates, branding), each with
  whether it's there and writable, its size and last write. `GET /export/backup-manifest.json` (Administer) is the same
  as JSON, paths and metadata, never key material; it's access-logged and SIEM 5304. Setting sources now also show
  `Integrity:ExportPath`, `DataProtection:KeyPath`, `ReportTemplates:RootPath` and `ReportBranding:RootPath`. No setting
  or migration. Compare the card with your backup job's folder list once after upgrading.
- **Trusted signing keys for configuration bundles (CAP-16).** A new server-side setting, `Config:TrustedBundleKeys`,
  names a folder of public keys (PEM) whose bundles import as this server's own do; it's blank (none) unless you add it
  to `appsettings.Production.json` (the production template now carries it). **Behavior change:** a bundle signed with
  any other key no longer imports on a tick box; the administrator types the key's id, which the page shows, to
  confirm it. Re-importing this server's own bundle is unchanged. To promote from a test server without typing, put
  the public half of its seal-signing key in the folder and recycle the app pool. A file there that isn't an RSA key
  stops startup with its name. The import's audit entry and SIEM 5405 now end `signed with this server's key <id>`,
  `signed with trusted key <id> (<file>)` or `signed with key <id> (...), its id typed to confirm`; a SIEM rule that
  matched the 5405 detail's old `; key <id>` ending needs updating.
- **The Cases list exports to CSV (CAP-17).** *Export CSV* beside Views downloads every case the list's filters match
  (`/export/cases.csv`, the same query as the page), with the list's columns and the detected, contained, resolved,
  closed and reported times, up to 10,000 cases. Need-to-know applies as on the page; each download is in the access
  log and is SIEM 5304, and it counts against the downloads rate limit. A search is passed as a short-lived reference,
  not its text. No setting or migration.
- **`Retention:CaseYears` now does something: a retention review (CAP-10).** Administration → Compliance & security →
  **Retention review** lists closed, not-archived cases closed more than `Retention:CaseYears` ago (default 7) for an
  administrator to archive, at most 25 at a time after confirming the list. A legal hold or a regulatory notice not yet
  recorded still stops a case being archived, and nothing is ever deleted. If your installs set the value expecting
  nothing to happen, check it: after the upgrade, Diagnostics shows how many cases are past it; set `0` to turn the
  review off. A new setting, **Monthly retention-review email to Legal** (`Notifications:RetentionReview:Email`, off), sends
  the Legal / Privacy distribution the counts once a month; its wording is the new *Retention review (Legal / Privacy)*
  email template. No migration; no case is changed by the upgrade.
- **The access review exports and can be recorded (CAP-15).** Roles & access → Access review now lists the API tokens
  that work, downloads as CSV (`/export/access-review.csv`, access-logged and SIEM 5304, rate-limited like every export),
  and has **Record this review**: a note kept as an `AccessReview` entry in the audit trail, shown as "Last reviewed …
  by …". Diagnostics flags the access review as due when none has been recorded in `Governance:AccessReview:ReminderDays`
  (new, default 90; 0 turns it off), so on an upgraded install it shows as due until the first review is recorded. No
  migration.
- **An evidence file filed on the wrong case can be withdrawn, with a reason (CAP-21).** One migration
  (`EvidenceWithdrawal`) adds three nullable columns to `Evidence` (`WithdrawnAtUtc`, `WithdrawnBy`, `WithdrawnReason`);
  the app applies it on first start, and DBAs applying the schema by hand re-run `deploy/sql/casebook-schema-sqlserver.sql`.
  No existing row changes or re-hashes: the withdrawal is in the row hash (format 5) only when set. Withdrawn files stay
  (bytes, hash, custody, downloads) but leave the report, the gates' evidence count, citing, packages, tasks, recorded
  transfers and other cases' "also evidence in" (Find still lists them, marked *Withdrawn*); the "evidence
  is immutable" wording now means the bytes. **Behavior change:** a withdrawn copy no longer blocks uploading the same
  file to the same case again. New SIEM event **5516** (Warning); add it to any rule that watches 5506-5515.
- **A case's evidence can be packaged for hand-over (CAP-12).** *Package evidence…* on the Evidence tab downloads the
  files picked as one zip with the password `infected` and a `MANIFEST.txt`, from `GET /evidence/package/{ticket}`
  (`EditCases`, the `downloads` rate limit). The transfer is recorded before the first byte is sent ("Transfer begun" on
  each file, and an audit entry with the package id and the hand-over), then as sent in full ("Transferred", and an
  entry with the package's SHA-256) or as partial ("stopped after N of M files", saying which went out in full, in part
  or not at all): a zip like this can be read without its directory, so a cut transfer is a transfer. A begun entry with
  nothing after it is partial. Each file is checked against its SHA-256 before it's sent, so a package reads each file
  twice. No migration or setting: a package is capped at
  500 files and at `Evidence:MaxUploadMB` in all. New SIEM event **5308** (Warning, High on a restricted case) and a new
  access-log type, *Evidence package*; a SIEM rule for bulk export may want both 5307 and 5308. 5308 is sent as a package
  begins, so one that stops part-way is in the stream too.
- **The chat webhook URL and the SIEM webhook token can be entered in Administration (CAP-40).** One migration adds the
  `StoredSecrets` table (the app applies it on first start; DBAs applying the schema by hand, re-run
  `deploy/sql/casebook-schema-sqlserver.sql`). Nothing changes for an install that sets `Chat:Webhook:WebhookUrl` and
  `Siem:Webhook:Token` in `appsettings.Production.json`: those still win, and the new cards (Settings → Notifications →
  Team chat webhook; Server configuration → SIEM webhook token) show them read-only. To move a value into the app, clear
  it in the file, recycle the app pool, and enter it on the card. Saved values are encrypted with the Data Protection
  key ring, so back up `DataProtection:KeyPath` with the database (OPERATIONS.md §1). **Behavior change:** a SIEM webhook
  token that's set but won't resolve (a CyberArk reference that fails) or decrypt now stops the webhook's sends; before,
  each event went without an auth header. Diagnostics → Delivery health shows it.
- **IOC feeds a machine can pull (CAP-09).** `GET /api/export/iocs.csv` and `GET /api/export/iocs.stix.json` give a
  firewall, an EDR or a threat-intel platform the malicious-IOC feed with a **system API token** whose role grants
  `ViewCases`, no Windows sign-in. No migration and no new setting is needed; the installer's anonymous carve-out for
  `/api` already covers the new paths (check with `Verify-Install.ps1 -Url`, which tests each carve-out, `/api` included).
  - **Give a feed token a role with `ViewCases` alone.** The feed holds what the token's owner may see, so one holding
    `ViewRestricted` or `ViewAllCases` feeds restricted matters' indicators to the consumer. Exercises never appear.
  - Pulls are rate-limited per token (a burst of 20, then one a minute; `RateLimiting:ApiFeeds:*`, restart to change).
    `If-None-Match` with the last `ETag` answers an unchanged feed with 304; `?since=` gives a delta.
  - Each pull with a body is in the access log and is SIEM 5304, by `apitoken:<name>`.
  - The feed, and the signed-in *Malicious IOCs* download, now stop at 100,000 indicator occurrences (the most recently
    changed) and say so when cut.
- **An import's sender can check what became of it (CAP-13).** `GET /api/import/cases/{pendingImportId}` answers the
  token that sent it (or one with `EditCases` that could review it): pending, applied (with the case's number and id
  when the token can see the case) or rejected. Anything else is a 404.
- **Imports can name the existing case by its detection case id (CAP-14).** `target.detectionCaseId`, an optional
  addition to the import schema (v1 and v2), is resolved when the import is reviewed, among the open cases the reviewer can see;
  with no match the `newCase` is prepared (with a warning), and with several the reviewer picks. A `target.caseId` and `target.detectionCaseId` that
  name different cases are refused (400). Producers sending only `caseId` or `newCase` see no change. The XSIAM
  template's README shows the new target.
- **API callers get their 403.** A refused GET under `/api` is a plain 403 rather than a redirect to the access-denied
  page (SIEM 5201 as before).
- **Evidence records how it was collected (CAP-08); the Evidence list filters and sorts (CAP-25).** One migration,
  `EvidenceCollection`, adds three nullable columns to `Evidence` (`CollectedAtUtc`, `CollectedFrom`, `CollectedBy`);
  the app applies it on first start, and `DbaApplies` installs run the regenerated
  `deploy/sql/casebook-schema-sqlserver.sql`. Existing rows are untouched and keep their row hashes (the columns join
  format 5 of the hash only when set). Nothing to configure. Large uploads in progress across the upgrade still resume (their
  saved state reads without the new fields). Templates can use `evidence.collected`, `evidence.collected_from` and
  `evidence.collected_by`. A file with a collection time recorded puts its *Evidence added* timeline milestone at that
  time. Browsers pick up the new upload script and styles by their cache version.
- **How a regulator was notified (CAP-07).** One migration, `NoticeDetails`: four nullable columns on
  `JurisdictionNotices` (`Method`, `Reference`, `NotifiedBy`, `EvidenceId`); no data moves. Existing notices are
  unchanged and keep their row hashes. New row hashes are written as `v5:` (canonical format 5), which differs from
  format 4 only for a notice with these details, evidence with collection details (CAP-08) or a withdrawn file
  (CAP-21), so nothing is re-hashed
  and the integrity upgrade doesn't run again. Templates can use the new `notice` collection (`jurisdiction`,
  `notified`, `due`, `method`, `reference`, `by`, `file`). The case report's Business Impact section now lists each regulator's notice ("Notice to NY: …"), so a regenerated
  report of a notified case reads differently from an older version. The legal-register CSV gains three columns after
  `deadline_status`: `notice_references` (this item), `outside_parties` (CAP-34) and `notification_status` (CAP-38,
  the last). A script that reads columns by position is unaffected; one that checks the header needs all three added. No new SIEM event: editing how a regulator was notified sends none (recording the notice still sends 5513).

### v1.9.0

One migration: the new `SmtpSignIns` table (one row; the app applies it on first start). Things to check:

- **New SIEM events: tell the SOC.**
  - **What's new:** 5405 *reference data changed* (stage gates, data elements, deadline rules, templates, outcomes,
    taxonomy, report profiles, Word and email templates; one event for a configuration-bundle import), and 5506-5515
    for the case lifecycle: created, phase changed, reclassified, closed, reopened, archived or restored, materiality,
    reported or a notice recorded, report approved, import applied.
  - **What they carry:** each holds the case number, the actor and, when the case has one, `detection=<id>` at the end
    of the detail. Exercises are sent too, with detail starting `EXERCISE:`.
  - **Worth a rule:**
    - 5508 `CaseDowngraded`;
    - 5509 with `gateOverridden=true`;
    - 5511 `CaseRestored`;
    - 5512 `status=Material`;
    - 5513 `ReportedCleared` or `RegulatorNoticeRemoved` (a clock running again);
    - 5405 for a `StageGate` or `DeadlineRule`.
  - **Where to look:** OPERATIONS.md section 5. Ids are only ever appended.
- **Email can sign in to the mail relay.** Set it under **Administration → Settings → Notifications → Email sign-in**:
  - **Modes:** no sign-in (as before), a username and password, or the server's Windows account (the gMSA).
  - **Storing the password:** it's never shown again. CaseBook encrypts it with the Data Protection keys
    (`DataProtection:KeyPath`). **Back that folder up with the database:** without it, a restored or moved database
    can't open the password, so email is held and Diagnostics asks for it again.
  - **Server configuration instead:** `Email:SmtpUsername`, `Email:SmtpPassword`, `Email:SmtpUseDefaultCredentials` and
    `Email:SmtpTimeoutSeconds` (default 30) also work, and win over the form. `Email:SmtpPassword` may be a CyberArk
    reference or a `@protected:` value (below).
  - **When the relay refuses the sign-in:** a 530 or 535 isn't tried again for an hour (to spare the account a
    lockout), and held mail is given up after 24 hours.
  - **Existing installs:** nothing changes until you set a sign-in.
- **`@protected:` secrets (ADR 0018).** `casebook-keytool protect-secret` encrypts a secret to a certificate in the
  machine store. CaseBook opens it, with or without CyberArk, for `Email:SmtpPassword`, `Chat:Webhook:WebhookUrl` and
  `Siem:Webhook:Token`. The app-pool account needs read on that certificate's private key. After renewing the
  certificate, make the values again before removing the old one.
- **Installer.** New options for how email signs in:
  - `-SmtpSignIn App|Windows|Password`, with `-SmtpUsername` and `-SmtpPasswordSource Protected|CyberArk|Literal`;
  - matching answers-file keys (INSTALL.md section 4);
  - the installer prompts for the password and never reads it from the answers file.
- **API imports are announced.** Reviewers (EditCases) see waiting imports:
  - on the Desk;
  - on a new **Import** entry in the side menu, with a count;
  - in their digest (`Notifications:DigestScan:ImportWaitingHours`, 24). A digest with nothing else in it uses the new
    *digest-imports* email template.

  Email and chat notices are off until turned on under Notifications. An import aimed at a restricted case shows only
  to that case's audience. The API's response is unchanged.
- **Set a verdict on several entities at once** on the Entities tab: up to 2,000, all or nothing, each with its own
  verdict record. The Closure gate's *Assess* opens the tab with the Unknown ones ticked.
- **The Integrity page searches the whole audit trail.** Filter by actor, action, entity type, case, setting and dates,
  page through the results, and export them (`/export/audit.csv`). Each setting on Administration has a *History*
  link. A truncated audit export now says so at its end as well as its top.
- **Diagnostics → Delivery health** shows email, chat and each SIEM transport: held mail, last failure by type or code,
  dropped events. Held mail comes from the database; the rest resets at restart.

### v1.8.0

A release with no migration, following up v1.7.0's evidence work. Things to check:

- **New SIEM events: tell the SOC.** 5006 *evidence key unavailable* (High; once per outage), 5007 *evidence key
  changed* (action `KeyCreated`, `KeyAvailable`, `KeyProtectionChanged`, `SharesIssued`, `RecoveryDrill`, or
  `KeyRecovered`, which is High: the key moved onto another certificate) and 5307 *evidence exported decrypted* by
  `casebook-keytool export` (Warning). Ids are only ever appended; see OPERATIONS.md section 5.
- **What the keytool does is now in the audit trail.** `split`, `verify`, `recover` and `export` each leave a record in
  the keys folder's `evidence-key.json`; CaseBook writes it to the audit trail and the SIEM within a minute. Run the
  tool against the site's own keys folder (on the server). Records left by v1.7.0's tool aren't there, so nothing old
  is replayed.
- **Installer.** The answers file takes `EvidenceEncryption`, `EvidenceKeyThumbprint` and `RecoveryCertificates`
  (INSTALL.md section 4), and `Verify-Install` checks them. Re-running the installer still keeps an existing
  `appsettings.Production.json` unless `-ReplaceSettings`.
- **The same file twice in one case is refused** (by SHA-256), naming the first copy; in another case it's stored and
  the uploader is told which other cases they can see hold it.
- **Hash as IOC** on each evidence row adds the file's SHA-256 to IOCs & entities (unjudged).
- **Large uploads resume.** One cut off part-way (network, page closed, app restart) is listed under *Unfinished
  uploads* on the Evidence tab for a day; picking the same file again carries on. Leaving the page now keeps an upload
  rather than deleting it; only Cancel deletes. Each upload's state is a small `.state.json` beside its parts in
  `<store>\.incoming`.
- **A smaller bundle.** SkiaSharp's native debug symbols (about 276 MB unpacked) are no longer shipped.

### v1.7.0

A feature release with one additive migration (`EvidenceKeyEnvelopes`). Nothing changes until you choose it, except
the larger upload limit and the safe-download button. Things to check:

- **Upload limits are settings now, and the default is larger.** The largest file was fixed at 50 MB; it's now
  **Administration › Governance & security › Evidence storage**: largest file (`Evidence:MaxUploadMB`, default
  **500 MB**, up to 64 GB), the most all evidence may take (`Evidence:StorageQuotaGB`, no limit by default), and the
  free space an upload must leave (`Evidence:MinFreeSpaceGB`, default 10 GB). Diagnostics shows the store's use
  against them.
  - Files over 100 MB, such as memory dumps, upload in 8 MB parts with a progress bar. Nothing in IIS needs changing.
  - A per-user rate limit applies to the parts (`RateLimiting:Uploads`).
- **The evidence store can be on a network share** (`EvidenceStore:RootPath` as a UNC path, installer
  `-EvidencePath`). The app-pool account needs Modify on the folder and Change on the share. OPERATIONS.md §1.2.1
  covers the rights and how to move an existing store.
  - **New behaviour:** once evidence is recorded, CaseBook never recreates a missing store folder. If the folder is
    gone (a share down or remapped), uploads are refused, downloads say the store can't be read, `/health` reports
    Unhealthy, and Diagnostics gives the reason, until it's back. Don't create an empty folder in its place.
- **Safe download.** A file that can run (a program, script, shortcut, disk image, Office file with macros) shows
  **Can run** on the Evidence tab and downloads first as a zip with the password `infected`, so it can't be run by a
  double-click and the analyst's antivirus doesn't delete it on arrival. The plain file is behind a confirmation.
  `Evidence:SafeDownload` makes the zip the first choice for every file (`Always`) or none (`Off`).
- **Evidence encryption at rest (off until you turn it on).** Evidence and reports can be stored encrypted (AES-256),
  so a copied disk or backup doesn't expose them and the server's antivirus can't delete a malware sample. Read
  **OPERATIONS.md §2, Evidence key** before turning it on. In short:
  - The key is protected by the integrity certificate (or CyberArk chain key) you already have. Nothing is encrypted
    until a backup of it exists: a recovery certificate (`Storage:Encryption:RecoveryCertificates`) or shares from
    `casebook-keytool split`. Make two recovery certificates with two custodians, and run a drill
    (`casebook-keytool verify`).
  - **Losing the key loses the encrypted files.** Back up the data root's `keys` folder with the database and the
    evidence store, and restore all three together.
  - Files stored before are encrypted in the background, starting 15 minutes after start-up, or at once with
    **Convert now** on Diagnostics. **This is one-way:** a rollback after it also needs the evidence store from
    before it (see Rollback above).
  - With encryption on, no antivirus exclusion is needed for the evidence store. Until conversion finishes, plain
    samples are still visible to it.
- **New in the release bundle:** `deploy\keytool\casebook-keytool.exe`, which splits the key into shares, checks a
  share, runs a recovery drill, recovers the key onto a new certificate, and exports evidence as the original files.
- **Compliance bundles** now say in VERIFY.txt that evidence hashes are of the original files.

### v1.6.15

A small release with no migration. Things to check:

- **Access log retention: read before upgrading.** The access log (who opened which case, downloaded which evidence
  or report, exported what) was never pruned. It's now kept for **Retention › Access log retention (years)**,
  `Retention:AccessLogYears`, default **3**. **On the first night after upgrading, and at the first start, entries last
  seen more than 3 years ago are deleted.** If your record-keeping rules need them longer (some apply six years to
  access logs), raise the setting, or set it to 0 to keep everything, **before** upgrading: put
  `"Retention": { "AccessLogYears": 6 }` (or 0) in `appsettings.Production.json`, or change it in Administration
  straight after the first start.
  - Entries for a case under a legal hold are never deleted, including while a release of the hold is pending.
  - Each prune that deletes anything is recorded in the audit trail (how many, and the cutoff date).
- **Evidence re-verification is spread over a week.** When it's on (`Integrity:EvidenceVerify:Enabled`), each run now
  re-hashes a share of the stored files instead of all of them, so every file is checked at least once in
  **`Integrity:EvidenceVerify:PassDays`** days (default **7**) and a large store isn't read end to end every day.
  - A damaged or swapped file is now found within a week rather than a day (up to two weeks after an outage or a
    settings change). Set `PassDays` to 1 to keep the daily full pass.
  - Runs now happen once per interval counted from midnight UTC (and once at startup), not 24 hours after the app
    started. A problem found stays listed, and isn't alerted again, until that file's turn comes round.
  - Diagnostics shows how many files the latest run checked out of the total.

### v1.6.14

A small release with no migration. Things to check:

- **Integrity check cost.** Each run of the integrity check now logs what it cost (time for the audit trail and for
  the records, how many it read, how many records it holds in memory), and **Administration › Diagnostics › Integrity
  check cost** shows the latest. The record check reads every record every 10 minutes, so this is how you see it grow
  with your data. Measured on SQL Server 2022: a 10-minute run takes about 7.5 s per million records and a full run
  (every 6 hours, at start-up and on *Verify now*) about 50 s (`docs/architecture/integrity.md`, *Check cost*).
  - The check holds about a third of the memory it did between runs (114 MB per million records, from 305 MB).
  - A run slower than 60 s is logged as a warning, and the next waits ten times as long (up to 30 minutes), so the
    check never takes most of the database's time. Detection takes that long meanwhile; the log and Diagnostics say
    so. At CaseBook's intended size this doesn't happen.
- **Import schema:** date fields accept a time without an offset (read in the document's `timeZone`, else UTC), so a
  document using `timeZone` passes schema validation.
- **Import fields:** times now use `detectedAt`, `occurredAt`, `occurredUntil` and `dueAt`. The old `...Utc` names
  still work (deprecated), but don't give both. This keeps an AI from converting local times to UTC itself.
- **Import preview** shows times in your own time setting rather than UTC.

### v1.6.13

A fix release with three migrations (`HeldEmails` table and its retry/audience columns, `Reports.RowHash`). The first start after upgrading
runs a one-time integrity upgrade; read **Integrity upgrade** below before deploying. Things to check:

- **Integrity upgrade (tamper detection).** The record check now catches a row planted in the database without a
  hash or trail entry in any table, a record last saved before v1.5.1 rewritten with its hash recomputed, a moved
  notice deadline, a changed list of a reported case's jurisdictions, a planted legal-hold release request, a note
  edit unlinked to restore earlier wording, a stage-gate requirement weakened in the database, and a note or
  timeline entry hidden without a successor or retraction. Reports are now hashed records: renaming who generated
  one, marking a draft final, renumbering or deleting one is caught.
  - After the first start, CaseBook records every honest row against its audit trail (one audited "CaseBook upkeep"
    entry per row, not counted as activity or changes after closure), logs any row it couldn't record, and only then
    sets `Integrity:RowHashFormat=4` and makes the check strict. It runs in the background, starting once the app has
    been up for 15 minutes (`Integrity:Upgrade:DelayMinutes`; keep it above the upgrade script's 11-minute warm-up, so
    a build that fails its warm-up is rolled back before any row is rewritten), and logs its progress. Until it
    finishes the check is as before. Measured on SQL Server 2022: a few seconds per 100,000 records already recorded
    (most of a v1.6.12 database), under a minute per 100,000 it records (records last saved before v1.5.1); allow
    several times that on a remote server. A shutdown part way, or a failure, leaves what it recorded and the next
    start carries on; a failure that won't clear on its own is logged as an error. A row that disagrees with its
    trail is left unrecorded and reported. Recording a case's hash doesn't count as a change, so someone editing the
    case meanwhile isn't told it was changed.
  - Start-up fills (a reported case's jurisdictions, a notice's deadline, the hash of an older status, assignment or
    citation record) no longer sign off a row changed in the database, including one whose older-format hash didn't
    cover the changed value or whose hash was cleared, and never overwrite a save made at the same moment. A start-up
    fill that fails is logged, not a stopped service.
  - Once strict, a record deleted in the database is reported however old its last trail entry.
  - Tested upgrading from v1.0.0, v1.4.0, v1.5.0, v1.5.9 and v1.6.12 on SQL Server 2022: no false alarms, and
    tampering after the upgrade is caught.
- **Regulator deadlines.** A second regulator on the same deadline gets its own at-risk and breached reminders
  (reminders already sent aren't repeated, and a regulator that joins a clock reminded before the upgrade is
  emailed and posted). An element added to a reported case counts as one it already had, so a
  later admin mapping no longer shows a clock that reminders and the close gate ignore. The close gate's
  notifications check judges the case the way the case page does.
- **Held email.** Assignment, mention and handoff emails the relay didn't take are kept in the database (they
  survive a restart) and sent when it answers; a temporary refusal (450-452) is retried. Held mail is given up only
  after 12 temporary refusals or 24 hours with the relay unreachable. A breach or integrity alarm cut off by
  shutdown is still kept for retry.
  - Before a held case email goes, it is checked against who may still see the case; anyone who lost access is
    dropped, and it isn't sent if the case is gone.
  - It waits while email is turned off, and when the relay refuses the session (for example 530 authentication) or
    the From address, with an error logged until it's fixed, instead of being deleted. Refused recipients no longer
    back the relay off, and one recipient's "mailbox full", or one email the relay refuses for its content (a DLP or
    transport rule), no longer holds back the rest; an email too large for the relay (552) is refused at once.
  - The email log shows the error type and SMTP code, not the relay's reply text (which can echo addresses).
- **Settings and AD.** A saved setting, label, template or import can't be undone by a slower reload that read
  earlier, and "saved but not in effect" reflects that save's own reload. A disabled API-token owner, or one removed
  from an AD group, loses the access at once even when AD answers slowly or partially.
- **Import case (from user testing):** a tabletop / exercise case can be imported (`newCase.exercise`, or the
  preview's switch), and the case number can be chosen on the preview.
- **Imported times:** a time without a time zone is read in the organization's zone on the Import page (switchable
  there), or in the document's own `timeZone`; the API still treats such times as UTC unless the document names a
  zone. The preview says which zone was used. Changing the zone after Preview reads the document again in that zone
  (and says so, since edits to the preview are undone), so Apply imports what the picker shows; the picker is locked
  once part of an import is applied.
- **AI prompt:** keeps times as the material states them instead of converting to UTC; its Target select no longer
  goes blank.
- **Smaller fixes:** a sign-in that lands while the user directory reloads keeps its new roles; a report download
  hands over exactly the bytes it checked, and a report whose stored path was edited to lead outside the store is
  refused as altered.

### v1.6.12

A fix release with no migration. It closes whole classes of bug at once, each with a test that fails if the class
comes back. Things to check:

- **Unsaved text asks first.** Switching case tab, hiding Now/Next, moving or closing a side panel, leaving the case,
  changing the time display or opening another action over one you've typed in now asks **Stay / Discard** and names
  what would be lost. Edit on a second row (timeline entry, note, entity, relationship, task, review action, deadline
  rule, cite picker) while one is open says "Save or cancel the … you're editing, then try again." An edit or editor
  you haven't changed doesn't ask.
- **Late results stay out.** A search, preview, lookup or reload that finishes after you've moved on no longer
  replaces what's on screen or moves the page. Case import's Apply and Reject act only on the preview shown. Text
  typed while a save runs is kept, and a save closes only its own form.
- **One click, one action.** Double-clicks and Enter-plus-click no longer save, send, approve or delete twice anywhere
  in the case, admin and report pages. Saving a view over an existing name needs **Overwrite**; New case's duplicate
  pause needs **Create anyway**. Ctrl+Enter in the notes composer saves that note, not one being edited in place.
- **Active Directory.** Sign-in no longer asks AD about each role on every request, and a role named like an AD group
  is granted again. Display and group names are looked up with a time limit. When AD can't name a user's groups in
  time, Managers aren't dropped from escalations or reminders, open sessions still lose a role an admin removed, and
  a personal token keeps only what its named groups grant.
- **Email and chat.** A relay or webhook that stops answering is backed off after three failed connections in two
  minutes (1 minute, up to 10). Assignment, mention and handoff emails sent meanwhile are held and sent when it
  answers (held in memory: an app restart while it's down loses them). Critical-alert retries aren't spent while it's
  backed off. HTML in case text shows as text in Teams posts.
- **Who gets case email.** Assignment, mention and handoff emails go only to people still entitled to the case,
  checked against the directory. A pre-v1.5.1 role name with a comma (e.g. "Readers,SysAdmin") is read as one role;
  start-up logs any such names so you can rename them.
- **Regulatory reporting.** A notice or reported time recorded from a stale page is refused when a colleague recorded
  one meanwhile. The brief editor keeps questions and Known lines added while it was open. The deadline reminder
  links to the at-risk list (closed cases still owing a notice included). Damaged kept-jurisdiction values from
  v1.5.7–v1.6.3 are repaired at start-up.
- **Past quarters stay put.** Correcting a transition time, removing or re-dating a notice, clearing a review,
  switching deadline tracking off, or tagging a technique later no longer changes a reported quarter. The dashboard's
  and Metrics CSV's all-time SLA figure now judges each milestone by the targets, severity and class of its time, as
  the program report does. Nothing is measured from an approximate start. The Cases page no longer loads the SLA
  history.
- **Config import.** The preview now runs the import's own code without saving, so it shows exactly what the import
  will write and refuses what it refuses; importing an unchanged bundle twice changes nothing. Names are read by name
  only ("4" or "A,B" is no longer another value). Data element keys with "," ";" or spaces are refused. **Note:** if
  live config already holds an undefined playbook default stored by an older import, importing the server's own
  export is refused until that playbook is fixed (the message names it).
- **Exports and limits.** CSV exports guard formulas after a ";" too (Excel set to a ";" separator). The calendar feed
  no longer fails for the team when a task is due at the end of 9999; task dues must fall between years 2 and 9998.
  Saving a view with filters over 2,000 characters says so. Evidence transfers are always audited. Ledger digest file
  names use the Gregorian calendar on any server culture, and Verify-LedgerDigests picks the newest by ledger block.
- **Smaller fixes:** double "Assign to me" or two people tagging the same technique says "someone else changed this
  case" instead of failing, and bulk assign no longer stops halfway; editing a task or advancing a phase no longer
  moves a time in the repeated autumn hour; a long value no longer breaks access-log, alert, directory or
  import-rejection saves; entity tags with backslashes or brackets show as chips.
- **From user testing:** pasting a document into Import case works at any size an upload takes (up to 4 MB); entity
  pills say "Show details for …"; date pickers run from 1970, dates for things that happened stop at today, due dates
  and targets reach 20 years ahead, and a stored date outside that range can still be kept or have its time edited.

### v1.6.11

A fix release with no migration. Things to check:

- **A slow domain controller no longer stalls the app.** Display names and group names are looked up with a short
  time limit (2 s and 5 s). Until a name arrives the sign-in name is shown; a group not named in time matches role
  mappings by SID only for that request, so a user may hold fewer roles until the next refresh.
- **Find:** `entity:` with words lists only rows where every word appears, and an indicator searched beside `entity:`
  is matched by its own tags.
- **Regulator reporting:** on a case reported before CaseBook recorded its data elements, an element added later keeps
  its regulator's deadline on the case page and in reminders. Such cases get their elements recorded at start-up. A
  case reported with nothing in play is reminded again when an added element reopens a deadline.
- **Pages left while loading:** the case list, case page, notification bell and alert banners no longer keep
  refreshing in the background, and a note editor closed mid-load no longer stops the next one attaching.
- **Administration:** changes to settings, taxonomy, roles, AD mappings, data elements, deadline rules and system API
  tokens wait for a running config import, and a data element saved twice at once no longer breaks the page. The
  import preview counts AD mappings the way the import applies them. A new outcome or data element never takes a
  deleted one's key, so re-adding a deleted item gives it a numbered key (for example `PassportNumber2`).
- **Smaller fixes:** editing a task's other fields no longer moves a due set in the repeated autumn hour; the case
  beside no longer names the previous case while the next loads, and Ctrl+Enter inside it submits nothing; the
  Integrity page, evidence list and stored-report table show a short hash instead of failing on it.

### v1.6.10

A fix release with no migration. Things to check:

- **One fixed culture.** CaseBook now formats every date and number the same way whatever the server account's
  regional settings. A Buddhist or Hijri year, or a comma decimal, can no longer appear anywhere.
- **Defaults stay deleted.** Deleting every stage gate, case template or report profile now sticks. The defaults are
  seeded only on a real first start, not whenever a table is empty.
- **Briefs:** holding Ctrl/Cmd+Enter in the brief editor saves once, so a "someone else changed this" warning can't be
  skipped and a colleague's brief overwritten. A held Enter adds one Desk task or saves one view.
- **Timeline:** 'l' and "Show on the timeline" no longer leave a hidden type or tactic filter, or the Story lens,
  hiding entries. 'n' waits while a working note is edited in place. Saving Details again after a refusal keeps the
  times shown.
- **Regulator reporting:** a case reported with nothing in play keeps what was kept when an added element reopens
  it, so later changes are judged against the original. The reported time is recorded again by the user.
- **Program report and overview:** a past quarter's SLA targets stay put when an old setting is changed then reset; a
  custom range ending today is compared with the same span before it. The executive email's text part lists one
  figure per line.
- **Administration:** playbook template saves wait for a running import and never break the page on a name clash. A
  deadline rule's code can't contain "," or ";" (such a rule never applied; the import preview names any
  existing one). The config import preview counts profiles, rules, outcomes, settings and roles the way the import
  applies them.
- **Smaller fixes:** "Send test event" reports a missing Event Log source; the Word preview shows the template now
  selected; the idle lock fires after a long sleep; a resumed import shows only current warnings; a SQL Server
  database that can't be opened stops startup instead of getting a new chain key.

### v1.6.9

A fix release with no migration. Things to check:

- **Upgrade script and the chain key.** When the audit chain key or the retired-key folders have no path set and
  would fall inside the site folder, the upgrade copies any files there to `<DataRoot>\keys`, checks the copies'
  hashes and sets the paths, so the next upgrade can't delete them. **Check:** the upgrade now stops before changing
  anything if a File signing key sits inside the site folder, or if it can't work out the data root (pass
  `-DataRoot`).
- **"Copy briefing as text"** includes open questions written as prose, as the briefing page shows them.
- **Timeline:** the 'n' shortcut and a jump to a note no longer throw away an entry you are editing. 'l' always opens
  an investigation finding. Holding Ctrl/Cmd+Enter submits once.
- **Administration:**
  - Two stage-gate saves at once can't leave two active gates on one transition or two gates with one name. A
    server that already has a duplicate gate name gets a "rename one" message on config import.
  - A report profile edit that waited behind an import or upload is refused instead of overwriting it.
  - Quick clicks on default-view stars leave one default.
- **Import:** a user who can't change classification is offered Complex Event only. A reopened import warns it may
  already have written more than the marked items.
- **Smaller fixes:** a cut-off audit or access-log CSV says "100000" rows in one cell; the report preview dates
  indicators in the Gregorian calendar.

### v1.6.8

A fix release with no migration. Things to check:

- **Exercise Breach emails** carry the EXERCISE note exactly once in both the HTML and text bodies, whatever the
  template.
- **Report preview** shows what the Word report will contain: a vendor case's disclosure milestones and "Where"
  column, each entity's TLP, "Activity began", "Recovery started" and changes made after closure.
- **Administration:**
  - Two Word templates can no longer end up with the same name. If a server already has a duplicate name, a config
    import names it and asks you to rename one, instead of failing.
  - A save that's stored but can't be put into effect yet counts as saved. Saving again is no longer refused, and
    Taxonomy label changes made with an order change are kept.
- **Cases:**
  - Bulk "Refer to Legal" keeps a referral another analyst made after you selected the cases.
  - Two people linking the same two cases at once make one link.
  - Back from your default view leaves the case list.
- **Search and import:**
  - Find and "seen before" quote a closed case's conclusion as it stood at closure, as plain text.
  - An imported case whose detected or activity time is impossible has that time left out with a warning, so Apply
    works.
- **Exports:**
  - An audit-trail CSV's first line can't be turned into formulas by a case number.
  - File names and the compliance bundle's audit entry use Gregorian dates whatever the server's language settings.
- **Dates on screen:** the notification bell and due dates use Gregorian dates whatever the server's language
  settings, like every other time shown.
- **Releases** find the quality-gate result when docs commits were pushed after the tagged one.

### v1.6.7

A fix release with no migration. Things to check:

- **New case:** ticking or unticking "Tabletop / exercise case" checks the indicators again. A live case can no longer
  be filed without the duplicate and campaign check, and a drill no longer quietly drops a chosen link. Indicators are
  filed only as entity types an admin offers.
- **Past quarters stay as reported:** the Program report and Program overview keep a past quarter's containment and
  resolution figures when a case is later moved back into Containment. A later correction to a case's detected or
  occurred time no longer changes a quarter that has ended.
- **Active Directory:** on a slow but working domain controller, the list of trusted domains is kept again, so
  `DOMAIN\name` lookups work. Only a single directory search that runs into its 10-second limit counts as incomplete.
- **Case record:**
  - Typing a time back to the minute it showed no longer moves an entry an hour in the repeated autumn hour.
  - Editing an attack step keeps tactics its picker doesn't show, for example from an import.
  - The Things tab and the New IOC dialog never default to, or auto-detect, a type or verdict an admin has hidden.
  - A task result put on the record from Now/Next is logged as the same type the Tasks tab uses, and says which.
  - Gates passed when a case is filed stay as their own timeline rows.
  - Tactics read in ATT&CK matrix order in the Briefing, the case report and the review draft, named as in the app.
  - The case preview's "+N other cases" counts only cases on its own side of the exercise line.
- **Navigation:** switching between UTC and local time, or "Reload the page", keeps the case where you were. "Show on
  the timeline", entry links, "Cited by" and "changes since" work whatever timeline lens is on. The Desk's "Browse all
  cases" opens all cases.
- **Smaller fixes:**
  - Export date ranges and token expiry limits work under any server calendar.
  - A Word template's table inside a text box shows its own card's item.
  - Two graph-layout saves at once no longer lose the layout.
  - A release tagged on a release-notes commit finds its code's quality-gate result in more cases.
  - v1.6.6's note on tagged questions also applies to Known lines.

### v1.6.6

A fix release with no migration. Things to check:

- **Who sees cases:** a signed-in user without the View cases permission sees no case data. That includes a domain
  user with no CaseBook role, and a custom role with Administer only. The search pill, the case tabs, the beside pane
  and the activity bell are hidden for them, and the command palette shows no cases. Every built-in role has View
  cases, so nothing changes for them. **Check:** a custom role whose users should see cases has View cases ticked.
- **Releases** need SonarQube Cloud's quality gate to have passed on the tagged commit (or, for a release-notes commit,
  on the code before it). A red gate now fails CI on main.
- **Email:** the From address must be one address (`CaseBook <casebook@contoso.com>` is fine). A blank value, a name
  alone or a list is refused, in the settings and in config-bundle imports. A bad value already saved is flagged in
  the health checks. **Check:** Administration › Diagnostics shows "Settings within limits" as passing.
- **Active Directory:**
  - An API token's owner check gives up after 10 seconds. A hung domain controller no longer stalls token requests,
    reminders, escalations or the agenda feed, and a hung trusted domain doesn't hold up the others.
  - A list of trusted domains cut short by a slow controller isn't kept for an hour.
- **Report templates** with text boxes work. A field inside a text box isn't refused on upload, and a list in a text
  box repeats inside the box. A stage gate with many long requirements no longer blocks the close or escalation it
  records.
- **Case record:**
  - A note promoted to the timeline, or an entry edited, keeps its time in the repeated autumn hour.
  - When an admin hides Analysis, forms default to the first type offered.
  - After editing an entity, the add form gets its own verdict back.
  - A question or Known line with `[[tags]]` is limited by what you typed.
  - A climb such as Complex Event to Incident names every gate it passed.
  - Accounts copied by a supersede keep their directory details.
  - Tactics are listed in ATT&CK matrix order everywhere, so Defense Impairment comes before Discovery.
- **Navigation:**
  - Going back to Cases returns to the list you left: All, Mine or your filters.
  - A closed evidence panel or a followed link stays closed after a refresh.
  - On a phone, another case opens on Now, or on the note its link points at.
- **Smaller fixes:**
  - A case import with an empty item in a list is previewed instead of erroring.
  - Odd dates in Cases links and the timeline's time buttons no longer break the page.
  - Program overview bars render under any server language.
  - Case-link searches show the latest results.
  - A screenshot pasted during an upload is refused with a message.
  - The reclassify checklist matches the level you picked.
  - Colleagues on a closed case see "changes after closure" update.
  - Email templates don't stay "Unsaved" after a save, and two templates can't both be the lessons default.
  - Search snippets are dated on the organisation's calendar.
- **v1.6.4's notes** now also list three changes they missed.

### v1.6.5

A fix release with no migration. Things to check:

- **Ctrl/Cmd+Enter saves what you just typed.** The field you're typing in is committed before the form saves. This
  applies everywhere, including the Impact editor, a link's note, the paste review's source and a relationship's
  description. The brief's "Add a task" box adds the task.
- **`[[` tags** always link to the entity you picked, even when the text already cites evidence, or has an older link,
  with the same name.
- **Program figures:**
  - A campaign's ATT&CK coverage includes its cases' attack-chain techniques.
  - "Open cases" on the Program overview opens all open cases, not your default view.
  - A notice recorded under a combined code ("NY;CA") keeps its deadline when its codes share one, so its past outcome no longer moves. One whose codes have different deadlines is still judged code by code against today's rules.
- **Directory lookups** recover a minute after a domain controller stops answering, instead of staying unavailable
  until the app restarts.
- **Administration:**
  - Two admins setting the same new setting at once, or a save that loses to a reset, get a plain message instead
    of the error page.
  - Switching sections while saving keeps your other edits.
  - Email template bodies are limited to 8,000 characters, which is what can be stored.
  - The template list is locked while a template saves.
- **Smaller fixes:**
  - Saving a view twice and closing a tab twice no longer error.
  - Clearing Find while it searches clears the results.
  - A "To" date of 31 Dec 9999 in the access log, audit tab or timeline no longer breaks the page.

### v1.6.4

A release with two small migrations:
- `AccountDirectorySnapshots`, a new append-only, hashed table.
- `RetractEntriesAndVerdictTimes`, which adds three nullable `TimelineEntries` columns (`RetractReason`,
  `RetractedAtUtc`, `RetractedBy`) and a nullable `EntityVerdictChanges.EffectiveAtUtc`.

The DBA script is regenerated; sites where a DBA applies the schema run it first. Things to check:

- **Account indicators are looked up in Active Directory.**
  - When an Account indicator is added, CaseBook looks it up in AD as the app pool's identity and keeps what AD
    returns with the case. On the indicator's panel you can also choose "Look up now" and "Keep with the case".
  - Lookups go only to the server's own forest and to domains it trusts. Accounts in other domains, local `.\name`
    accounts and accounts on the server itself are shown as "Not looked up", and no lookup is sent for them.
  - Each add spends at most 50 lookups and 15 seconds waiting on the directory. A domain that fails isn't asked
    again for a minute.
  - **Check:** the web server can reach its domain controllers over LDAP. Where it can't, account indicators are
    still added, just without directory details.
- **New in the case record:**
  - A timeline entry can be retracted, with a reason. It stays visible as retracted and leaves the counts, the
    attack chain and the reports.
  - A verdict can record when it was reached.
  - A Command line entity type holds full command lines.
  - Date and time fields keep what you type, whichever field you type it in.
  - `[[` tags an entity in plain text boxes too, always linking the one you picked.
  - Long IOCs wrap instead of overflowing.
  - An entity's type follows its value as you type, until you pick a type yourself. A bare name the directory
    knows is added as an Account, in single adds and bulk pastes.
  - A case's detected time can't be moved after a verdict was reached; the save says so.
- **Reassigning:** reassigning or rebalancing a case onto someone who observes it moves them into the seat being handed
  over (for example Analyst) and tells them, as for anyone newly assigned.
- **Keyboard:** Ctrl/Cmd+Enter saves the form it's pressed in (an inline task, notice, impact, relationship,
  improvement action or comment), never another form's composer or a hidden tab's.
- **Locking:** the idle lock and *Lock now* no longer stop at "Leave site?" on Administration with unsaved settings.
- **Who's emailed:** task, deadline and stale-case reminders, the digest and the calendar feed go only to people
  who still hold a role with View cases, and who can see a restricted case. A task whose owner no longer can
  falls back to the incident commander; the escalation email still names the real owner. An email subject that
  picked up a line break from a token is sent on one line, so it is no longer lost.
- **Figures for past quarters stay as reported:**
  - "Reported to regulators" and "Detection to regulatory report" keep their values if the case is later made
    unreported or reported again.
  - Notice outcomes keep their values when the trigger is withdrawn.
  - A legacy notice coded "NY;CA" counts for both regulators.
- **Integrity:** the record check also flags a retracted entry that was put back as current, and an account
  snapshot with no hash.
- **Admin:**
  - Changing a taxonomy label that already has an override saves.
  - Deadline rules, email templates, taxonomy order and the report layout refuse a save from a stale page.
  - Double-clicks and simultaneous saves no longer show the error page.
  - A config bundle whose Entity types order was saved before Command line existed imports.
  - Keyboard settings refuse `;`, `,` and Ctrl chords on K.
- **Upgrade script:** `-Confirm` asks once, the upgrade question.
- **Refreshing an open case** no longer shows an error (it happened when times are shown in local time).
- **Scrolling:** nothing on the page (timeline items, table headers) draws over the top bar any more.
- **Smaller fixes:**
  - The idle lock and draft handling, overlapping loads on list pages, the Cases month drill-in, the Program
    overview links with exercises, the Find retry and the vendor-case figures.
  - Account names from trusted domains, IOC CSV headers named by type, tab-separated pastes, nested Word template
    tables, and pins and tabs closed in two windows at once.

### v1.6.3

A fix release with two small migrations (`NoticeDueAt`: a nullable `JurisdictionNotices.DueAtUtc`;
`TaskCompletionRecordedAt`: a nullable `ActionItems.CompletionRecordedAtUtc`; the DBA script is regenerated). Things to
check:

- **Slow start-ups don't roll back.** The shipped `web.config` gives the app 600 seconds to start (IIS's default is 120),
  so a long migration isn't cut off, and the upgrade's warm-up now waits up to 660 seconds and reads IIS's "still
  starting" answer (500.37) as starting, not a crash.
- **Past quarters' notice and improvement-action figures are frozen.** Each regulator notice keeps the deadline it was
  made against, so its on-time outcome doesn't move when a rule's window or the materiality decision changes later
  (notices made before this release get today's at start-up). Improvement-action figures are worked out from each
  action as it stood at the quarter's end.
- **Exercise links made before v1.5.7** no longer bring a drill into a live campaign's rollup (or the reverse); the links
  stay on the cases.
- **Find**: a colleague's email address or `DOMAIN\user` lists their cases, entries and tasks with the indicator's
  results; `owner:` lists tasks only and `type:` entries only; a word only inside a link's hidden target (`evidence`,
  part of an id) no longer matches.

- **Upgrades run with the new release's own script.** `-Version` downloads the bundle and then hands over to the
  `Upgrade-CaseBook.ps1` inside it, so a fix to the upgrade itself applies to the upgrade that ships it. The kept scripts
  from v1.6.0-v1.6.2 don't hand over yet, so for this upgrade use `-BundleZip` with the bundle's own script (or `-Version`
  from a v1.6.1 or v1.6.2 copy, whose warm-up is already right).
- **One kept-scripts folder per site.** The copy is now `<site parent>\<site folder>-deploy`, with `site.txt` naming the IIS
  site, and Administration › Updates puts `-SiteName` in its command. For a site in `C:\inetpub\CaseBook` that's the same
  `CaseBook-deploy` as before; a site in another folder gets its own after this upgrade (the old shared `CaseBook-deploy`
  can then be deleted if no site named `CaseBook` lives beside it).
- **`-AppSource` and `-Build` upgrades record the version** read from the new build, instead of leaving the previous one.
- **The update check signs in to a proxy** as the app pool's account (`Updates:Proxy`), and a 407 is reported as the
  proxy refusing, not GitHub.
- **Notification deadlines after an admin change.** Editing a reported case's impact assessment (just the affected count)
  no longer reopens it when an administrator has since added a jurisdiction to one of its data elements; only an element
  added in that edit brings in a new regulator. The report's "Notification triggers" lists the regulators in play when
  the case was reported.
- **"1 change after closure by system".** v1.5.8-v1.6.2 recorded the start-up back-fill of each reported case's
  jurisdictions as a change, so closed reported cases showed one change after closure (header, report Outcome line).
  That entry is no longer counted, and the back-fill no longer writes one.
- **Program figures for past quarters** use the severity and classification a case had then for SLA met/missed, and a
  close dated before the case was filed counts. The Program Overview's 12-month chart and the metrics CSV follow the same
  rule, so a case reopened later no longer moves past months.
- **IOC feed**: an occurrence without its own TLP carries the default (`Reporting:DefaultTlp`), as reports and STIX do.
- **Critical alerts with email off** wait in the outbox until email is on again, instead of being given up after a few
  hours with a "may not have heard" notice.
- **Find** finds entries, notes, briefs and tasks that tag an entity by its label, marks archived and exercise cases in an
  entity's case list and the palette, and says back filters it can't use.

From a whole-codebase review (BUG-262 to BUG-326 in the tracker):

- **Settings have limits.** Numbers that become times (scan intervals at most 744 hours, escalation and lead times a
  year, stale days 366, retention 100 years, the access-log coalesce window a day) are refused above that on the settings
  page and in a configuration bundle, and a value above it in `appsettings.Production.json` is read as the limit. A huge
  interval meant as "never" used to stop the app. Link templates must be a full `http://` or `https://` address with
  `{0}` in it, and the public base URL a full address. **Check:** a bundle exported from an older version with a larger value is refused
  with the setting named; lower it in the bundle or on the source server.
- **A case with many open tasks** can save its brief and close again (the next-steps snapshot was over the brief's limit).
- **Upgrades check the probe first.** Before anything is stopped, the script asks the site at its probe address; with no
  answer it stops, changes nothing, and asks for `-HealthUrl`. A binding with an IP and no host name is probed at that IP.
- **Releases run every CI check on the tagged commit** (the SQL Server tests, the DBA script, the upgrade path) before
  they publish.
- **Verify** flags an earlier version of a note, entry or brief set back as current in the database, and row hashes now
  cover an indicator's TLP marking and pin and an evidence file's description (format 3, `v3:`). Existing rows keep
  verifying as written and move to format 3 when next saved; nothing is re-hashed at upgrade.
- **Notices** are judged against the deadline kept when they were given everywhere (the case page and the Legal register
  too), a case that goes back to unreported keeps the jurisdictions it was reported against (removing an element added
  by mistake reports it again), and the program report
  counts each notice in the quarter it was given.
- **The SIEM stream** sends to each destination on its own, so a webhook that doesn't answer no longer delays or drops the
  Event Log's events, and critical events go first.
- **Shared editing**: applying the ATT&CK matrix and saving cited evidence change only what you changed, so a colleague's
  tag or citation added meanwhile stays; Team workload's rebalance keeps an incident commander's seat filled.
- **Stage gates** need unique names, and a climb's checklist shows a stricter threshold on a higher rung.
- **Past quarters' SLA figures stay as reported.** The program report (and its quarterly email) judges each containment,
  resolution and detection against the target in force when it happened, rebuilt from the audited changes to the SLA
  settings, so tightening a target no longer changes board packs already sent. A target set only in the server's
  settings file has no history: today's file value applies. The Program Overview's "Within target" figures follow the
  same rule; the live at-risk and breached flags on open cases use today's targets.
- **A cancelled task** can't be set to Done in Edit (reopen it first), as elsewhere.
- **Open questions written as prose with a list after it** (a question added later) pair each listed question with its
  task; the Briefing now shows prose questions too.
- Smaller fixes: the activity feed keeps a renamed case's history; case-list pages don't repeat or drop cases; the indicator
  CSV keeps the feed's TLP column; reports and report layouts after closure aren't "changes after closure"; a Word template's
  picture field alone in a table cell no longer makes an unreadable file; filing a case in the repeated autumn DST hour works.

From a second whole-codebase review (BUG-327 to BUG-368):

- **Upgrades name the site as the app knows it.** The warm-up probe connects to the binding's address but sends the
  site's name (its binding's host name, else the first `AllowedHosts` entry) as the Host header, so a site bound to an IP
  or `*` is no longer answered 400 and rolled back after its migrations. A 400, or any answer the warm-up would read as
  "not started", now stops the upgrade in its preflight, before anything changes. **Check:** if the preflight stops, add
  the site's name to `AllowedHosts` or pass `-HealthUrl` with the name you open the site with.
- **The upgrade asks before it changes anything** ("Proceed with backup + deploy?") unless you pass `-Force`, and
  `-WhatIf` runs the checks and stops before any backup.
- **New installs' HTTPS binding requires SNI**, so its certificate is bound to the site's name and doesn't take the
  server-wide 443 slot. Existing sites keep their binding (tick "Require Server Name Indication" in IIS Manager and pick
  the certificate again if another site shares the server).
- **Restricted cases:** a queued import naming a case its submitter couldn't see previews and applies as a new case for
  every reviewer.
- **Config bundles exported by v1.0.x and v1.1.x** verify and import again (they were reported as altered).
- **Audit trail:** re-recording materiality or editing a legal referral records the real previous values, and only the
  fields that changed.
- **Lock now** locks even with an unsent draft, instead of stopping at the browser's "Leave site?" prompt.
- **The integrity alarm banners** appear when a break is found and clear when it's fixed, without reloading the page.
- **Keyboard:** Ctrl+Enter inside a dialog, sheet or side panel no longer records the composer behind it (in an action
  dialog it applies the dialog, except Archive); Enter while editing an entity saves the edit instead of adding a second
  entity; the entity form keeps what was just typed; Enter in the command palette opens what was typed.
- **Drafts:** switching the timeline to Attack chain or the composer to an event, disclosure or question mode keeps a
  half-written Finding or Decision.
- **After a case switch** an action that was still saving only says it's done; it no longer reloads, or opens the close-out
  of, the case you moved to. The screenshot preview and the archive message stay with their case.
- **Post-incident review:** reopening a not-pursued improvement action clears "No improvement actions identified", so the
  review saves again; the program report counts a review from when "What happened" was first filled in.
- **Milestones:** backdated regulator notices and task completions count as new in the brief's "changed since" and the
  handoff pre-fill, "Task done" credits who completed the task, and editing the last handoff no longer drops earlier work
  from the next pre-fill.
- **Admin:** a double-click on Save, Add or a confirm button acts once; saving a report profile someone changed since you
  opened it is refused instead of undoing their change; renaming a Word template no longer restores an archived one; a
  Word template with malformed XML is refused as unreadable; a long data element label gets a key that fits; a custom role
  with a numeric name no longer reads as a built-in role; keyboard settings accept only chords that can fire; the scan
  intervals and access-log window say that 0 means their default.
- **Chat posts** show case text as typed: Slack no longer turns `<!channel>` or `<url|label>` in a title or note into a ping
  or a disguised link, and Teams cards no longer turn `[label](url)` into a link.
- Smaller fixes: reports for a case number with `| " : < > ? *` are stored under a safe file name (the download keeps the
  name); report jobs log unexpected failures and show a plain message; dropping more than 50 files on Evidence says so;
  the entity graph keeps your layout when an entity is added; side panels, the reassign dialog, the Indicators and Due
  pages, the program report and overview, improvement actions and ATT&CK coverage always show the latest choice; a new
  user's first two tabs no longer crash the second; New case waits for a running overlap check before filing.

### v1.6.2

A fix with no migration. Things to check:

- **The API now reaches the app.** On IIS, every request under `/api` (API imports, and the import schema the upgrade
  uses to check the new build started) was answered by IIS itself with a 404 and never reached CaseBook. The published
  `web.config` held CaseBook's handler in `<location path="." inheritInChildApplications="false">`, and IIS didn't apply
  it to the `/api` path the installer opens to API tokens. This release ships a `web.config` without that wrapper, and
  the upgrade puts it in place. If you edited the live `web.config` by hand to set `inheritInChildApplications="true"`,
  the upgrade replaces it with this one, which works the same way.
- **The upgrade only counts CaseBook's own answer as "started"**: the import schema. v1.6.1 also took an IIS 404 page
  for the app. If IIS answers `/api` itself, the script says so and checks the site root as you instead.
- **The upgrade keeps `VERSION.txt`**, so the next upgrade shows the version it's replacing instead of "(unknown)".
- **`Verify-Install.ps1` checks that `/api` reaches CaseBook.**

After upgrading, open `https://<your site>/api/import/cases/schema`: it should show the JSON schema, not a 404 page.

### v1.6.1

A fix to the upgrade script only, with no migration and no change to the app. Upgrading to v1.6.0 or earlier with the
older script could stop at "Warming up", wait the full three minutes and roll back, although the new build had started.
Its probe went through the administrator's proxy, which on many servers can't reach the site, and followed redirects
to an HTTPS address that wasn't bound. The probe now goes straight to the site and says what each attempt got. If you
were rolled back, upgrade again with this release's script: `-BundleZip` with the v1.6.1 bundle. (Not `-Version v1.6.1`
from the kept v1.6.0 scripts: before v1.6.3, `-Version` ran the kept, older script, with the old probe.)

### v1.6.0

A feature release with no migration. Things to check:

- **The app knows its version.** Administration › Diagnostics shows the release (e.g. `1.6.0 (a1b2c3d)`); earlier builds
  all read 1.0.0.0, and so did the `AppVersion` in an exported configuration bundle.
- **Update check (off by default).** Administration › Updates can list newer releases with these notes. Turning it on
  makes the web host call `api.github.com` once a day; see "Knowing when a release is out" in
  `docs/UPGRADE.md` for the firewall and proxy settings.
- **One-command upgrades from the next release on.** This upgrade (still `-BundleZip`) keeps a copy of the deploy
  scripts in `<site parent>\CaseBook-deploy`, writable only by Administrators and SYSTEM. The next upgrade is
  `& '<site parent>\CaseBook-deploy\Upgrade-CaseBook.ps1' -Version vX.Y.Z`, which downloads the bundle and checks its hash.

### v1.5.9

A maintenance release with no migration and nothing to check. The start-up back-fill and the recheck after a data
element's jurisdictions change read a case's data elements and notices in separate queries, and the STIX pattern check
on imports has a time limit.

### v1.5.8

A bug-fix release with one migration, applied at startup (`PendingImportHash`: a hash column on `PendingImports`). Things to check:

- **A due date or improvement target picked without a time now means the end of that day on the organization's
  calendar** (23:59 in `Organization:TimeZone`), not in the picker's zone, so every viewer and every report shows the day
  that was picked. A viewer far from the organization's zone sees such a task fall due at the organization's end of day.
  Values saved before this release keep their instants.

- Also: Find counts every matching entity and lists the most widespread; a pasted screenshot is stored only when its
  timeline entry is saved; the import API matches a retried submission by its hash.

### v1.5.7

A bug-fix release from a review by workflow, with one migration, applied at startup (`ReportedJurisdictionsAndAppendedBriefs`:
a column on `Cases` and one on `CaseBriefs`). At the first start, each reported case records the jurisdictions that were in
play (its notices', where it has any). Things to check before or right after upgrading:

- **API tokens edited in the database before v1.5.6 are left flagged, not signed off.** The v1.5.6 start-up back-fill
  recorded every existing token as clean. From this release, a token whose row disagrees with its audit trail (revoked in
  the trail but live in the row, or roles or expiry different from its Create entry) isn't recorded, and the integrity
  check flags it. **If the banner shows an API token after upgrading, treat it as a possible tampering incident and
  revoke it.** A token whose secret was swapped in the database can't be detected: the trail never recorded it. A
  v1.5.6 install already signed its tokens off; review them in Administration › API tokens.

- **A reported case keeps the jurisdictions in play when it was reported.** Changing a data element's jurisdictions now
  affects only cases not yet reported (one whose remaining jurisdictions are all notified becomes reported), and an
  analyst adding an element to a reported case no longer records a notice to a regulator that wasn't told.

- **With `Email:Enabled` off, scheduled reminders, the executive report and critical alerts are held**, not recorded as
  sent, so the ones still due go out when email is switched on. **Expect a catch-up of reminders** the first time email
  is turned on after running with it off.

- **The IOC feed (`/export/iocs.csv`) has a `tlp` column**, last, so existing column positions don't move. Every
  indicator is still included; **filter RED / AMBER+STRICT in the consumer** if it shouldn't get them.

- **A role an active API token holds can't be deleted.** Revoke the tokens or change their roles first.

- **Exercise and live cases can't be linked or superseded into each other.** Existing links are left as they are.

- **Find:** `status:open` leaves archived cases out (archived results are labelled), `after:`/`before:` filter entities by
  when they were added, `by:` means who first recorded an entry, and a quoted word is never read as a person.

- **Program report:** past quarters are figured from the history as it stood at the quarter's end, so a quarter's
  figures can differ slightly from what an earlier version showed for a case reopened or reclassified since.

- Also: the Reopen dialog asks when a legacy case was contained or resolved where it needs to; a materiality call taken
  back and made again is shown as the clock restarting; the close gate notes a classification lowered within 7 days of
  closing; a stuck import can be reopened by any reviewer; reminders reach a task owner named by email or UPN; manager
  emails fall back to the user mirror while AD can't be reached; the import preview can file a case restricted and
  assigned to you; pasting a verdict onto an Unknown indicator records "Set by paste".

- **A config bundle is held to the admin pages' rules.** Import (and its preview) now skips, and says so, an AD mapping
  with no group or to a role that doesn't exist; it refuses taxonomy keys that hide every option of a list or reorder
  one that can't be, and labels longer than the Taxonomy page allows. A gate check's threshold below its floor is raised to it. Role
  permissions are read by name only, so a permission written as a number (`7`) in a role grants nothing. **Re-export
  a bundle that an older server produced by hand-editing** if it relied on any of these.

- **Lessons-learned templates and the legend.** With `Reporting:LessonsLegend` set, a Word template used for the
  lessons-learned report must contain `{{report.legend}}` (the lessons starter has it in its header); one without it
  is refused, as one without `{{report.tlp}}` is. **Add the field to your lessons template** before generating.

- **Word templates with fields that load or run something are refused** (DDEAUTO, INCLUDETEXT, INCLUDEPICTURE and the
  like, and altChunk imports), at upload and when a report is filled from one already stored. Page numbers, dates,
  tables of contents and hyperlinks are fine. **A report from such a template fails until its file is replaced.**

- **Two system API tokens can't share an identity.** A new system token whose name differs from an active one only by
  case or punctuation ("Splunk SOAR" / "Splunk-SOAR") is refused. Existing tokens aren't changed.

- **Reports print a due date, an improvement target and the materiality decision day on the organization's calendar**
  (they printed as UTC dates, a day late west of UTC). The headings say "Target" rather than "Target (UTC)".

- **The access log's date range includes sessions that began in it and ran past it.** A filtered view or CSV may list
  more sessions than before.

- **The Desk** leaves exercise cases out (as Due work and Team do) and shows notes that mention you on any open case you
  can see, not only the ones you're on.

### v1.5.6

A bug-fix release with one migration, applied at startup (a row hash on API tokens). Four things need a look before
or right after upgrading: seal copies on disk are named differently, two settings are now bounded, filing a case
straight onto the ladder needs Change classification, and **an API token the integrity banner flags after the upgrade
was added outside CaseBook**. Read the notes below before upgrading.

- **A case's Audit tab and audit CSV now include what was recorded under its earlier numbers.** A promotion out of
  Complex Event (or a renumber) used to cut the trail at that point. Evidence uploads, report generate/approve and case
  links are now also stamped with their case, so they appear there (entries already written without one stay as they
  are).

- **Seal chain head verifies the whole chain first** and refuses while it doesn't verify.

- **Seal copies on disk have the seal's id in the name** (`seal-<sequence>-<time>-<id>.json` and `.tsr`). Update any
  job that picks them up by the old pattern.

- **Two settings are bounded.** `Security:IdleTimeoutMinutes` takes 0 to 1,440 (a larger value is held to 1,440), and
  `Compliance:NotificationDeadlines:DefaultWindowHours` takes 1 to 8,760 (a value outside that from the file falls back
  to 72). **Check both** if either was set high in `appsettings.Production.json`.

- **A config bundle is refused when an item breaks the admin pages' rules**: a notification rule window outside 1 to
  8,760 hours, a blank label, or no case outcome left active. Rule codes are stored upper-case.

- **Filing a case straight onto the ladder (Adverse Event or above) needs Change classification.** All built-in editor
  roles have it; **check custom roles** that should file Incidents or Breaches directly.

- **Evidence thumbnails are rate-limited per user** (`RateLimiting:Thumbnails`, 300 a minute by default), and refused
  cross-site loads no longer spend the download budget.

- **Manager escalations, the executive report and the digest go only to people the directory still holds** (Windows
  sign-in): a disabled or expired account, or one whose groups no longer map to a CaseBook role (Manager, for the first
  two), is left out.

- **Installer and upgrade scripts.** Re-running `Install-CaseBook.ps1` keeps an existing `appsettings.Production.json`
  (the newly generated one is written beside it as `.new`; `-ReplaceSettings` overwrites), stops the app pool before
  publishing, and asks for a normal service account's password. `Upgrade-CaseBook.ps1` waits for the app pool's worker to
  exit before copying files. Both probe over TLS 1.2 on Windows PowerShell 5.1. `Enable-Ledger.ps1` fails when the first
  digest couldn't be saved, and judges the last backup's age on the SQL host's clock.

- **API tokens are chained and checked like other records.** One migration adds a row hash to `ApiTokens`. At the first
  start, each token the audit trail's own Create entry names is recorded with its hash. A token row that no entry names
  was added outside CaseBook, and the integrity check now flags it: **if the banner shows one after upgrading, treat it
  as a possible tampering incident** (it can grant API access) and revoke it.

- One migration, applied at startup (`ApiTokenRowHash`).

### v1.5.5

A bug-fix release with one migration, applied at startup (a wider API-token role column). Three things need a look
before or right after upgrading: `Verify-LedgerDigests.ps1` now exits 2 when it couldn't run the check, the Legal and
integrity-alert lists hold addresses only, and Material calls recorded after an Under-review save may carry an early
decision time. The 10-minute integrity check now re-hashes the whole chain every 6 hours rather than every cycle.
Read the notes below before upgrading.

- **`Verify-LedgerDigests.ps1` exits 2 when it couldn't run the check** (server unreachable, sign-in or permission
  refused, a timeout). Exit 1 is kept for a ledger that doesn't match its digests. **Update any scheduled task or
  monitor that treats every non-zero exit as tampering.**

- **The Legal and integrity-alert distribution lists hold addresses only.** A pasted `a@x; b@x` is split into one
  per line; anything that isn't an address is refused on save. **Check both lists**: one saved as `legal@corp;
  privacy@corp` on one line sent to the last address only.

- **Materiality "Under review" keeps no decision time.** The decision time is asked when the call is made (Material
  or Not material). **Check open Incidents and Breaches whose Material call was recorded after an Under-review save**:
  the decision time may have been pre-filled with when the review began, starting the notification clock early.
  Re-record it with the real time.

- **The 10-minute integrity check no longer re-reads the whole audit log.** Each cycle hashes the entries written
  since the last one and checks every record, as before; the whole chain is re-hashed every 6 hours and on *Verify
  now*. So an edit to an *older* audit entry is now found within 6 hours, not 10 minutes (new entries, records
  changed in the database and the latest seal are still checked every cycle).

- **A config bundle counts as this server's only if it carries this server's key.** "Signed by this instance" used to
  compare the key id the bundle states, which is public, so a bundle signed with any key could claim it. A bundle
  that names this server's key id but carries another key is now refused; one signed elsewhere asks you to confirm
  its source, as before.

- **Config import keeps one active stage gate per transition.** A bundle that would leave a transition with two
  active gates (yours and one of the same transition under another name) is refused at preview: deactivate one,
  then import.

- **Downloads refuse frames and loads started by another site.** An evidence file, report or export opens from a
  link or button in CaseBook, a typed or bookmarked address, or a desktop mail client's link, not from a link or
  frame on another web page.

- **The installers write AD role groups as `DOMAIN\Group`.** A bare name maps only a group in the web server's own
  domain (v1.5.4), so `New-CaseBookConfig.ps1` and `Install-CaseBook.ps1` now resolve each group and store its own
  domain. Existing installs aren't changed.

- **The upgrade warm-up asks the app itself** (`/api/import/cases/schema`, anonymous at the IIS level on an installed
  site) and needs a `200`, so a build that crashes at startup is rolled back. A failed rollback copy now leaves the
  app pool stopped and says how to restore the snapshot by hand.

- **Administration › Settings shows the values in force**, including those set in the server's appsettings files
  (which it now says), and *Reset* returns to that value.

- **One migration widens the API token role column** (`ApiTokenRolesWider`: `ApiTokens.RolesCsv` to 4,000).

### v1.5.4

A bug-fix release with two migrations, applied at startup (an audit-log index, which takes a moment on a large audit
log, and a wider user-role column). Two changes need a look before upgrading: a bare AD group name now maps only that
group in the server's own domain, and a blanked SLA target is now off. Visible to the team: deadline reminders name
every jurisdiction, skipping Recovery asks when it was resolved, Markdown images show as links, and stale task edits
are refused instead of undoing a colleague's change. Read the notes below before upgrading.

- **A bare AD group name maps only that group in the server's own domain.** A mapping written `SOC-AppAdmins` used
  to match a group of that name in any domain the server trusts, so whoever could create groups in a child or
  trusted domain could make one and get its role. It now matches the server's domain (and local or built-in groups)
  only. **If people from another domain sign in through a mapping by bare name, rewrite it as `OTHER\Group`** in
  Administration → Roles & access before upgrading, or they lose that role.

- **A blanked SLA target is off, as its hint says.** Clearing a Containment or Resolution hours box saved it blank,
  but the shipped `appsettings.json` default (4 h, 12 h, …) kept applying, while the Settings page showed it blank. A
  blank target now means none. **If you cleared one and its cases were still being measured, they stop being
  measured after the upgrade**; use *Reset to default* to get the default back.

- **The import API is stricter about what it takes, and kinder to retries.** A document now carries up to 2,000
  indicators, 1,000 timeline entries and 500 tasks (split a bigger one); a time without an offset is read as UTC, as
  the schema says, not as the server's local time; a chunked body over 5 MiB gets 413; an unexpected error gets
  `500 { error, ref }` instead of a redirect to an HTML page; and an identical document resent by the same token
  while the first is still waiting for review returns that one (`200`, `duplicate: true`) rather than queueing it
  twice. **Check producers (SOAR, XSIAM playbooks) that send offset-less times or very large documents.**

- **One migration adds an audit-log index** (`AuditLogEntityIndex`: `IX_AuditLog_EntityType_EntityId`). Opening a
  closed case and downloading a report each looked up a record's own audit entries, which scanned the whole audit
  log. On a large audit log the index takes a moment to build at first start. On a site that enabled the SQL Server
  ledger it's added to the ledger table in place.

- **One migration widens the user mirror's role list** (`UserRolesWider`: `Users.RolesCsv` from 400 to 4,000
  characters). A user with several long-named roles overflowed it, the update failed silently on every request, and
  the mirror kept their old roles, which decide who a restricted case's notifications reach. Such a failure is now
  logged too.

- **Deadline reminders cover every jurisdiction in play.** Only the soonest-due clock was reminded, and a breached
  jurisdiction stays soonest until it's notified, so a second jurisdiction could go at risk and breach with no
  reminder naming it. Each jurisdiction's clock is now reminded as it enters at risk and breached (jurisdictions on
  the same deadline share one line). Reminders already sent aren't sent again.

- **Skipping Recovery says when it was resolved.** Moving a case to Post-incident without going through Recovery
  never set its resolved time, so its resolution clock ran on: SLA-breached on the list and dashboard, and "not
  resolved" in Needs action. The move now asks when it was resolved. Cases that already skipped Recovery are
  unchanged: their resolution clock runs until they close (closing stops it), or until one is moved to Recovery,
  which records that move's time as when it was resolved (a move can't be dated before the case's previous one).

- **The STIX export's identity id is a valid RFC 4122 UUID.** It was derived from the organization name without the
  version and variant bits STIX 2.1 requires, so strict consumers (the OASIS `stix2` library, validators, some TIPs)
  refused the bundle or dropped the identity. It's now a version-5 UUID, which **changes the identity id once**: a
  platform that keyed on the old one sees a new author for later exports.

### v1.5.3

A bug-fix release with five migrations, applied at startup, and a first start that records each history row's hash
in the audit trail (one audited system entry per row, once). Visible to the team: skipping Containment needs a
recorded decision, an archived case is restored before its classification, materiality or impact changes, and
Supersede warns in more cases. Touching the deployment: DBA-applied installs now run the schema with `sqlcmd -I`, a
failed upgrade that already migrated leaves the app pool stopped, and audit entries use format 2, so update any
compliance-bundle verifier of your own. Read the notes below before upgrading.

- **A brief left current by v1.5.2's clean-up is corrected.** Where two brief saves had raced, v1.5.2 kept one
  current but could keep the earlier, which then disagreed with the case summary. A data migration makes the later
  one current (`CaseBriefLatestCurrent`; no schema change).

- **Audit entries are written in format 2.** An entry's reason and its label were each appended to its hash only when
  present, untagged, so the two could be swapped (a correction's reason turned into a label, dropping it from the
  trail) without breaking the chain, and no field was escaped. New entries record `Format = 2`: their canonical
  starts `v2|`, escapes `\` and `|`, and names the reason and label. Earlier entries verify exactly as they were
  written, and a first-format entry after a format-2 one is a break. One migration adds the nullable
  `AuditLog.Format` column; on a site that enabled the SQL Server ledger it's added in place. **If you verify
  compliance bundles with your own script, update it to the format-2 rule in the bundle's VERIFY.txt** (the CSV
  gains a `Format` column).

- **Skipping Containment is a recorded decision.** Moving a case from New or Triage straight to Eradication,
  Recovery or Post-incident now asks when it was contained, or why containment wasn't needed. Before, such a case
  kept a running containment clock, so it showed as SLA-breached and "not contained" until it closed. "Not needed"
  stops the clock and leaves the case out of time-to-contain (one migration, `Cases.ContainmentNotNeededReason`).
  Cases that already skipped Containment are unchanged.

- **History rows' hashes are recorded in the audit trail.** v1.5.2 gave existing status, classification, materiality,
  severity, assignment and verdict changes, case assignments and evidence citations their row hash but wrote it only
  to the row, so deleting one, or editing it and recomputing its hash, still passed the record check. At the first
  start after this upgrade each such row's hash is recorded as an audited change (actor: the system), once; from then
  on a deleted, cleared or re-hashed history row is caught. A row that no longer matches the hash v1.5.2 gave it isn't
  recorded, and the record check reports it.

- **STIX imports keep TLP markings.** An imported indicator now takes the TLP its `object_marking_refs` name (TLP 2.0
  or 1.0, or a TLP marking-definition in the bundle; the most restrictive if several), so a partner's TLP:RED intel is
  no longer exported at the default AMBER. The case-import document gains an optional `tlp` on each entity. An import
  never lowers a marking an indicator already has on the case.

- **A reminder is recorded as sent only once its send has finished.** v1.5.2 kept the scans' sent marks in the
  database (BUG-95), but a mark was written before the send, so a scan that stopped part-way (the app shutting down
  mid-send, or a crash) left marks for reminders that never went out, and they were never sent. A mark is now a claim
  until the scan's sends finish; a scan that throws drops its claims, and claims left by a process that stopped are
  cleared at the next start, so those reminders go out (one migration, `NotificationMarks.ConfirmedAtUtc`; existing
  marks count as sent).

- **A queued import that failed part-way carries on where it stopped.** When applying a submission from the import
  queue failed after writing some items, it went back to the queue (BUG-116) but reopening it re-read the original
  document, so applying it again wrote the summary note, timeline entries and tasks a second time. The reviewed
  preview is now kept with what it wrote (a new `PendingImports.ResumeJson` column; one migration, applied at startup).

- **DbaApplies installs: `Install-Database.ps1 -ApplySchema` now applies the schema with `sqlcmd -I` too.** v1.5.2 added
  `-I` only to the database-creation step, so on a host without the SqlServer PowerShell module the schema step still
  ran with QUOTED_IDENTIFIER off and stopped at the first filtered index (a fresh install got no schema; an upgrade
  stopped at `IX_CaseBriefs_OneCurrent`). If that happened, re-run the script (it's idempotent) or apply
  `deploy/sql/casebook-schema-sqlserver.sql` with `sqlcmd -I` yourself.

- **A store folder the upgrade script creates gets the app's write access.** When an upgrade adds a missing
  data-folder setting it creates the folder; that folder used to copy the data root's permissions, which after the
  v1.5.2 lockdown give the app only read, so uploads to it failed with "Access denied". It now also grants the app
  identity Modify, as the installer does for each store. A folder an earlier upgrade created (on an install that began
  before v1.2.0, typically `report-templates`) may have no grant of its own; after the v1.5.2 `icacls` lockdown, give it
  one:

  ```
  icacls "D:\CaseBook-Data
eport-templates" /grant "CONTOSO\svc-casebook$:(OI)(CI)M"
  ```

### v1.5.2

A bug-fix and hardening release with six migrations, applied at startup, and a first start that gives existing
history rows their row hash. Several changes are visible to the team (a reason to leave Closed, reopen before raising
a closed case, report TLP raised to its most restrictive content, `{{report.tlp}}` required in Word templates) and two
touch the deployment (the data-root ACL and the app pool's recycling); read the notes below before upgrading.

- **The installer now locks down the data root.** `Install-CaseBook.ps1` removes what the folder inherits from the
  volume and grants only SYSTEM, local Administrators and the app identity (Modify on each store). Before, on a
  default NTFS volume `BUILTIN\Users` could read evidence, reports and the data-protection keys. The upgrade script
  doesn't change an existing install's permissions; to apply this to one, run in an elevated prompt (with your data
  root and app identity):

  ```
  icacls "D:\CaseBook-Data" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "CONTOSO\svc-casebook$:(OI)(CI)RX"
  ```

  The app identity's Modify grants on the store folders the installer made are explicit and stay (for a folder an
  upgrade created, see the next release's notes). Check that a backup agent reading the
  data root runs as SYSTEM or holds the backup privilege.

- **STIX exports are marked with the default TLP.** An indicator with no TLP of its own now carries
  `Reporting:DefaultTlp` (AMBER unless changed), and the bundle's report object at least that, as the Word report
  already did. Before, such a bundle went out with no marking, which a TIP or partner reads as unrestricted.

- **DbaApplies installs: the schema script now runs.** `deploy/sql/casebook-schema-sqlserver.sql` failed with
  "Invalid column name 'TemplateId'" (or 'TemplateFileName' on a re-run), so a DBA-applied install or upgrade stopped
  part-way. Its data statements now run through `EXEC`, and CI applies the script to an empty database twice. Apply
  it with `sqlcmd -I` (QUOTED_IDENTIFIER on); `Install-Database.ps1` now passes `-I` when it falls back to sqlcmd.

- **Audit exports name a removed record `Delete`**, not `SoftDelete` (the audit CSV, the compliance bundle). It was always a
  hard delete; only the name changes, and earlier entries verify unchanged. Update any SIEM or spreadsheet filter that
  matches `SoftDelete`.

- **Leaving Closed needs a reason, and a closed case is reopened before its classification goes up.** Change phase
  out of Closed now asks for a reason, as Reopen does. Raising a closed case's classification (to Breach, say) is
  refused with "Reopen the case to raise its classification", so closing it again runs the close checks for the
  higher class. Lowering it while closed is still allowed.

- **Every Word report template must print `{{report.tlp}}`.** The upload check now refuses a template without it,
  and a template stored before this upgrade that lacks it is refused when a report is generated from it ("has no
  {{report.tlp}} field"). Before, a report recorded as TLP:RED could print with no marking. Add the field (the page
  header is a good place) and replace the template's file under Admin → Report templates.

- **Case numbers use the organization's calendar.** A new case's year, and a Complex Event's date, now come from
  `Organization:TimeZone` rather than UTC, so a case opened at 9 pm in New York on 31 December takes that year's number.
  Existing numbers don't change. The materiality "decided on" date in milestones is shown in your display zone.

- **Exercise escalations are marked EXERCISE.** An exercise case escalated to Breach used to send the real Legal
  email, chat alert and SIEM `BreachEscalated` event unmarked. They now carry "EXERCISE" (the email subject and body,
  the chat title, the SIEM event's `msg`). To send none of them, set Settings → Notifications → Exercise escalations
  to "Don't send them". A SIEM rule on event 5503 can exclude exercises by matching `msg` starting `EXERCISE`.

- **One table migration** (`NotificationMarks`): what the reminder, digest and executive-report scans have sent is
  now kept in the database, so an IIS recycle or a deploy no longer resends every active reminder, digest and the
  executive report. Marks older than 180 days are pruned.
- **The app pool no longer recycles on a schedule or overlaps.** `Install-CaseBook.ps1` and `Upgrade-CaseBook.ps1`
  set `recycling.periodicRestart.time` to `00:00:00` (IIS's default is every 29 hours) and turn on
  `recycling.disallowOverlappingRotation`, so two CaseBook processes never run side by side. `Verify-Install.ps1`
  warns when either isn't set. A recycle still happens on a config change or a crash; the marks cover those.

- **One table migration** (`AlertDeliveries`): a breach-escalation or integrity-alarm email whose send fails is now
  tried again (after 2, 10 and 30 minutes, then 2 hours). Before, a failure was only logged. One that never goes shows
  in a banner for administrators and, for a breach escalation, on the case for everyone who can see it ("The breach
  escalation email to Legal / Privacy wasn't delivered"). An administrator clears it with **Mark handled** once the
  people it was for have been told another way.

- **A report is marked at least as restrictively as anything in it.** A report generated at TLP:GREEN on a case with
  an indicator marked TLP:RED is now marked TLP:RED (the indicator also appears in the relationships appendix, the
  entity graph and the attack chain, not only the IOC table). The Report tab says so before you generate. To share the
  report more widely, change that entity's TLP first.

- **One column migration** (`HistoryRowHashes`): status, classification, materiality, severity, assignment and
  verdict changes, case assignments and evidence citations now carry a row hash and are in the record check. A direct
  edit of when a transition happened, or an assignment inserted outside CaseBook, is now caught. At the first start
  after the upgrade, existing rows the audit trail records are given their hash; the trail itself isn't changed (so
  until the next release records those hashes, an edit whose author also recomputed the hash isn't caught).

- **One column-and-index migration** (`CaseEditVersion`): two saves to the same case at the same moment no longer
  both land (two closes, two current briefs). The second is refused with "Someone else just changed this case.
  Reload to see their change, then try again." A unique index keeps one current brief per case; if a case already
  has two, the migration keeps the latest current and makes the other an earlier version.

- **One column migration** (`SealKeyedFrom`): a seal made while the chain key is on records, under its signature,
  the entry the chain is keyed from. A rewrite of keyed entries with the plain hash is now caught even after a
  restart, before any seal covers a keyed entry. Older seals verify unchanged. The compliance bundle's `seals.csv`
  has a new last column, `KeyedFromSequence`, and `VERIFY.txt` explains the longer payload. **If you enabled the
  ledger** (`02-Enable-Ledger.sql`), the migration adds the nullable column to the append-only table, which SQL
  Server allows; use this release's script for any new install.

- **One column migration** (`RowHashFormat2`, SQL Server only): every `RowHash` column widens from 64 to 70
  characters. New row hashes are written in canonical format 2, which escapes `\` and `|` in free text so text can't
  be moved between two fields of a record without changing the hash, and are stored with a `v2:` prefix. Existing
  hashes are checked as they were written, so the record check passes on upgrade; a record moves to format 2 the next
  time it's saved, which adds its new hash to the audit trail as usual.

### v1.5.1

A bug-fix release with two migrations, applied at startup. Stage gates now apply when filing a case and on every rung
climbed, which changes what New case asks for; read the gate note below before upgrading.

- **One index migration** (`CaseEntityIndexFitsSqlServer`): replaces `IX_CaseEntities_CaseId_Type_Value` with
  `IX_CaseEntities_CaseId_Type`, carrying `Value` as an included column on SQL Server. The old index's key could
  exceed SQL Server's 1,700-byte limit, so an indicator value over about 840 characters (a long URL or command line)
  failed to save. Rebuilding the index on a large `CaseEntities` table takes a moment at startup; no data changes.
- **One table migration** (`JurisdictionNotices`): regulator notices are recorded per jurisdiction, and each
  jurisdiction's clock stops on its own notice. A case counts as reported once every jurisdiction in play is
  notified. Cases reported before this keep their single reported time (it counted for every jurisdiction).
- **Stage gates apply on every rung climbed, and when filing a case.** A jump (Adverse Event to Breach) passes the
  Incident gate too, and New case and imports that create a case pass the gates up to the chosen rung. With the default
  gates, filing an Adverse Event needs a summary, an Incident also an indicator, and a Breach the impact fields, or an
  override reason recorded with the case. Review the gate definitions under Administration before upgrading if your
  team files Incidents or Breaches directly.
- **Archiving** is refused while a regulatory notification deadline is running with no notice recorded.
- **The integrity check now covers the records**, not only the audit chain: *Verify now* and the background monitor
  also flag a record edited directly in the database, including one whose row hash was recomputed. Checked against
  v1.5.0 data with no false alarms. A DBA fix made with raw SQL on an audited table will now raise the integrity
  alarm, as it should; make corrections through the app.
- **Materiality decision time.** The materiality dialog now records when the decision was made (date and time, in the
  user's zone), and a Material call starts the notification clock at that moment. Before, it took a date only and
  started the clock at 00:00 UTC that day, which in New York is 8pm the evening before. Determinations already
  recorded keep that start; for an open case whose clock still matters, re-record the determination with the real time.
- **`Install-CaseBook.ps1`** now JSON-escapes every value it writes into `appsettings.Production.json`. A named SQL
  instance (`SQLHOST\PROD`) or a `DOMAIN\Group` name used to make the file invalid or silently corrupt it.

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
  migrations itself — have a DBA apply `deploy/sql/casebook-schema-sqlserver.sql` (idempotent; with `sqlcmd -I`) before
  the first request, then run the upgrade with the app already schema-current.
- Match the runtime: a build targeting .NET 10 needs the **.NET 10 Hosting Bundle** on the server
  (the shared framework, not just the SDK). The preflight checks this and stops with guidance.
- **Sites with the SQL Server ledger on** (OPERATIONS.md §7): upgrades work unchanged. The ledger tables only
  accept new nullable columns, and the build enforces that for every release, so a migration can't fail on
  them. Take a ledger digest (`Export-LedgerDigest.ps1`) before and after the upgrade for your records.
