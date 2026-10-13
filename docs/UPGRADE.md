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
When the script sees that the new build recorded migrations, it restores the previous binaries but leaves the app
pool **stopped** until you've restored the backup.

Never roll back the binaries alone over a database a newer build has run against. From v1.5.2 on, row hashes and
seals are written in formats earlier builds don't read, so an earlier build reports them as tampered (critical log,
SIEM event, alarm email, banner), and a migration's `Down()` can't always undo one (a wider column holding longer
values). Restore the pre-upgrade database backup together with the previous binaries.

---

## Notes

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
