# Troubleshooting

How to diagnose problems in a running CaseBook, from startup failures to integrity alarms. Each entry is
**Symptom → Likely causes → Where to look → Steps → Fix.** For how the system works, see the
[architecture](../architecture/overview.md) pages.

> **Never edit the database or the file stores by hand.** CaseBook is a tamper-evident record. A direct change
> to `AuditLog`, any business table, evidence files, seals or `AppSettings` breaks the hash chain or trips the
> settings alarm, and looks exactly like an attack. Make changes through the app. If data is genuinely wrong,
> capture the case number and audit rows and escalate to engineering.

## Where to look

| Source | What it tells you | How |
|---|---|---|
| Windows **Application** event log (app server) | Startup failures (ASP.NET Core Module, .NET Runtime), Critical alarms 5001 and 5003, warnings | Event Viewer → Windows Logs → Application. Filter by level Critical/Error. **Needs verification on your host:** the source name the app's own Critical entries appear under. |
| `logs\stdout_*.log` in the site folder | Console output when the app can't start | Set `stdoutLogEnabled="true"` in `web.config`, recycle, reproduce. Turn it off again afterwards. (An upgrade replaces `web.config`.) |
| IIS logs (`%SystemDrive%\inetpub\logs\LogFiles`) | Status code per request (401, 403, 500.x) | |
| `/health/live`, `/health` | Process up; database reachable and evidence folder present | Needs Windows authentication on an IIS install unless carved out (below) |
| Administration → **Diagnostics** | Backup freshness, evidence-drift status, CyberArk resolution, writable paths, SIEM test event | Administrators |
| Administration → **Setting sources** | The effective value of every setting and where it comes from | Administrators |
| **Integrity & audit** | Chain verdict, first broken sequence, seals, audit trail | *Verify now* |
| **Access log** | Who read or downloaded what | Administrators |
| SIEM | The security-event stream | If configured ([OPERATIONS.md §5](../OPERATIONS.md#5-siem-security-event-stream-f-18)) |
| Browser developer tools | JS errors, failed WebSocket (`/_blazor`), 4xx/5xx on downloads | Console and Network tabs |

### The 60-second health check

1. The dashboard (or My work) loads for a mapped user.
2. Integrity → *Verify now* reports **VALID**, and there's no red banner.
3. A seal exists within the auto-seal interval.
4. Diagnostics → Backup & restore health reads **Fresh** for both.
5. No Critical 5001, 5002 or 5003 events since the last check.

## Startup and deployment

### HTTP 500.19 and no application log

- **Causes:** the ASP.NET Core Module isn't installed, so IIS can't read the `<aspNetCore>` section in
  `web.config`.
- **Look:** `%SystemRoot%\System32\inetsrv\aspnetcorev2.dll`; *Programs and Features* for "Microsoft .NET 10 …
  Windows Server Hosting".
- **Fix:** install the **.NET 10 Hosting Bundle** (not just the SDK or runtime) after IIS, then `iisreset`.

> If an install or upgrade script says the module is missing but it is installed: older scripts checked
> `System32` from a 32-bit PowerShell, which Windows redirects to `SysWOW64`. Current scripts check both views,
> the registry and `Program Files`. Run the script from the bundle you're installing, in 64-bit PowerShell.

### HTTP 500.30 / 500.31 (the app failed to start)

- **Causes, most likely first:**
  1. A migration failed at startup (see [Migration failures](#migration-failures)).
  2. The database is unreachable or the app identity can't log in.
  3. `Auth:Mode` isn't `Windows` in Production (the message says so).
  4. `DataProtection:KeyPath` is relative.
  5. The .NET 10 runtime is missing.
- **Look:** Application event log (*IIS AspNetCore Module V2* and *.NET Runtime* entries), then stdout logs.
- **Steps:** read the first exception. For SQL errors, test the login with the app pool's identity.
- **Fix:** correct the configuration in `appsettings.Production.json` and recycle. A 500.30 during an upgrade can
  mean some migrations were applied before the failure: see [Upgrade went wrong](#an-upgrade-failed-or-rolled-back).

### Every page shows "Something went wrong" after an upgrade, and the log says *Access to the path … App_Data\… is denied*

- **Cause:** a storage setting that a newer release introduced (for example `ReportBranding:RootPath` or
  `ReportTemplates:RootPath`) is missing from `appsettings.Production.json`, so that store falls back to
  `App_Data` inside the read-only web root.
- **Look:** the event log error names the path. Compare your config with
  `deploy/appsettings.Production.template.json`.
- **Fix:** run the upgrade with the current bundle's `Upgrade-CaseBook.ps1`; its preflight adds missing
  data-folder settings under your data root, creates the folders with the right permissions, and refuses to
  proceed if `Integrity:SigningKeyPath` is missing. Or add the settings by hand (paths under your data root),
  create the folders, grant the app pool Modify, and recycle.

### Startup throws "Auth:Mode is 'Dev' in Production"

A fail-safe, not a bug. `appsettings.Production.json` is missing, or doesn't set `Auth:Mode` to `Windows`. Never
set it to `Dev` on a server.

### `401` for everyone

- **Causes:** Windows authentication isn't negotiating: no SPN for the site's hostname, Kerberos disabled, the
  browser not treating the site as intranet, or anonymous authentication still on.
- **Steps:** `setspn -Q HTTP/<hostname>`; check IIS authentication settings for the site (Windows on, anonymous
  off except `/api`); try from a domain-joined machine with the site in the Local intranet zone.

### Health probe returns 401

- **Cause:** the installer disables anonymous authentication for the whole site except `/api`, and IIS rejects
  the request before the app sees it, even though `/health`, `/health/live`, `/branding/logo` and
  `/agenda/feed.ics` are anonymous in the app.
- **Fix:** let the probe authenticate, or add `<location>` entries in `applicationHost.config` enabling
  anonymous authentication for those paths (as the installer does for `/api`). The email logo and calendar feed
  need the same carve-out to work for mail clients and calendar apps.

### Requests by IP or a different name get HTTP 400

`AllowedHosts` is set to the site hostname. Use that name, or add the others to `AllowedHosts` (semicolon
separated). This also makes an upgrade's warm-up time out and roll back if its health URL uses another name.

### `dotnet publish` fails with NU1100 during install

No NuGet source is registered for the account running the installer. `dotnet nuget list source`; add nuget.org
(`dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org`) or rerun with
`-AddNuGetOrgSource`. Better: install from the release bundle, which needs no SDK ([INSTALL.md](../INSTALL.md)).

### The app pool stops immediately after install

If you used a normal domain account rather than a gMSA and didn't pass `-AppPoolCredential (Get-Credential)`,
the installer set a blank password. Set the identity's password in IIS Manager (or rerun with the credential).

## Database

### Migration failures

- **Symptom:** 500.30 at startup or after an upgrade; the log mentions EF Core, `There is already an object
  named …`, `CREATE TABLE permission denied`, or a constraint error.
- **Causes:**
  1. The database's migration history doesn't match this build (an install from a pre-release whose migrations
     were later regenerated).
  2. The app account isn't `db_owner` (installed with `DbaApplies`) and nobody applied the new schema.
  3. A ledger table rejected a schema change (only nullable column additions are allowed; releases are checked
     for this).
  4. A partial earlier failure.
- **Look:** `SELECT * FROM __EFMigrationsHistory ORDER BY MigrationId` and compare with
  `migrations-sqlserver.txt` in the release bundle.
- **Fix:**
  - (1) [UPGRADE.md → resolving a mismatch](../UPGRADE.md#resolving-a-mismatch).
  - (2) A DBA applies `deploy/sql/casebook-schema-sqlserver.sql` (idempotent), then recycle.
  - (4) Restore the pre-upgrade backup the script took, then retry.

> `Upgrade-CaseBook.ps1` from v1.2.1 reported a false *MIGRATION MISMATCH* on every database (a PowerShell
> array-wrapping bug). Use v1.2.2 or later.

### An upgrade failed or rolled back

- **What the script did:** before deploying it backed up the database (to the instance's default backup folder,
  `<db>-preupgrade-<stamp>.bak`), the configuration and the site (to `…\casebook-upgrade-backups\<stamp>\`). If
  the new build didn't come up during warm-up, it restored the **binaries** and restarted. **It doesn't restore
  the database.**
- **Look:** the script output (it prints the last Application-log errors); the event log; whether
  `__EFMigrationsHistory` gained rows.
- **Steps and fix:**
  1. If no new migrations were recorded, fix the cause (often configuration, a host-header mismatch with
     `AllowedHosts`, or a missing runtime) and rerun the upgrade.
  2. If some new migrations were recorded, the schema is ahead of the restored binaries. Restore the
     pre-upgrade backup, then fix and rerun.
  3. Warm-up treats any 2xx, 401 or 403 from the site root as started; a 400 (host rejected) or 5xx loops until
     the timeout and then rolls back.
- The upgrade replaces `web.config` and removes other files in the site folder that aren't in the release
  (they're in the rollback snapshot).

### "Login failed for user …" or "Cannot open database"

The app pool identity has no SQL login or user, or it's running as a different account. Rerun
`Install-Database.ps1` for that account; check the identity in IIS (Application Pools → Advanced Settings).

### Upgrade preflight: "Schema present but no matching history" / "Different or newer lineage"

See [UPGRADE.md](../UPGRADE.md#the-migration-compatibility-preflight-why-an-old-instance-can-fail-to-start). The
second also blocks downgrades: you can't deploy an older build over a newer database.

## Access and permissions

### A user lands on `/access-denied` everywhere

- **Cause:** they're signed in but in no mapped AD group, so they have no permissions.
- **Steps:** the page shows who they're signed in as. Administration → Roles & access lists the mapped groups.
  Check their membership in AD.
- **Fix:** add them to a mapped group, then they sign out of Windows and back in (or wait for a new logon
  ticket). Mapping changes made in CaseBook reach open sessions within two minutes; group membership changes
  need a new logon. SIEM 5201 is emitted for each refusal.

### A user can't see a case they expect to

Almost always need-to-know working as designed. A restricted case is visible only to its incident commander,
its assigned team, and roles with `ViewAllCases` or `ViewRestricted`. A hidden case and a missing one both show
"not found".

1. Is the case restricted? (The header flag; an administrator can check.)
2. Is the user assigned? Do their roles include a cleared permission?
3. If they need access, **assign them** rather than lifting the restriction.

### A user gets "You don't have permission to …" on an action

The message names the missing permission. Check *My access* (account menu) and the role definitions. If they
recently lost a role, their open tab updates within two minutes; reloading picks it up immediately. SIEM 5202.

### A settings change in Administration didn't take effect

1. Is it a server-side setting? Those are read-only in the app and need a file change and recycle
   ([configuration.md](configuration.md)).
2. Did you clear a number expecting "off"? A blank number restores the file value; enter `0`.
3. Check *Setting sources* for the effective value. The settings form shows catalog defaults, not file values.
4. Background jobs pick changes up within about five minutes; the idle timeout applies to new sessions.

## Integrity

### Integrity alarm (5001)

The red banner, a Critical 5001 event, and an email to the integrity distribution list mean the audit chain or
the latest seal failed verification. Treat it as a **possible security incident**.

1. **Preserve first.** Don't restart, re-seal or "fix" anything. Copy the database backup chain and the seal
   export folder (`Integrity:ExportPath`).
2. Integrity & audit shows the **first broken sequence** and why (gap, broken link, hash mismatch, or seal
   mismatch). Record it.
3. If the seal signature is valid but the head no longer matches, history was rewritten after sealing. If the
   signature itself is invalid, the seal record was altered or a different key signed it.
4. New seals are suspended while the chain is broken. Leave it that way.
5. **Rule out the benign cause:** did anyone run SQL against the database, restore a partial backup, or run a
   tool that updates rows? Any of these breaks the chain.
6. Recovery is a restore of a known-good backup with prior-seal verification ([OPERATIONS.md §1.3](../OPERATIONS.md#13-restore-verification-do-not-skip)),
   coordinated with security and engineering.

### Evidence drift (5003)

The re-hash job found a stored evidence file that doesn't match its recorded hash, is missing, or can't be read.
The email lists case, evidence id and file name. Preserve the store and database; restore the file from the
evidence backups (the recorded hash tells you what it must hash to); check EDR and file-system logs for who
touched it.

### Rejected setting override (5002) at startup

An `AppSettings` row whose key isn't an in-app setting exists in the database. The app ignored it. It can only
have been written outside the app (a hand edit, a merged restore, tampering). The Critical log line names the key.
Establish how it got there; remove it through a coordinated database change with engineering (it's harmless
while it stays, since it's ignored).

### No recent seal

Check `Integrity:AutoSeal:Enabled` and `IntervalHours` (*Setting sources*), that the chain verifies (no seals are
made over a broken chain), and that the app pool can write `Integrity:ExportPath`. Seal-export failures aren't
logged today; check the folder's permissions directly.

## Files, downloads and reports

### Evidence or a report won't download

- **"Not found" or the error page:** the user can't see the parent case (need-to-know), or the id doesn't exist.
  Both show the same result by design; an unknown id currently produces a 500 and the error page, not a 404.
- **429 Too Many Requests:** the per-user download limit (40 burst, 40 a minute by default). Wait and retry. A
  spike from one account is worth a look (SIEM 5306). Tune `RateLimiting:Downloads` if legitimate use hits it.
- **The database row exists but the file is gone:** the file store and database drifted, usually a restore that
  didn't include the stores. Restore the store to the same point in time.
- **Inline thumbnail missing:** only real PNG, JPEG, GIF and WebP files are shown inline. *Download* still works.

### Report generation fails

- A Word template with unknown fields or unsupported content; check it in Administration → Reports (preview
  reports the problem).
- The report store isn't writable by the app pool.
- Template uploads with macros, embedded objects or external content are refused by design.

## Notifications and integrations

### Emails aren't arriving

1. Administration → Notifications → **Delivery readiness**: email on, sender set, triggers enabled.
2. *Send a test email*: confirms the relay end to end.
3. With email off, the log shows "Email delivery disabled; not sending to N recipient(s)".
4. The SMTP client doesn't authenticate; the relay must accept the app server anonymously or by IP.
5. Blank `App:BaseUrl` means emails send without links or the logo.
6. Reminder scans are off by default; check each `Notifications:*Scan:Enabled`.
7. Users can opt out of assignment, overdue and due-soon emails unless they're mandatory.

### The SIEM isn't receiving events

1. A transport must be enabled (`Siem:Webhook`, `Siem:Syslog`, `Siem:EventLog`); all are off by default.
2. Administration → Diagnostics → **Send test event** (5901) reports success per transport.
3. Webhook URLs must be https (http only to loopback). A token that's a CyberArk reference and fails to resolve
   is sent without authentication; see Diagnostics → Secret resolution.
4. The Event Log transport needs its source registered once (`New-EventLog -LogName Application -Source
   CaseBook`); otherwise it disables itself until restart.
5. The queue (`Siem:QueueCapacity`) drops events under a flood; delivery is best effort and events in the queue
   are lost on restart. The audit chain remains the record.
6. 5101 only appears with Windows authentication.

### CyberArk secret not resolving

Diagnostics → Secret resolution shows the last error (for example `HTTP 403 (APPAP004E)`). Check
`Secrets:CyberArk:Enabled`, `BaseUrl` (https), `AppId`, and with the CyberArk administrator that the AppID allows
this host, its OS user and any client certificate (in `LocalMachine\My`, readable by the app pool). All CyberArk
settings need a recycle. See [OPERATIONS.md §6](../OPERATIONS.md#6-secret-management-f-19).

### The import API returns 401, 403, 413 or a redirect

- **401**: no or invalid token, expired or revoked; or IIS isn't letting `/api` through anonymously (the
  installer sets this).
- **403**: the token's roles lack `EditCases`.
- **413**: the body is over 5 MB.
- **302 to `/Error`**: a server error; check the event log with the reference id.

See [API.md](../API.md).

### Backup health shows Stale or Missing

CaseBook only reads `BackupStatus:FilePath`; your backup and restore-verification jobs write it. *Missing*: the
path isn't set or isn't readable, or the job never wrote `lastBackupUtc`. *Stale*: the job stopped. A future
timestamp counts as stale (clock skew). See [OPERATIONS.md §1.3.1](../OPERATIONS.md#131-backup-health-status-file-h-04).

## In the browser

### "Attempting to reconnect" or the page freezes

The SignalR circuit dropped: an app-pool recycle, a network blip, a proxy that doesn't allow WebSockets, or an
idle timeout on a load balancer. If it happens on every recycle, `DataProtection:KeyPath` isn't persisted. If
behind a proxy, enable WebSockets for the site. Users can reload safely; unsaved composer text is lost on a
reload.

### "Your session was locked"

The idle timeout (`Security:IdleTimeoutMinutes`, default 15) or *Lock now*. *Resume* signs back in with Windows
authentication.

### A change someone else made doesn't appear

Live refresh works only when both users are on the same app instance. Reload the page. If running more than
one instance, that's the cause (unsupported).

### The page looks unstyled or a button does nothing after an update

A cached stylesheet or script. Hard-refresh. For developers: bump the file's `?v=` in `App.razor`.

## Data looks wrong

### The timeline shows an event at an unexpected time

1. Display time zone: the account menu's UTC/Local setting.
2. "recorded …" means it was entered later than it happened; the occurred time is what's shown.
3. Transitions use their effective time, which may have been corrected (the milestone shows "time corrected").
4. Gate passages use the time they were recorded, even when the transition was backdated.

### A dashboard number seems off

Exercise cases are excluded; closed cases with an unrecorded notification still count as awaiting report;
restricted cases are included only for roles that can see them; SLA clocks use effective times; days and months
follow `Organization:TimeZone`.

### A reminder email was sent twice

After a restart the in-memory "already sent" trackers are empty, so the first scan re-sends one reminder per
qualifying item. Expected behavior today ([known issues](../reference/known-issues.md)).

## Escalation

| Situation | First responder | Escalate to |
|---|---|---|
| App down or won't start | Platform / IIS support (this page) | Engineering if configuration is correct |
| Access question | Service desk + AD team | Engineering if scoping behaves against [security.md](../architecture/security.md) |
| **Integrity alarm 5001 or evidence drift 5003** | **Security incident process: preserve, don't touch** | Security lead + engineering |
| Rejected setting 5002 | Security triage | Engineering |
| Download throttling (429 / 5306) | Usually expected; a spike from one account is a scraping signal | Security triage |
| Backup health stale | Backup / DBA team | — |
| Data looks wrong | Don't edit SQL; capture the case number and audit rows | Engineering |
| SIEM not ingesting | Support (above) + SIEM team | — |

## Things support must never do

- Edit the database or the file stores directly.
- Delete or regenerate the seal-signing key to clear an alarm: you lose the ability to verify earlier seals.
- Set `Auth:Mode=Dev` on a server, even briefly.
- Restore the database without the matching file stores and seal exports.
- Disable the integrity job to silence a banner.
- Put a secret into an in-app setting.
