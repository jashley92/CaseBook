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
| `/health/live`, `/health`, `/health/alarms` | Process up; database reachable and evidence folder present; whether any alarm is up (Degraded; Diagnostics says which) | Anonymous on an installed site (CAP-37); a 401 means the carve-out is missing (below) |
| Administration → **Diagnostics** | Backup freshness, the backup set (CAP-19), evidence-drift status, CyberArk resolution, writable paths, SIEM test event | Administrators |
| Administration → **Setting sources** | The effective value of every setting and where it comes from | Administrators |
| **Integrity & audit** | Chain verdict, first broken sequence, seals, audit trail | *Verify now* |
| **Access log** | Who read or downloaded what | Administrators |
| SIEM | The security-event stream | If configured ([OPERATIONS.md §5](../OPERATIONS.md#5-siem-security-event-stream-f-18)) |
| Browser developer tools | JS errors, failed WebSocket (`/_blazor`), 4xx/5xx on downloads | Console and Network tabs |

### The 60-second health check

1. The dashboard (or the Desk) loads for a mapped user.
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
  3. `Auth:Mode` isn't `Windows` outside Development (the message says so).
  4. The seal-signing key file isn't there yet ("The seal-signing key … doesn't exist"); provision it
     ([OPERATIONS.md §2](../OPERATIONS.md#2-integrity-signing-key-management-f-05b)).
  5. `DataProtection:KeyPath` is relative.
  6. The .NET 10 runtime is missing.
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
set it to `Dev` on a server. The same check stops any other non-Development environment (`Staging`, `QA`) with
"Auth:Mode is '…' in the '<environment>' environment"; set `Auth:Mode=Windows`, or, on a demo box only,
`Auth:AllowDevSignInOutsideDevelopment=true`.

### `401` for everyone

- **Causes:** Windows authentication isn't negotiating: no SPN for the site's hostname, Kerberos disabled, the
  browser not treating the site as intranet, or anonymous authentication still on.
- **Steps:** `setspn -Q HTTP/<hostname>`; check IIS authentication settings for the site (Windows on, anonymous
  off except `/api`, `/health`, `/branding/logo` and `/agenda/feed.ics`); try from a domain-joined machine with the
  site in the Local intranet zone.

### Health probe returns 401

- **Cause:** the site has no anonymous carve-out for the path, so IIS rejects the request before the app sees it,
  even though `/health*`, `/branding/logo` and `/agenda/feed.ics` are anonymous in the app. Sites installed before
  CAP-37 had a carve-out for `/api` only, and `Upgrade-CaseBook.ps1` doesn't change IIS authentication.
- **Where to look:** `Verify-Install.ps1 -Url <site>` names each path IIS refuses.
- **Fix:** re-run `Install-CaseBook.ps1`, or add the `<location>` entries by hand with `appcmd` (anonymous on, Windows
  off, for `<site>/health`, `<site>/branding/logo` and `<site>/agenda/feed.ics`; the commands are in
  [UPGRADE.md](../UPGRADE.md), *Unreleased*). The email logo and calendar feed need the same carve-out to work for
  mail clients and calendar apps.

### Requests by IP or a different name get HTTP 400

`AllowedHosts` is set to the site hostname. Use that name, or add the others to `AllowedHosts` (semicolon
separated). The upgrade's probe sends the site's name as the `Host` header (its binding's host name, else the first
plain `AllowedHosts` entry), so its `-HealthUrl` can be a binding's IP or `localhost`. If the probe still gets a 400,
the upgrade stops in its preflight, before anything is changed.

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
  - (2) A DBA applies `deploy/sql/casebook-schema-sqlserver.sql` (idempotent; `sqlcmd -I`, since filtered indexes need QUOTED_IDENTIFIER on), then recycle.
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
  1. If no new migrations were recorded, fix the cause (often configuration or a missing runtime) and rerun the
     upgrade.
  2. If some new migrations were recorded, the schema is ahead of the restored binaries. Restore the
     pre-upgrade backup, then fix and rerun.
  3. Warm-up counts only CaseBook's import schema (`/api/import/cases/schema`) as started. When IIS answers `/api`
     itself it asks the site root signed in as you, where a page, a redirect, 401 or 403 counts. A 5xx, or no
     answer by the timeout, rolls back. The preflight asks the same way before anything changes, and stops on no
     answer, a 400 (host rejected), or an answer that isn't CaseBook's.
- The upgrade replaces `web.config` and removes other files in the site folder that aren't in the release
  (they're in the rollback snapshot).

### "Login failed for user …" or "Cannot open database"

The app pool identity has no SQL login or user, or it's running as a different account. Rerun
`Install-Database.ps1` for that account; check the identity in IIS (Application Pools → Advanced Settings).

### Upgrade preflight: "Schema present but no matching history" / "Different or newer lineage"

See [UPGRADE.md](../UPGRADE.md#the-migration-compatibility-preflight-why-an-old-instance-can-fail-to-start). The
second also blocks downgrades: you can't deploy an older build over a newer database.

### Search is slow, or Diagnostics says "Search: substring" on SQL Server (CAP-22)

- **Symptom:** the command bar lags on a large database, or Diagnostics' *Search* row says *substring* though you expected
  full-text.
- **Cause:** by the row's words:
  - *full-text not installed*: the instance lacks the optional Full-Text Search feature.
  - *indexes not created*: it was added after CaseBook's migration ran.
  - *still being filled*: SQL Server is populating new indexes (minutes on a large database).
  - *couldn't be checked*: the metadata read failed or took over 5 seconds.
- **Where to look:** Diagnostics' *Search* row; the startup log line `Search: …`; the warning "Couldn't check SQL
  Server's full-text indexes".
- **Fix:** install the feature (SQL Server setup, *Full-Text and Semantic Extractions for Search*), then *Create
  full-text indexes* on the row, or have a DBA run `deploy\sql\03-Enable-FullText.sql`
  ([OPERATIONS.md §9](../OPERATIONS.md#9-full-text-search-on-sql-server-cap-22)). Wait for the fill; *Check again*.
  "isn't allowed to create full-text indexes" means the app account isn't `db_owner`: use the script.

### "A full-text search (…) failed with SQL Server error …" in the log (CAP-22)

- **Symptom:** a warning naming error 7601 (not full-text indexed), 7609 (not installed), 7630 (syntax) or another in
  the 7600s or 30000s; the *Search* row counts searches that "ran again by substring".
- **Cause:** a full-text query the server refused: an index or the catalog was dropped, or the feature removed, since
  the last check; or a search the word breaker can't read. The person searching got their results by substring.
- **Where to look:** the first of each error number is a warning, later ones Debug. The status is checked again at the
  next search, so a dropped index stops being used.
- **Fix:** none needed for an odd search. For a dropped index, recreate it (Diagnostics or `03-Enable-FullText.sql`). If
  one error number keeps coming for ordinary words, report it with the number and the words.

### A word finds less than it used to (CAP-22)

- **Symptom:** `sass` no longer finds "LSASS", or part of a host name finds nothing.
- **Cause:** with full-text search a word matches the words that **start** with it, not text in the middle of a word
  ([Find](../workflows/find.md#how-find-reads-the-query)). Indicators, case numbers and entities still match anywhere.
- **Fix:** type the start of the word, or the whole value (a value shaped like an indicator is matched as written).

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
3. Check *Setting sources* for where the effective value comes from (the form shows it, from your files when the
   app holds no override).
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

### Evidence store unreachable

**Symptom:** evidence downloads answer "the evidence store couldn't be read just now", uploads say "the evidence
store can't be reached", `/health` is Unhealthy, and the evidence re-check reports one "evidence store unreachable"
finding; the rest of CaseBook works.
**Cause:** the folder in `EvidenceStore:RootPath` can't be written and read: a share or volume that's down, the app
account's rights changed, or the folder isn't there (a remapped share, a changed drive or DFS target, a move done
without changing the setting). CaseBook never recreates a store that held evidence.
**Where to look:** Administration → Diagnostics → Evidence storage gives the reason; the log has it with the account.
**Fix:** bring the share back or restore the rights, or point `EvidenceStore:RootPath` at where the store now is
([OPERATIONS.md §1.2.1](../OPERATIONS.md#121-evidence-storage-limits-large-uploads-and-network-shares)). Downloads and
uploads resume as soon as it's reachable; no restart needed. Don't create an empty folder at the old path to make
the error go away: every file would then read as missing.

### Evidence key unavailable

**Symptom:** evidence and report downloads, uploads and report generation answer "the evidence key isn't
available"; an integrity email and the administrators' banner say the same; the rest of CaseBook works.
**Cause:** evidence encryption is on and the key's envelope can't be opened: the certificate protecting it was
removed, replaced without the old one left in the store, or the app-pool account lost read on its private key; the
chain key's CyberArk object can't be fetched; or a restore left out the keys folder.
**Where to look:** Administration → Diagnostics → Evidence encryption names the certificate or source and what's
wrong with each envelope copy; the Critical log line at start-up says the same.
**Fix:** put the certificate back (or its rights), or bring CyberArk back; CaseBook retries every 5 minutes, no
restart needed. If the certificate is gone for good, recover the key onto a new one with a recovery certificate or
the shares ([OPERATIONS.md §2, Evidence key](../OPERATIONS.md#evidence-key-encryption-at-rest-backups-and-recovery-prod-57)).
Never delete `evidence-key.json` or the `KeyEnvelopes` row to "reset" it: CaseBook won't make a new key while files
need the old one, and the files can't be read without it.

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
4. If the relay wants a sign-in, set one under **Email sign-in** (Settings → Notifications), or in the server's
   configuration ([integrations.md, Email](integrations.md#email-smtp)); see the next entry for a refused one.
   Diagnostics → **Delivery health** shows how many emails are held, the last error by type and code, and when
   they're next tried.
5. Blank `App:BaseUrl` means emails send without links or the logo.
6. Reminder scans are off by default; check each `Notifications:*Scan:Enabled`.
7. Users can opt out of assignment, overdue and due-soon emails unless they're mandatory.

### The relay refuses the sign-in (SMTP 530 or 535)

- **Symptom:** *Send a test email* says "The mail relay refused the sign-in (SMTP 535)" (or 530, 534, 538); the log
  says "The held notification emails can't be sent until the mail relay's sign-in is fixed"; Diagnostics → Delivery
  health shows held emails and that code.
- **Cause:** a wrong username or password, an expired password, an account the relay doesn't allow to send (Exchange
  Online: SMTP AUTH turned off for the mailbox or the tenant), or Windows sign-in to a receive connector that doesn't
  accept the app-pool account. A wrong password usually shows as 530 at MAIL FROM: `SmtpClient` carries on unsigned
  after a refused AUTH.
- **Where to look:** the *Email relay sign-in* row in Server configuration (how it signs in, and from where: the form
  or the server's file), the health check of the same name on Diagnostics, and the relay's own log.
- **Fix:** correct it on the Email sign-in form (or in `Email:SmtpUsername`/`Email:SmtpPassword`, which win), then
  *Send a test email*. It's not a relay outage, so nothing is backed off, and the held mail goes once the fix lands.
  CaseBook doesn't try a refused sign-in again for an hour (unless the settings change or a test gets through), so a
  wrong password doesn't lock the account out; unlock it in the directory if it already is. Held mail is given up
  after 24 hours.

### "Re-enter the SMTP password" (the saved password can't be decrypted)

- **Symptom:** the Email sign-in form and Diagnostics say the saved password can't be decrypted on this server; email
  that signs in is held; the log says "The SMTP password saved in Administration can't be decrypted" once.
- **Cause:** the database was restored, or the site moved, to a server without the Data Protection key ring it was
  saved with (`DataProtection:KeyPath`), or that folder was lost or replaced.
- **Fix:** restore the key ring folder from the same backup as the database ([OPERATIONS.md §1](../OPERATIONS.md)), or
  re-enter the password on the form. Nothing is sent with a password that isn't the one saved (fail closed).

### "Someone changed the email sign-in since you opened it" (Save refused)

- **Symptom:** Save sign-in (or Clear) on the Email sign-in form says nothing was saved because someone changed it since
  you opened it; or, on a first save, "Someone else saved the email sign-in just now; reload to see it."
- **Cause:** another administrator saved the sign-in after your form loaded it. Saving over it could have paired your
  old username with the password they just set (CAP-05 review), so the save is refused instead.
- **Fix:** the form now shows what's saved, with your entries kept. Check the username and the password (type it again
  if you're the one changing it), then save again. For the first-save message, reload the page first.

### "Re-enter the team-chat webhook URL" or "the SIEM webhook token" (a saved secret can't be decrypted)

- **Symptom:** the Team chat webhook or SIEM webhook token card, and Diagnostics, say the saved value can't be
  decrypted on this server; chat isn't posted, or the SIEM webhook sends nothing; Delivery health shows it **Stopped**;
  the log says "The team-chat webhook URL (or SIEM webhook token) saved in Administration can't be decrypted" once.
- **Cause:** as for the SMTP password above: the database is on a server without the Data Protection key ring it was
  saved with (`DataProtection:KeyPath`).
- **Fix:** restore the key ring from the same backup as the database ([OPERATIONS.md §1](../OPERATIONS.md)), or Replace
  the value on the card (Settings → Notifications → Team chat webhook; Server configuration → SIEM webhook token).
  Nothing is sent with it meanwhile (fail closed, CAP-40).

### Saved secrets while the database is down

- **Symptom:** during a database outage, the log says "The secrets saved in Administration couldn't be read" once.
  Team chat may show **Stopped** on Delivery health with "the webhook URL saved in Administration can't be read (the
  database isn't answering)", and Server configuration shows "can't tell" for the token or webhook.
- **Cause:** the senders read the saved team-chat webhook URL and SIEM webhook token from the database. Each read waits
  at most 3 seconds; a database that doesn't answer is asked again only every 10 seconds meanwhile (CAP-40 review).
- **What happens:** a value read before the outage keeps being used, so chat posts and the SIEM webhook sends as
  before. When nothing was read yet (the database was down from startup), the SIEM webhook sends without a token, as
  it did before one could be saved, so a collector that wants one answers 401 and Delivery health shows it. A chat post
  counts as failed, not "chat is off", so the next reminder scan tries a scheduled broadcast again rather than marking
  it sent.
- **Fix:** none needed for the secrets: once the database answers, the next read picks the values up. To keep the SIEM
  token through a cold start with the database down, set it in the server's configuration (`Siem:Webhook:Token`)
  instead.

### "The … couldn't be encrypted on this server" on Save

- **Symptom:** saving the team-chat webhook URL or the SIEM webhook token says it couldn't be encrypted, so nothing was
  saved.
- **Cause:** Data Protection couldn't use its key ring: `DataProtection:KeyPath` is missing, or the app-pool account
  can't write to it (a new key can't be created).
- **Fix:** check the folder exists and grant the app-pool account Modify on it, then save again (CAP-40 review: before,
  this ended the page's connection).

### "Someone changed the team-chat webhook URL (or SIEM webhook token) since you opened it"

- **Symptom:** Save or Clear on a secret card says nothing was saved; or "Someone else saved the … just now; reload to
  see it."
- **Cause:** another administrator saved or cleared it after your card loaded it (CAP-40, as the Email sign-in's
  check). A *Send test* doesn't count as seeing their change.
- **Fix:** the card now shows what's saved. Decide again, and type the value again if you're replacing it.

### The chat webhook URL is refused on Save

- **Symptom:** saving the Team chat webhook says "The webhook URL was refused (…). Use an https URL."
- **Cause:** the same check a post makes (S-06): https only, or http only to this server itself (loopback).
- **Fix:** use the https URL Slack or Teams gave. The URL isn't logged or repeated in the message.

### A `@protected:` secret doesn't open

- **Symptom:** the log says "A @protected: secret (certificate …) couldn't be opened"; the email is held, the chat post
  isn't made, or the SIEM webhook stops sending (CAP-40: before, it sent without auth).
- **Cause:** the certificate it names isn't in `LocalMachine\My`, the app-pool account can't read its private key, the
  value was made for another certificate (a renewal), or it was changed.
- **Fix:** run `casebook-keytool check-secret <value>` on the server (as an administrator it tells you whether the value
  itself is good), grant the app-pool account read on the private key (certlm.msc → Manage Private Keys), or make the
  value again with `casebook-keytool protect-secret` and recycle the app pool. A value that opens but whose password
  the relay refuses (535), for a password with accented or other non-ASCII letters, was likely piped in from a script
  in the console's code page: the keytool reads piped input as UTF-8, so in Windows PowerShell set
  `$OutputEncoding = [System.Text.UTF8Encoding]::new($false)` before piping (the installer does), or type it at the prompt.

### The SIEM isn't receiving events

1. A transport must be enabled (`Siem:Webhook`, `Siem:Syslog`, `Siem:EventLog`); all are off by default.
2. Administration → Diagnostics → **Send test event** (5901) reports success per transport.
3. Webhook URLs must be https (http only to loopback). A token that's set but won't resolve (a CyberArk reference;
   see Diagnostics → Secret resolution) or decrypt (one saved in Administration; see the next entry) stops the
   webhook's sends: nothing goes unauthenticated (CAP-40). Delivery health shows the last error, or **Stopped** for a
   saved token.
4. The Event Log transport needs its source registered once (`New-EventLog -LogName Application -Source
   CaseBook`); otherwise it disables itself until restart, and Diagnostics → **Delivery health** shows it as
   **Stopped** ("event source missing").
5. The queue (`Siem:QueueCapacity`) drops events under a flood; delivery is best effort and events in the queue
   are lost on restart. The audit chain remains the record. Diagnostics → **Delivery health** shows each transport's
   last good send, queue depth and drops since start.
6. 5101 only appears with Windows authentication.

### Syslog over TLS fails (CAP-33)

- **Symptom:** with `Siem:Syslog:Protocol` `Tls`, nothing reaches the collector; *Send test event* or Delivery health says
  the handshake failed.
- **Cause and fix**, by what Diagnostics says:
  - *"isn't trusted by this server (its chain doesn't reach a trusted root)"*: the collector's certificate is self-signed
    or from a private CA this server doesn't trust. Import the root (or the certificate) into *Local Computer › Trusted
    Root Certification Authorities* (`certlm.msc`); optionally pin it with `ServerCertificateThumbprint`.
  - *"isn't issued to Siem:Syslog:Host"*: `Host` must be a name (or address) the certificate's subject alternative names
    list. Use the collector's DNS name rather than its IP address, or reissue the certificate.
  - *"isn't the one pinned"*: the collector's certificate was renewed or replaced. Check the new one's thumbprint with the
    collector's owner, then update `ServerCertificateThumbprint` (SHA-1 or SHA-256).
  - *"timed out"* / *"didn't … finish the handshake in time"*: the port answers but doesn't speak TLS (it's the plain TCP
    or UDP port: TLS is usually 6514), a firewall drops it, or the collector is overloaded. Raise `TimeoutSeconds` only for
    a slow link.
  - An `AuthenticationException` or `IOException` straight after connecting, with the collector logging "no client
    certificate": it wants mutual TLS. Set `ClientCertificateThumbprint` to a certificate in `LocalMachine\My` and grant
    the app pool's account read on its private key.
  - **Stopped**, *"No certificate with thumbprint … in LocalMachine\My"* or *"has no private key, or the app account can't
    read it"*: install the certificate or grant read on its key (Manage Private Keys in `certlm.msc`); it's looked for
    again within 5 minutes.
  - **Stopped**, *"Siem:Syslog:Protocol '…' isn't Udp, Tcp or Tls"*: the protocol is read by name; a number or a typo
    isn't one (before CAP-33 any value other than `Tcp` silently meant UDP).
- **Where to look:** Diagnostics → Delivery health (the syslog row), *Send test event*, and the Windows Event Log
  warnings "Syslog delivery failed for event … (reason)".

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

"Already sent" marks are kept in the database, so a restart shouldn't resend. Check the app pool: `Verify-Install.ps1`
warns when it allows overlapped recycling or recycles on a schedule. A reminder whose send failed is sent again on the
next scan, by design. A reminder still due after 180 days is sent once more when its mark is pruned.

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
