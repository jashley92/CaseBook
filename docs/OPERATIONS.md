# CaseBook — Operations & Deployment Guide

The runbook for a production CaseBook (Windows Server, IIS, SQL Server 2022). Development uses SQLite and needs none
of this. This page is the index, the host controls (§3), the deploy-time checklist (§4) and the periodic reviews (§8);
the rest has its own page, with its section number kept, so "OPERATIONS.md section 2" in the app and the scripts still
finds it.

| To… | Go to |
|---|---|
| See everything that runs on a schedule, and what tells you it didn't | [What runs when](operations/backup-and-recovery.md#16-what-runs-when) |
| Take backups, prove a restore, recover from a disaster | §1, [Backup and disaster recovery](operations/backup-and-recovery.md) |
| Set up, rotate or recover the signing key, the chain key, the evidence key; renew certificates | §2, [Keys and certificates](operations/keys-and-certificates.md) |
| Harden the host (EDR, IIS, health probes) | §3, below |
| Sign off a deployment | §4, below |
| Send security events to a SIEM; the event-id catalog | §5, [SIEM](operations/siem.md) |
| Keep secrets out of plain text (`@protected:`, CyberArk) | §6, [Secret management](operations/secrets.md) |
| Turn on and verify the SQL Server ledger | §7, [Ledger](operations/ledger.md) |
| Run the access and retention reviews | §8, below |
| Turn on full-text search | §9, [Full-text search](operations/full-text-search.md) |

Related: [configuration reference](operations/configuration.md), [troubleshooting](operations/troubleshooting.md),
[integrations](operations/integrations.md), [install](INSTALL.md), [upgrade](UPGRADE.md).

---

## 1. Backup & Disaster Recovery (H-03)

Now in **[operations/backup-and-recovery.md](operations/backup-and-recovery.md)**:

- [1.1 Taking backups](operations/backup-and-recovery.md#11-taking-backups)
- [1.2 Evidence, seals & reports](operations/backup-and-recovery.md#12-evidence-seals--reports)
- [1.2.1 Evidence storage: limits, large uploads and network shares](operations/backup-and-recovery.md#121-evidence-storage-limits-large-uploads-and-network-shares)
- [1.3 Restore verification (do not skip)](operations/backup-and-recovery.md#13-restore-verification-do-not-skip)
- [1.3.1 Backup-health status file (H-04)](operations/backup-and-recovery.md#131-backup-health-status-file-h-04)
- [1.3.2 Evidence-at-rest re-verification (F-17)](operations/backup-and-recovery.md#132-evidence-at-rest-re-verification-f-17)
- [1.4 RTO / RPO](operations/backup-and-recovery.md#14-rto--rpo)
- [1.5 Disaster recovery](operations/backup-and-recovery.md#15-disaster-recovery)
- [1.6 What runs when](operations/backup-and-recovery.md#16-what-runs-when)

---

## 2. Integrity Signing-Key Management (F-05b)

Now in **[operations/keys-and-certificates.md](operations/keys-and-certificates.md)**:

- [Where the key can live](operations/keys-and-certificates.md#where-the-key-can-live)
- [Setting up the key](operations/keys-and-certificates.md#setting-up-the-key)
- [Moving between sources](operations/keys-and-certificates.md#moving-between-sources)
- [The audit chain key (F-25, off by default)](operations/keys-and-certificates.md#the-audit-chain-key-f-25-off-by-default)
- [Extra seal copies (F-27, each off unless set)](operations/keys-and-certificates.md#extra-seal-copies-f-27-each-off-unless-set)
- [Rotating the signing key](operations/keys-and-certificates.md#rotating-the-signing-key)
- [Renewing certificates](operations/keys-and-certificates.md#renewing-certificates)
- [Evidence key: encryption at rest, backups and recovery (PROD-57)](operations/keys-and-certificates.md#evidence-key-encryption-at-rest-backups-and-recovery-prod-57)

---

## 3. Host Controls

- **Endpoint EDR/AV**: run a host **endpoint EDR/AV** agent whose sensor scans the evidence-store
  path on access/write at the host level. Ensure the evidence, seal, and report
  directories are **included** in the EDR monitoring policy and not inadvertently excluded.
  **Malware samples:** with evidence encryption on (§2, Evidence key), samples are encrypted from the first byte
  written, including uploads in progress under `<store>\.incoming`, so the scanner never sees one and no exclusion
  is needed. Without it, or until the files stored before are converted, evidence is stored as uploaded: a
  real-time scanner that *quarantines or deletes* will remove a sample on upload or when the evidence re-check reads
  it, and the case then shows it missing and its chain of custody ends there. In that state set the agent to
  **detect and alert only** on the evidence store, and press **Convert now** on Diagnostics after turning
  encryption on. Don't exclude the folder from monitoring altogether.
- **IIS / app-pool hardening**: least-privilege app-pool identity; HTTPS/TLS only (HSTS enabled in
  non-dev); security headers via `SecurityHeadersMiddleware`; server header suppressed.
- **Authentication**: production requires `Auth:Mode=Windows`; the app refuses to start in Production
  otherwise (see F-02), and in any other non-Development environment unless it sets
  `Auth:AllowDevSignInOutsideDevelopment=true`, so the dev auth handler can never run in prod.
- **SQL access**: use integrated auth to SQL (no SQL credentials in config).
- **Download rate limiting (F-13)**: the evidence/report/export endpoints are throttled per user by a
  token bucket, so a compromised account can't bulk-scrape artifacts. Tune under `RateLimiting:Downloads`
  (`TokenLimit` = burst, `TokensPerPeriod` over `PeriodSeconds` = sustained rate; defaults 40 / 40 / 60s).
  Over budget returns **429** with a `Retry-After` header and emits SIEM **`EventId 5306`** — a spike of
  these from one account is a bulk-exfiltration signal worth a detection rule. The inline timeline
  thumbnail endpoint is intentionally exempt (many load at once; it is image-only and need-to-know scoped).
- **Health probes (H-09)**: four endpoints the app serves **anonymously** for IIS / a load balancer / uptime
  monitoring — they return the status word only (no case data, no paths, no exception text), so they are safe
  to expose to an internal monitor. `Install-CaseBook.ps1` carves `/health` and every path below it out of
  Windows authentication (CAP-37), so a probe needs no sign-in; on a site installed before that,
  `Upgrade-CaseBook.ps1` checks for the carve-out and adds it
  (see [operations/troubleshooting.md](operations/troubleshooting.md#health-probe-returns-401)):
  - `GET /health/live` — **liveness**: the process is up and the pipeline responds. Runs no dependency
    checks. `200 Healthy`. Use this for the app-pool / container "is it running" probe.
  - `GET /health` (alias `GET /health/ready`) — **readiness**: additionally verifies **database
    connectivity** (a cheap `CanConnect`, no case data) and **evidence-store reachability** (the configured
    root exists — catches an unmounted/disconnected data volume). `200 Healthy`, or **`503 Unhealthy`** if a
    dependency is down. Point the load balancer's health check here so a node with an unreachable DB or
    evidence volume is pulled from rotation instead of serving 500s. Complements the backup-health (H-04)
    and evidence-drift (F-17) signals on the Diagnostics page, which cover freshness/tamper rather than
    live reachability.
  - `GET /health/alarms` — **alarms** (CAP-18), for a monitoring tool rather than the load balancer:
    `200 Healthy`, or `200 Degraded` while any alarm the app otherwise shows only in banners and the SIEM is
    up: the audit chain broken (5001), evidence drift or its store unreachable (5003), the evidence key
    unavailable, a seal copy whose last attempt failed (5005), or the backup status file stale or missing
    (§1.3; not configured isn't an alarm). It never answers 503 and isn't part of readiness, so an alarm
    never takes a node out of rotation: none of them is fixed by sending traffic elsewhere. The word is all
    it says; **Administration → Diagnostics** and the Integrity page say which alarm is up. The backup file
    read is time-limited (5 s), so a share that doesn't answer reads as Degraded rather than hanging the
    probe. Alert on `Degraded`, not on the status code.
  - **Shared reads and a per-address limit (CAP-18 review, C10).** The slow parts of the probes are read once
    per node for every request that asks while they run: the backup status file, kept **30 s** after each read
    (so a new backup shows on `/health/alarms` within half a minute), and the evidence store's folder, kept
    **10 s** (so a node whose share is back returns to rotation within about 10 s of the next probe). A share
    that doesn't answer holds one thread, however many probes arrive; each still answers within its 5 s limit.
    `/health/alarms` is also limited **per caller's address**: a burst of 120, then 120 a minute
    (`RateLimiting:Health`), far above a monitor polling every few seconds; past it the address gets **429**
    (logged, SIEM 5306). If every monitor arrives through one proxy address, raise the limit there. The
    readiness probes (`/health`, `/health/ready`, `/health/live`) are never limited: behind a proxy every probe
    shares one address, and a 429 would take the node out of rotation.
- **Scheduled jobs (CAP-29)**: **Administration → Diagnostics → Scheduled jobs** lists every background job (the
  integrity check and seal, the evidence re-check, store upkeep and key, access-log retention, the retention review count,
  the reminder scans, the digest, the executive report, the alert-email retry, the update check and the one-time integrity
  upgrade) with its last run (when, how long, how it ended, how many items), when it's next due, and its last error by
  type only; the server's log has the detail. The figures are held in memory and reset when the app restarts, so an empty
  row after a recycle is expected. **Run now** is offered only for the read-only scans (the evidence re-verification of
  this interval's share, and the retention review's count, which never sends its email); it needs `Administer`, is
  refused while that job is running, is in the audit trail, and doesn't move the schedule. A job that shows **Failed**
  again and again, or a next due that stays in the past, is worth a look in the Windows Event Log.

---

## 4. Deploy-time Checklist

- [ ] `Auth:Mode=Windows`; AD group → role mappings under `RoleMapping:Groups` match real groups.
- [ ] `Database:Provider=SqlServer` and a valid integrated-auth connection string.
- [ ] Backups scheduled (§1.1): `Backup-CaseBook.ps1 -Register` (nightly set and 15-minute log backups) to a
      secured, encrypted, offsite target, or your backup product with `Update-CaseBookBackupStatus.ps1 -Register`.
- [ ] Evidence / seal / report / branding directories exist outside the webroot, ACL-restricted, and in
      the backup set and the EDR monitoring policy.
- [ ] Web root is **read/execute-only** — on SQL Server the app writes no `App_Data` under the content
      root (H-07); every store lives under `DataRoot`. No Modify carve-out on the site folder is required.
- [ ] Load balancer / uptime monitor points at **`/health`** (readiness) and the app-pool/container probe
      at **`/health/live`** (liveness) — H-09. Both are status-only and anonymous on an installed site
      (CAP-37); `Verify-Install.ps1 -Url` checks it. A monitoring tool alerts on **`Degraded`** from
      **`/health/alarms`** (CAP-18), which is never a readiness signal.
- [ ] Signing key provisioned out of band and protected (the certificate store, recommended, or CyberArk; §2);
      its public half saved apart from the server (`casebook-keytool signing-public-key`).
- [ ] `DataProtection:KeyPath` set to an ACL-restricted folder (installer creates `DataRoot\dp-keys`) so
      the antiforgery/circuit keyring survives app-pool recycles; keys encrypted at rest (DPAPI machine
      scope). Back it up with the other stores. A scaled-out farm needs a shared key location + certificate.
- [ ] `Integrity:AutoSeal:Enabled=true` with an interval appropriate to activity volume.
- [ ] `Integrity:EvidenceVerify:Enabled=true` (F-17) with an interval appropriate to store size, and
      `Email:IntegrityAlertDistribution` populated so drift is actively alarmed (§1.3.2).
- [ ] `BackupStatus:FilePath` set (the installer sets it) and the scripts writing it (§1.3.1); Diagnostics →
      Backup &amp; restore health reads **Fresh** for both signals.
- [ ] A restore drill has passed: `Test-CaseBookRestore.ps1` (§1.3), and `-Register` for every fourth Sunday.
- [ ] SQL Server 2022 **updatable ledger** enabled for defense-in-depth (backlog E-10), with
      `Export-LedgerDigest.ps1 -Register` and `Verify-LedgerDigests.ps1 -Register` scheduled (§7).
- [ ] (Optional) Email notification triggers (E-03b/E-03d) — all admin-editable under **Settings → Notifications**,
      and all requiring **Send email** on to deliver: **Assignment notifications** (email the assignee when
      assigned to a case); **Overdue after-action reminders** (a slow background scan — like AutoSeal /
      EvidenceVerify — that emails each item's owner, or the case's incident commander as a fallback, once
      when it passes its due date); **Due-soon after-action reminders** (the same, once as an item enters its
      lead window). Neither reminds for a task on a closed or archived case. On a restricted case, a task owner who can't see the case isn't emailed about it; the case's incident commander is. Escalation to Breach also emails the **Legal/Privacy distribution** if set. All off/empty by
      default; the scans are read-only and never touch the audit chain, and pick up a toggle change within a few
      minutes. To go live, the sequence is: **Send email** on → **From address** set → enable the triggers you
      want (populate the Legal distribution for breach alerts). The **Delivery readiness** panel at the top of
      Settings → Notifications shows this whole chain at a glance and warns when a trigger is enabled but email
      is off (it would be logged, not sent); the **Send a test email** card confirms the relay end to end.
- [ ] (Recommended if any email is used) Set **`App:BaseUrl`** (Settings → Notifications) to this deployment's
      absolute URL so branded emails include **direct links** and the **logo**. All notification emails are
      branded HTML (E-03c) using the console theme + the report logo; their subject/body are admin-editable
      under **Settings → Email templates** (audited; the shell/branding is fixed). Blank base URL still sends —
      emails just omit links and the hosted logo (a text wordmark stands in). The logo is served anonymously
      at `/branding/logo` (branding image only, no case data).
- [ ] (Optional) `Siem:Webhook` configured to the SIEM's HTTP collector (see §5) if the security-event
      stream is wanted.
- [ ] (Optional) `Chat:Webhook` configured to a **Slack or Teams incoming-webhook** URL (PROD-02) if the SOC
      wants case-lifecycle notifications broadcast to a shared channel. Set `Enabled`, `WebhookUrl` (the URL is
      the channel secret — may be a literal or a `@cyberark:` reference), and `Format` (`Slack` or `Teams`).
      Then choose which types post there in-app under **Settings → Notifications → Chat: …** (breach escalations,
      assignments, overdue/due-soon summaries). Independent of email (no SMTP needed); https-only egress; shows
      read-only in Admin → Server configuration, and in the Notifications delivery-readiness panel.
- [ ] (Optional) `Secrets:CyberArk` enabled (F-19, §6) if secrets should come from CyberArk CCP: `BaseUrl`
      (HTTPS) + `AppId` set, the CCP AppID allow-listed to this host/identity (and a client cert in
      `LocalMachine\My` with the app-pool granted read on its key, if used), and each externalized secret
      (e.g. `Siem:Webhook:Token`) written as a `@cyberark:Safe=…;Object=…` reference.

---

## 5. SIEM Security-Event Stream (F-18)

Now in **[operations/siem.md](operations/siem.md)**:

- [Configuration (`Siem:*`, server-side only)](operations/siem.md#configuration-siem-server-side-only)
- [Event payload (stable parse contract)](operations/siem.md#event-payload-stable-parse-contract)
- [Event-ID catalog](operations/siem.md#event-id-catalog)
- [Seal copies in the SIEM (F-26)](operations/siem.md#seal-copies-in-the-siem-f-26)

---

## 6. Secret Management (F-19)

Now in **[operations/secrets.md](operations/secrets.md)**.

---

## 7. SQL Server Ledger (E-10)

Now in **[operations/ledger.md](operations/ledger.md)**:

- [7.1 Turn it on (one-way)](operations/ledger.md#71-turn-it-on-one-way)
- [7.2 Digests: schedule them, store them where the DBA can't](operations/ledger.md#72-digests-schedule-them-store-them-where-the-dba-cant)
- [7.3 Verify](operations/ledger.md#73-verify)
- [7.4 Upgrades and schema changes](operations/ledger.md#74-upgrades-and-schema-changes)

---

## 8. Periodic reviews: user access and case retention (CAP-15, CAP-10)

Two reviews a person does on a schedule, which CaseBook reminds about in **Administration → Diagnostics** (Health
checks) and records, but never does itself.

**User-access review (NYDFS 500.7).** Under **Administration → Roles & access → Access review**, download the CSV
(`/export/access-review.csv`: broad access, restricted cases, known users and active API tokens; access-logged, SIEM
5304), review it, make the changes in AD and CaseBook, then **Record this review** with a note. The record is an
entry in the audit trail (entity type `AccessReview`), chained and sealed with the rest. Diagnostics shows *Access
review* as a problem when none has been recorded within `Governance:AccessReview:ReminderDays` (default 90; 0 turns
the reminder off). Like the evidence-key drill (§2), the reminder is worked out from the record when the page opens;
there's no job to schedule.

**Case retention.** `Retention:CaseYears` (default 7) lists closed cases older than that under **Administration →
Retention review**, where an administrator archives them, at most 25 at a time. A background count runs at start-up and
then every `Notifications:RetentionReview:IntervalHours` (server-side, default 24): Diagnostics'
*Retention review* row shows how many are waiting and how many are under a legal hold, as of that count (in memory; a
restart counts again). With `Notifications:RetentionReview:Email` on, the Legal / Privacy distribution
(`Email:LegalDistribution`) gets the counts once a month. The job only counts (ADR 0004): it never archives or deletes,
and CaseBook has no purge. Nothing needs scheduling outside CaseBook; to monitor it, watch the Diagnostics row, or the
app log for "Retention review count failed".

**Stored import documents (CAP-31).** An import sent through the API keeps the document it was sent with (up to 5 MB)
while it waits for review. Once it's applied or rejected, `Retention:DecidedImportDays` (default 90; 0 keeps every
document) decides how long the document stays: a nightly step of the access-log retention job (and one at start-up, and
whenever the setting changes) clears it after that. The decision row stays: who sent it and when, the document's
SHA-256, who decided, when, why and the case it went into, so the sender's status call (`GET /api/import/cases/{id}`)
still answers. Imports waiting for review, or claimed and still being applied, keep theirs. Each run that clears
anything writes an audit-trail entry (entity type `PendingImport`) saying how many and the cutoff. If you need the
documents longer (to re-read what a detection platform sent), raise the setting before the first night after
upgrading. A failure is logged as "Import retention failed" and retried a few minutes later.

---

## 9. Full-text search on SQL Server (CAP-22)

Now in **[operations/full-text-search.md](operations/full-text-search.md)**.
