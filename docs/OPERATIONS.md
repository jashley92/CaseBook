# CaseBook — Operations & Deployment Guide

Operational runbook for the on-prem production deployment (Windows Server + IIS, SQL Server 2022).
Covers backup/DR (backlog **H-03**), integrity signing-key management (**F-05b**), and related
host controls. Dev uses SQLite and needs none of this.

---

## 1. Backup & Disaster Recovery (H-03)

The system's integrity guarantees are only as good as the ability to restore a trustworthy copy.
Three data sets must be backed up **in lockstep** so they stay mutually consistent:

| Data set | Location | Backup method |
|----------|----------|---------------|
| Case database | SQL Server 2022 (`IncidentManager` DB) | Native SQL backups (below) |
| Evidence blobs | `EvidenceStore:RootPath` (outside webroot) | File backup of the whole tree |
| Integrity seals | `Integrity:ExportPath` (out-of-band seal exports) | File backup (append-only) |
| Generated reports | `ReportOutput:RootPath` | File backup |
| Report branding logo | `ReportBranding:RootPath` (`DataRoot\branding`, H-07) | File backup (single small image; low churn) |

### 1.1 SQL Server backup schedule (recommended baseline)

- **Full** backup nightly.
- **Differential** backup every 4–6 hours.
- **Transaction-log** backup every 15 minutes (DB must be in FULL recovery model).
- Write to a **secured, encrypted** share; keep an **immutable/offsite** copy (WORM or object-lock).
- Enable **backup checksums** and **TDE** (transparent data encryption) at rest.

Example (adjust paths/retention to policy):

```sql
-- Nightly full
BACKUP DATABASE [IncidentManager]
  TO DISK = N'\\backup-share\IncidentManager\full\IncidentManager.bak'
  WITH CHECKSUM, COMPRESSION, INIT;

-- Log backup (every 15 min via SQL Agent)
BACKUP LOG [IncidentManager]
  TO DISK = N'\\backup-share\IncidentManager\log\IncidentManager.trn'
  WITH CHECKSUM;
```

### 1.2 Evidence, seals & reports

- Back up the evidence store **with** each DB backup window so blob references never dangle.
- The evidence store is immutable by design (files are content-hashed and never rewritten), so an
  incremental/file-level backup is sufficient and cheap.
- Seal exports (`Integrity:ExportPath`) are append-only; include them in every backup — they are the
  out-of-band tamper-evidence anchor and must survive a DB compromise.

### 1.3 Restore verification (do not skip)

A backup that has never been restored is a hypothesis, not a control.

- **Monthly**: restore the latest full + logs to an isolated recovery instance.
- After restore, run the app's **chain verification** (Integrity page → *Verify now*, or the
  hosted auto-verify job) and confirm the chain is intact end-to-end.
- **Verify a prior seal** against the restored DB: pick a seal whose `UpToSequence` predates the
  restore point and confirm it still reports VALID. This proves both the backup fidelity and that
  history was not altered.
- Record **last successful backup** and **last verified restore** timestamps where Admin can see them
  — the app surfaces them (below).

### 1.3.1 Backup-health status file (H-04)

The app surfaces backup/restore freshness on **Administration → Diagnostics → Backup & restore health**,
warning when either signal is older than its cadence threshold. It reads this from a small **JSON status
file that the backup and restore-verification jobs write** — the app only ever *reads* it (never writes),
so the signal is available even while the database itself is being restored, and it stays out of the
tamper-evident audit chain (it is ops telemetry, not a case mutation).

Point the app at the file and set thresholds in server-side config:

```jsonc
"BackupStatus": {
  "FilePath": "D:\\ops\\casebook-backup-status.json", // absolute path; app-pool identity needs read
  "BackupMaxAgeHours": 24,   // nightly full → warn if the last backup is older than this
  "RestoreMaxAgeDays": 35    // monthly restore verification → warn if older than this
}
```

The jobs write this shape (UTC, ISO-8601; extra fields ignored):

```json
{
  "lastBackupUtc": "2026-08-14T02:00:00Z",
  "lastVerifiedRestoreUtc": "2026-07-20T03:00:00Z",
  "lastBackupSizeBytes": 524288000,
  "note": "Nightly full + 15-min logs; monthly restore verified on the recovery instance."
}
```

- **`lastBackupUtc`** — stamp on each successful SQL full/diff backup (e.g. from the SQL Agent job's
  final step). **`lastVerifiedRestoreUtc`** — stamp only after the monthly restore **and** its chain +
  prior-seal verification pass (§1.3). A missing value reads as **Missing** (more serious than stale);
  an age past the threshold reads as **Stale**; a future timestamp is treated as stale (clock skew).

Example final step for the backup job (PowerShell) — merge, don't clobber the restore timestamp:

```powershell
$path = 'D:\ops\casebook-backup-status.json'
$s = if (Test-Path $path) { Get-Content $path -Raw | ConvertFrom-Json } else { [pscustomobject]@{} }
$s | Add-Member -NotePropertyName lastBackupUtc -NotePropertyValue (Get-Date).ToUniversalTime().ToString('o') -Force
$s | ConvertTo-Json | Set-Content $path -Encoding utf8
```

### 1.3.2 Evidence-at-rest re-verification (F-17)

The audit hash-chain protects each evidence row's recorded **SHA-256** (it is part of the row's
canonical, chain-hashed content). It does **not** re-check that the *stored bytes* still match that
hash — so bit-rot, a silently substituted file, or a deletion under the evidence store would go
undetected until someone tried to open the file. F-17 closes that gap: a background job periodically
**re-hashes every stored evidence file** and compares it to the recorded hash.

- **Enable and schedule it** under **Administration → Settings → Integrity**
  (`Integrity:EvidenceVerify:Enabled`, default **off**; `Integrity:EvidenceVerify:IntervalHours`,
  default **24**). It is off by default because a full re-hash of the store is I/O-heavy; turn it on
  where the evidence store's at-rest integrity matters. A pass also runs once at startup.
- **On drift** (hash mismatch, missing, or unreadable file) it raises the same out-of-band alarm as the
  F-16 chain-break: a `LogLevel.Critical` event **`EventId 5003`** (the SIEM signal, counts only — no
  filenames), the same event on the F-18 stream, and **email** to `Email:IntegrityAlertDistribution`
  (the offender list — case number, evidence id, filename). The alarm fires **once per drift episode**
  and re-arms only after a clean pass.
- **Status** is surfaced on **Administration → Diagnostics → Evidence-at-rest integrity** (last checked,
  count verified, and any offenders) and, on drift, a persistent app-wide banner for Administer users.
- Like the backup-health signal, the job **only reads** — it records nothing to the database and is not
  part of the audit chain (ops telemetry, not a case mutation), so a tamper that targets the store or
  the DB cannot also suppress the signal. Recover drifted files from the out-of-band evidence backups
  (§1.2); the recorded hash tells you what the original bytes must hash to.

### 1.4 RTO / RPO

Document target RTO/RPO with the business. The 15-minute log cadence above implies an RPO of
≤15 minutes; RTO depends on restore automation and hardware. Adjust to the insurer's records policy
and any NYDFS Part 500 expectations (Legal owns the regulatory interpretation).

---

## 2. Integrity Signing-Key Management (F-05b)

Integrity seals are signed with an RSA key (RSASSA-PKCS1-v1_5-SHA256). **In development** the app
generates the key to `Integrity:SigningKeyPath` (`App_Data/keys/seal-signing.pem`) on first use.
This is convenient but means a host compromise could re-sign forged seals — unacceptable in prod.

### Production hardening

- **Provision the key out of band**, do not let the app generate it. Generate on a trusted admin
  workstation / HSM and install it, then point `Integrity:SigningKeyPath` at it (or replace the
  `ISealSigner` implementation with a cert-store/HSM-backed one).
- **Protect the private key** with one of:
  - Windows **DPAPI** (machine or, better, a dedicated service-account scope), or
  - the **Windows certificate store** with a non-exportable key, or
  - an **HSM / Azure Key Vault Managed HSM** for the strongest separation.
- **Restrict file ACLs** to the app-pool identity only (the dev signer already best-effort-restricts
  the file; verify it in prod).
- **Export the public key** and store it separately so seals can be verified by an independent party
  even if the app server is lost. Record the `KeyId` (public-key thumbprint) shown on the Integrity
  page alongside your key inventory.
- **Rotate** on a defined schedule and on suspected compromise. Rotation does not invalidate old
  seals — each seal records the `KeyId` and `Algorithm` that produced it, so keep retired **public**
  keys available for verification.
- Back up the key material under the same immutable/offsite regime as the database, but with tighter
  access control.

---

## 3. Host Controls

- **Endpoint EDR/AV**: run a host **endpoint EDR/AV** agent whose sensor scans the evidence-store
  path on access/write at the host level. Ensure the evidence, seal, and report
  directories are **included** in the EDR monitoring policy and not inadvertently excluded.
- **IIS / app-pool hardening**: least-privilege app-pool identity; HTTPS/TLS only (HSTS enabled in
  non-dev); security headers via `SecurityHeadersMiddleware`; server header suppressed.
- **Authentication**: production requires `Auth:Mode=Windows`; the app refuses to start in Production
  otherwise (see F-02), so the dev auth handler can never run in prod.
- **SQL access**: use integrated auth to SQL (no SQL credentials in config).
- **Download rate limiting (F-13)**: the evidence/report/export endpoints are throttled per user by a
  token bucket, so a compromised account can't bulk-scrape artifacts. Tune under `RateLimiting:Downloads`
  (`TokenLimit` = burst, `TokensPerPeriod` over `PeriodSeconds` = sustained rate; defaults 40 / 40 / 60s).
  Over budget returns **429** with a `Retry-After` header and emits SIEM **`EventId 5306`** — a spike of
  these from one account is a bulk-exfiltration signal worth a detection rule. The inline timeline
  thumbnail endpoint is intentionally exempt (many load at once; it is image-only and need-to-know scoped).
- **Health probes (H-09)**: three **anonymous** endpoints for IIS / a load balancer / uptime monitoring —
  they return the status word only (no case data, no paths, no exception text), so they are safe to expose
  to an internal monitor:
  - `GET /health/live` — **liveness**: the process is up and the pipeline responds. Runs no dependency
    checks. `200 Healthy`. Use this for the app-pool / container "is it running" probe.
  - `GET /health` (alias `GET /health/ready`) — **readiness**: additionally verifies **database
    connectivity** (a cheap `CanConnect`, no case data) and **evidence-store reachability** (the configured
    root exists — catches an unmounted/disconnected data volume). `200 Healthy`, or **`503 Unhealthy`** if a
    dependency is down. Point the load balancer's health check here so a node with an unreachable DB or
    evidence volume is pulled from rotation instead of serving 500s. Complements the backup-health (H-04)
    and evidence-drift (F-17) signals on the Diagnostics page, which cover freshness/tamper rather than
    live reachability.

---

## 4. Deploy-time Checklist

- [ ] `Auth:Mode=Windows`; AD group → role mappings under `RoleMapping:Groups` match real groups.
- [ ] `Database:Provider=SqlServer` and a valid integrated-auth connection string.
- [ ] SQL Agent backup jobs (full/diff/log) scheduled to a secured, encrypted, offsite target.
- [ ] Evidence / seal / report / branding directories exist outside the webroot, ACL-restricted, and in
      the backup set and the EDR monitoring policy.
- [ ] Web root is **read/execute-only** — on SQL Server the app writes no `App_Data` under the content
      root (H-07); every store lives under `DataRoot`. No Modify carve-out on the site folder is required.
- [ ] Load balancer / uptime monitor points at **`/health`** (readiness) and the app-pool/container probe
      at **`/health/live`** (liveness) — H-09. Both are anonymous and status-only; no auth exception needed.
- [ ] Signing key provisioned out of band and protected (DPAPI/cert store/HSM); public key + `KeyId`
      archived separately.
- [ ] `DataProtection:KeyPath` set to an ACL-restricted folder (installer creates `DataRoot\dp-keys`) so
      the antiforgery/circuit keyring survives app-pool recycles; keys encrypted at rest (DPAPI machine
      scope). Back it up with the other stores. A scaled-out farm needs a shared key location + certificate.
- [ ] `Integrity:AutoSeal:Enabled=true` with an interval appropriate to activity volume.
- [ ] `Integrity:EvidenceVerify:Enabled=true` (F-17) with an interval appropriate to store size, and
      `Email:IntegrityAlertDistribution` populated so drift is actively alarmed (§1.3.2).
- [ ] `BackupStatus:FilePath` set and the backup/restore jobs writing it (§1.3.1); Diagnostics →
      Backup &amp; restore health reads **Fresh** for both signals.
- [ ] A restore has been performed and chain + prior-seal verification passed on the restored copy.
- [ ] SQL Server 2022 **updatable ledger** enabled for defense-in-depth (backlog E-10), digest
      exported externally.
- [ ] (Optional) Email notification triggers (E-03b/E-03d) — all admin-editable under **Settings → Notifications**,
      and all requiring **Send email** on to deliver: **Assignment notifications** (email the assignee when
      assigned to a case); **Overdue after-action reminders** (a slow background scan — like AutoSeal /
      EvidenceVerify — that emails each item's owner, or the case's incident commander as a fallback, once
      when it passes its due date); **Due-soon after-action reminders** (the same, once as an item enters its
      lead window). Escalation to Breach also emails the **Legal/Privacy distribution** if set. All off/empty by
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
- [ ] (Optional) `Secrets:CyberArk` enabled (F-19, §6) if secrets should come from CyberArk CCP: `BaseUrl`
      (HTTPS) + `AppId` set, the CCP AppID allow-listed to this host/identity (and a client cert in
      `LocalMachine\My` with the app-pool granted read on its key, if used), and each externalized secret
      (e.g. `Siem:Webhook:Token`) written as a `@cyberark:Safe=…;Object=…` reference.

---

## 5. SIEM Security-Event Stream (F-18)

CaseBook can emit a single, structured **security-event stream** to a SIEM (or any JSON webhook) so the
SOC can build detection rules over app activity — reads, downloads, exports, authorization denials,
role/mapping changes, and case-governance actions — alongside the existing audit-chain tamper alarm.

**Transports: webhook (JSON) and syslog (CEF).** Events queue in memory once and a background dispatcher
**fans each out to every enabled transport**:
- **Webhook** — HTTPS `POST` of a JSON body to the SIEM's HTTP collector.
- **Syslog** — a **CEF** message over syslog (UDP or TCP) to a syslog collector.

Delivery is **best-effort and non-blocking**: a slow or unreachable collector never adds latency to, or
fails, a user action, and one failing transport never stops the others. The tamper-evident audit chain
remains the system of record; a dropped event is not a data-integrity concern. (A Windows Event Log
transport is the remaining planned option — the sink is pluggable.) Enable either or both.

### Configuration (`Siem:*`, server-side only)

These carry an endpoint (and, for the webhook, a secret), so they live in `appsettings.json` /
environment — **not** the in-app editable settings. Admin → Server configuration shows each transport's
status (enabled / endpoint / token present) but never the token value. Both transports are **disabled by
default**.

**Queue:** `Siem:QueueCapacity` (default `2048`) — bounded in-memory depth shared by both transports;
excess events are dropped and logged.

**Webhook** (`Siem:Webhook`):

| Key | Meaning | Default |
|-----|---------|---------|
| `Enabled` | On/off | `false` |
| `Url` | SIEM HTTP collector endpoint (HTTPS) | `""` |
| `Token` | Bearer token / API key (secret). Literal, or a `@cyberark:` reference resolved via CCP — see §6 | `""` |
| `AuthHeader` | Header carrying the token (`Authorization` or e.g. `x-api-key`) | `Authorization` |
| `AuthScheme` | Scheme prefix on an `Authorization` header (blank = raw value) | `Bearer` |
| `TimeoutSeconds` | Per-POST timeout | `5` |
| `MaxAttempts` | Delivery attempts before drop | `3` |

Point `Url` at your SIEM's **HTTP log collector**; set `Token`/`AuthHeader`/`AuthScheme` to match how it
authenticates. Rather than commit the token, either use a protected config source or — preferably — store
it in **CyberArk** and set `Token` to a `@cyberark:` reference (**§6, F-19**) so no secret lives in config.

**Syslog** (`Siem:Syslog`):

| Key | Meaning | Default |
|-----|---------|---------|
| `Enabled` | On/off | `false` |
| `Host` | Syslog collector (SIEM syslog receiver, rsyslog, …) | `""` |
| `Port` | Collector port | `514` |
| `Protocol` | `Udp` (fire-and-forget) or `Tcp` (LF-framed) | `Udp` |
| `Facility` | Syslog facility number (16 = local0) | `16` |
| `AppName` | APP-NAME in the RFC 5424 header | `CaseBook` |
| `TimeoutSeconds` | Connect/send timeout (TCP only) | `5` |

Syslog emits one **CEF** record per event, wrapped in an RFC 5424 line
(`<PRI>1 TIMESTAMP HOST APP - - - CEF:0|CaseBook|CaseBook|…`). CEF/syslog severities map from the event
severity; the CEF extension carries `suser`, `act`, `outcome`, `cat`, `cs1`=case number, `cs2`=target,
`msg`=detail, `dvchost`.

### Event payload (stable parse contract)

`{ eventId, category, action, outcome, severity, actor, actorUpn?, caseNumber?, targetType?, targetId?,
detail?, atUtc, host, app }` — camelCase, enums as strings, nulls omitted. Events carry **only**
ids/labels/actions — never case content, affected-individual PII, or before/after values.

### Event-ID catalog

| ID | Category | Meaning |
|----|----------|---------|
| 5001 | Integrity | Audit-chain integrity failure (also the F-16 critical log/email alarm) |
| 5002 | Integrity | Non-whitelisted AppSettings override rejected on load (S-02 tamper signal) |
| 5003 | Integrity | Evidence at rest drifted from its recorded SHA-256 (F-17 critical log/email alarm) |
| 5101 | Authentication | Authentication failure |
| 5201 | Authorization | Access denied (403) |
| 5301 | DataAccess | Case opened |
| 5302 | DataAccess | Evidence downloaded |
| 5303 | DataAccess | Report downloaded |
| 5304 | DataAccess | Data exported (metrics / IOC feed / bundle / audit CSV) |
| 5305 | DataAccess | **Restricted** case accessed (elevated severity) |
| 5306 | DataAccess | Download/export refused by the per-user rate limit (F-13; possible bulk-scrape) |
| 5401 | Admin | Role created / updated / deleted |
| 5402 | Admin | AD-group → role mapping added / removed |
| 5403 | Admin | Operational setting changed |
| 5501 | Governance | Legal hold placed |
| 5502 | Governance | Legal hold released |
| 5503 | Governance | Case escalated to Breach |

These ids are a **stable contract** — pin SIEM rules to them; they are only ever appended to, never
renumbered. **5101** fires on a failed **Windows (Negotiate) authentication handshake**, so it is a
production-only signal (the development auth handler never fails).

---

## 6. Secret Management (F-19)

App secrets read from configuration (today just the SIEM webhook `Token`; more may follow — e.g. an
authenticated SMTP relay credential) can be **kept out of config entirely** and fetched at runtime from
**CyberArk Central Credential Provider (CCP / AIMWebService)**. It is **opt-in and per-secret**: a value
is used literally unless it is written as a reference, so nothing changes until you choose to move a
specific secret to CyberArk.

**How a secret is selected**

- **Literal (default):** the configured value is the secret, exactly as before.
- **Reference:** a value of the form `@cyberark:Safe=<safe>;Object=<object>` (any `;`-separated CCP query
  parameters — `Safe`, `Folder`, `Object`, …) is fetched from CCP by **AppID + query**. The install-wide
  **AppID** comes from config, not the reference, so a reference names only *where* the secret is, never a
  credential.

Example — move the SIEM webhook token to CyberArk:

```jsonc
"Siem":    { "Webhook": { "Enabled": true, "Url": "https://collector...",
                          "Token": "@cyberark:Safe=SIEM;Object=CaseBook-Webhook-Token" } },
"Secrets": { "CyberArk": { "Enabled": true,
                          "BaseUrl": "https://ccp.corp.example/AIMWebService",
                          "AppId":   "CaseBook",
                          "ClientCertificateThumbprint": "‹thumbprint of a cert in LocalMachine\\My›",
                          "CacheTtlSeconds": 300, "FailClosed": true } }
```

**Configuration (`Secrets:CyberArk`, server-side only)**

| Key | Meaning | Default |
|-----|---------|---------|
| `Enabled` | Master switch. Off → all values are literals; a `@cyberark:` reference fails **closed** | `false` |
| `BaseUrl` | AIMWebService base URL. **Must be HTTPS** | `""` |
| `AppId` | CCP Application ID this app is provisioned as | `""` |
| `ClientCertificateThumbprint` | Optional client cert (in `LocalMachine\My`) for mutual TLS | `""` |
| `CacheTtlSeconds` | How long a fetched secret is cached (supports rotation without a restart) | `300` |
| `TimeoutSeconds` | Per-request timeout to CCP | `5` |
| `FailClosed` | On a CCP error: `true` → resolve to unavailable (safe degrade); `false` → serve the last-known-good cached value (never a plaintext-config fallback) | `true` |

**Authentication to CCP — who configures what.** There is **no CCP password to store** — that is the point
of CCP. The **CyberArk admin** decides how this application authenticates when they define its **Application
(AppID)** in the Vault, choosing any combination of: a **client certificate**, an **Allowed Machines**
list (source **IP address** / hostname), and/or the requesting **OS user**. CaseBook simply *presents* an
identity on each call; CCP accepts or rejects it against the AppID's rules. So most of the setup is on the
CyberArk side, and CaseBook's config is deliberately tiny. What you do here depends on the method(s) the
AppID requires:

| Authentication method (set on the CCP **AppID** by the CyberArk admin) | What CaseBook must do |
|---|---|
| **Client certificate** (whether the AppID marks it *required* or *optional*) | Install the cert in **`LocalMachine\My`**, grant the **app-pool identity read on its private key**, and set **`ClientCertificateThumbprint`**. This is the only auth method that needs a CaseBook config value. |
| **Allowed Machines — source IP / hostname** | **Nothing in config.** Ensure the web host reaches CCP from the **IP/hostname the admin allow-listed** — mind NAT, proxies, and multi-homed egress (the IP CCP *sees* is what matters, not the host's local IP). |
| **OS user** | **Nothing in config.** Run the CaseBook app pool under the **identity the admin allow-listed** — i.e. the gMSA / service account from [INSTALL.md §1.2](INSTALL.md); that account is the OS user CCP will see. |

Notes:

- **"Cert required" is a CCP-side switch, not a CaseBook one.** CaseBook attaches a client cert **only when
  `ClientCertificateThumbprint` is set**; if the AppID requires a cert and the thumbprint is blank (or the
  cert can't be loaded), every fetch fails closed and the Diagnostics health panel shows *Last attempt
  failed*. Conversely, setting a thumbprint the AppID doesn't expect is harmless — CCP ignores it.
- **Methods combine (defense in depth).** A common hardened setup is *client cert **and** Allowed-Machines
  IP* — the admin sets both on the AppID; CaseBook sets the thumbprint and you make sure the host egresses
  from the allow-listed IP. No extra CaseBook config for the IP half.
- **App identity is set once, in the installer.** The app-pool identity (which drives both *OS user* and,
  via the host, *source IP*) is `AppPoolIdentity` from `Install-CaseBook.ps1` / the answers file — so the
  account and host you give CyberArk to allow-list are the ones the install already uses.
- If the AppID authenticates **only** by Allowed-Machines and/or OS user, leave `ClientCertificateThumbprint`
  blank — that is a valid, fully-supported configuration.

**Failure behaviour.** A reference that cannot be resolved returns **unavailable** — never the reference
text — so a caller treats it as "no secret". For the webhook that means the event is sent **without** an
auth header (and the collector will reject it) rather than leaking a bogus token; the failure is logged.
With `FailClosed=false`, a transient CCP outage instead serves the **last successfully fetched** value past
its TTL, so a working integration is not dropped by a blip.

**Admin visibility (read-only).** Secrets are **never editable in the app** — this stays host-side config.
Two read-only views help operators confirm it is wired up and working:
- **Administration → Server configuration** shows a *Secret store — CyberArk CCP* row with status badges
  only (Enabled/Disabled · endpoint configured · AppID set · client-cert vs machine/OS-user auth) — never a
  value.
- **Administration → Diagnostics → Secret resolution (CyberArk)** shows live health: overall status
  (Healthy / Last attempt failed / No activity), the **last success** and **last error** (timestamp, the
  reference *location*, and a safe reason such as `HTTP 403 (APPAP004E)` — never the secret), and running
  success/failure counts. It is in-memory and resets on restart. A persistent *Last attempt failed* here is
  the first place to look if an integration that depends on a CyberArk-backed secret stops authenticating.

**Candidates.** First applied to `Siem:Webhook:Token`. Any future config-borne credential (e.g. E-03 SMTP)
should resolve through the same seam. The **seal signing key** (F-05b) and **Always-Encrypted column keys**
(F-14) are noted as candidates but generally prefer the Windows certificate store / HSM over CCP.
