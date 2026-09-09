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

---

## 4. Deploy-time Checklist

- [ ] `Auth:Mode=Windows`; AD group → role mappings under `RoleMapping:Groups` match real groups.
- [ ] `Database:Provider=SqlServer` and a valid integrated-auth connection string.
- [ ] SQL Agent backup jobs (full/diff/log) scheduled to a secured, encrypted, offsite target.
- [ ] Evidence / seal / report directories exist outside the webroot, ACL-restricted, and in the
      backup set and the EDR monitoring policy.
- [ ] Signing key provisioned out of band and protected (DPAPI/cert store/HSM); public key + `KeyId`
      archived separately.
- [ ] `DataProtection:KeyPath` set to an ACL-restricted folder (installer creates `DataRoot\dp-keys`) so
      the antiforgery/circuit keyring survives app-pool recycles; keys encrypted at rest (DPAPI machine
      scope). Back it up with the other stores. A scaled-out farm needs a shared key location + certificate.
- [ ] `Integrity:AutoSeal:Enabled=true` with an interval appropriate to activity volume.
- [ ] `BackupStatus:FilePath` set and the backup/restore jobs writing it (§1.3.1); Diagnostics →
      Backup &amp; restore health reads **Fresh** for both signals.
- [ ] A restore has been performed and chain + prior-seal verification passed on the restored copy.
- [ ] SQL Server 2022 **updatable ledger** enabled for defense-in-depth (backlog E-10), digest
      exported externally.
- [ ] (Optional) `Siem:Webhook` configured to the SIEM's HTTP collector (see §5) if the security-event
      stream is wanted.

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
| `Token` | Bearer token / API key (secret) | `""` |
| `AuthHeader` | Header carrying the token (`Authorization` or e.g. `x-api-key`) | `Authorization` |
| `AuthScheme` | Scheme prefix on an `Authorization` header (blank = raw value) | `Bearer` |
| `TimeoutSeconds` | Per-POST timeout | `5` |
| `MaxAttempts` | Delivery attempts before drop | `3` |

Point `Url` at your SIEM's **HTTP log collector**; set `Token`/`AuthHeader`/`AuthScheme` to match how it
authenticates. Prefer an environment variable / protected config source over committing the token.
**Planned (backlog F-19):** optional retrieval of `Token` (and any other app secret) from **an external
secrets manager** instead of config.

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
| 5101 | Authentication | Authentication failure |
| 5201 | Authorization | Access denied (403) |
| 5301 | DataAccess | Case opened |
| 5302 | DataAccess | Evidence downloaded |
| 5303 | DataAccess | Report downloaded |
| 5304 | DataAccess | Data exported (metrics / IOC feed / bundle / audit CSV) |
| 5305 | DataAccess | **Restricted** case accessed (elevated severity) |
| 5401 | Admin | Role created / updated / deleted |
| 5402 | Admin | AD-group → role mapping added / removed |
| 5403 | Admin | Operational setting changed |
| 5501 | Governance | Legal hold placed |
| 5502 | Governance | Legal hold released |
| 5503 | Governance | Case escalated to Breach |

These ids are a **stable contract** — pin SIEM rules to them; they are only ever appended to, never
renumbered. **5101** fires on a failed **Windows (Negotiate) authentication handshake**, so it is a
production-only signal (the development auth handler never fails).
