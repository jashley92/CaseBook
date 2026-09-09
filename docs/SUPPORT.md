# CaseBook — Support & Troubleshooting Runbook

A runtime playbook for the team that **supports** CaseBook after it is live. It assumes the app is already
installed (see **[INSTALL.md](INSTALL.md)**) and running (see **[OPERATIONS.md](OPERATIONS.md)**). For how
the app is built internally, see **[ARCHITECTURE.md](ARCHITECTURE.md)**.

> **Golden rule — never edit the database or the file stores directly.** CaseBook is a *tamper-evident*
> record. Any out-of-band change to the `AuditLog`, business rows, evidence blobs, seals, or `AppSettings`
> will **break the hash chain** or trip the settings-tamper alarm — which looks exactly like an attack and
> triggers a Critical alert. Make every change **through the app**. If you think the data itself is wrong,
> escalate to engineering; do not "fix" it in SQL.

---

## 1. System at a glance — where everything lives

| Thing | Where | Notes |
|---|---|---|
| The app | IIS site on the app host, in-process (ASP.NET Core Module) | App pool identity = gMSA/service account |
| Case database | SQL Server 2022, `IncidentManager` DB | FULL recovery, RCSI; integrated auth (no SQL password) |
| Evidence & report blobs | `EvidenceStore:RootPath` / `ReportOutput:RootPath` on the data volume | **Off the web root**, ACL-restricted, EDR-monitored |
| Integrity seals (out of band) | `Integrity:ExportPath` | Append-only; the tamper-evidence anchor |
| Signing key | `Integrity:SigningKeyPath` | Provisioned out of band in prod; ACL to app-pool identity |
| Data-protection keyring | `DataProtection:KeyPath` | Antiforgery + Blazor circuit keys; must persist across recycles |
| Operational settings | `AppSettings` table (edited in-app) | Whitelisted; audited; live-reloaded |
| Security/infra settings | `appsettings.Production.json` / env | Connection string, `Auth:Mode`, keys, `RoleMapping`, `Siem:*` |
| Backup-health signal | `BackupStatus:FilePath` JSON | Written by the backup/restore jobs; **read** by the app |

**In-app diagnostics live at:** Administration → **Diagnostics** (backup/restore health, config source),
**Integrity & Audit** (verify now, seals, audit trail), **Access log**, **Roles & access**, **Settings**.

---

## 2. Is it healthy? — the 60-second check

1. **App responds:** the dashboard loads for a signed-in, mapped user.
2. **Integrity is green:** Integrity & Audit → **Verify now** reports the chain **VALID**, and there is **no
   red integrity banner** at the top of the app. (The banner is app-wide and shared by every session.)
3. **Recent seal exists:** the Integrity page shows a seal within the last `IntervalHours` (default 6h) with
   a matching `KeyId`.
4. **Backups fresh:** Diagnostics → **Backup & restore health** reads **Fresh** for both the last backup and
   the last verified restore.
5. **No Critical events:** the Windows **Application** event log (and the SIEM, if wired) has no `5001`
   (audit-chain failure) or `5002` (rejected setting override) since the last check.

If all five are green, the system is doing its job.

---

## 3. Signals reference — what to look at

| Source | What it tells you | How to read it |
|---|---|---|
| **Windows Application event log** (app host) | App startup failures, the **Critical `5001`** audit-chain alarm, **`5002`** rejected-setting-override, email/seal-export warnings | Event Viewer → Windows Logs → Application; filter by source = the app / by Event ID |
| **`logs\stdout`** in the site root | ASP.NET Core Module stdout when the app won't start (500.30/500.31) | Enable stdout logging in `web.config` if not already; then reproduce |
| **IIS logs** | HTTP status per request (401/403/500.x) | `%SystemDrive%\inetpub\logs\LogFiles` |
| **In-app Integrity & Audit** | Chain verify result, first broken sequence, seals, filtered audit trail | Administer role; "Verify now" runs the same check as the background monitor |
| **In-app Access log (C-05)** | **Who read** a case or pulled an artifact/export; restricted flag; coalesced view-sessions | Administer role; filter by actor/case/type/date; CSV export |
| **SIEM stream (F-18)** | Structured security events (auth-fail 5101, 403 5201, data access 53xx, admin 54xx, governance 55xx, integrity 5001/5002) | Only if `Siem:Webhook`/`Siem:Syslog` is enabled; see OPERATIONS §5 for the catalog |

**Two logs, two purposes — don't confuse them:**
- The **audit trail** (Integrity & Audit) is the tamper-evident record of **mutations** — the system of
  record for "who changed what."
- The **access log** (C-05) is the out-of-chain, prunable record of **reads** — "who looked at what." It is
  intentionally *not* in the chain so high-volume reads never disturb the tamper-evidence.

---

## 4. Support playbooks

### 4.1 "Who did X to this case?" / "Who looked at this case?"

- **Changed it (mutation):** Integrity & Audit → filter by case number (and actor/date/entity). Each row is
  an audited change with actor, action, and before→after. Export one case's trail via the workspace Audit
  tab or `GET /export/case-audit.csv`.
- **Only read it (no change):** Administration → **Access log**, filter by case/actor. Case opens and
  artifact/export downloads appear here (subject to the configured **scope**). The workspace also shows a
  leadership-only "Viewed by" panel.
- If a read you expect is missing, check **`Access:LogScope`** — if it's `RestrictedOnly`, only
  restricted-case opens (and all artifact/exports) are recorded; unrestricted case opens are not.

### 4.2 A user "can't see a case" that they expect to

Almost always **need-to-know scoping**, working as designed. A case is visible to a user only if **any** of:
it is **not restricted**, they are the **Incident Commander**, they are **assigned**, or they hold
**`ViewAllCases`** (Manager/Legal, or a custom role granting it).

Diagnose in order:
1. Is the case **restricted**? (Workspace shows it.) If so, the user must be assigned/IC or have
   `ViewRestricted`/`ViewAllCases`.
2. What roles does the user actually have? Roles & access shows role→AD-group mappings; the user's roles
   come from their **AD group membership**. A recent AD group change is only picked up on the **next app
   restart** (the SID→name cache is process-lifetime).
3. Is this the right fix? If they genuinely need access, **assign them** (or their role needs the
   capability) — don't remove the restriction unless that's the intent.

There is **no existence leak**: a not-permitted case and a nonexistent case both return "not found." That is
deliberate, not a bug.

### 4.3 A user gets "access denied" everywhere / lands on `/access-denied`

They are **authenticated but unprovisioned** — signed in to Windows fine, but in **no mapped AD group**, so
they have no role and no permissions.

1. The `/access-denied` page shows **who they're signed in as**. Confirm that identity.
2. Check `RoleMapping:Groups` in `appsettings.Production.json` names the **real** AD group names, and that
   the user is actually a member of one.
3. Fix the membership (or the mapping) and **restart the app** so the mapping/SID cache refreshes.
4. This event is emitted to SIEM as **5201** (authorization denied) — expected when it's a provisioning
   gap, worth correlating if it's unexpected.

### 4.4 The red **integrity alarm** banner is showing / a `5001` fired

Treat as a **potential integrity/security incident**, not a routine bug. The audit hash-chain failed
verification — history may have been altered, truncated, or reordered, **or** the covering seal no longer
matches.

1. **Preserve evidence first:** do **not** restart, re-seal, or "fix" anything. Preserve the current
   database **and** the out-of-band seal exports (`Integrity:ExportPath`).
2. Integrity & Audit shows the **first broken sequence** and detail. Note it.
3. Verify the most recent **signed seal**: if the signature is authentic but the chain head no longer
   matches, history was rewritten *after* sealing; if the signature itself is invalid, the seal record was
   altered or signed by a different key.
4. New seals are **automatically suspended** while the chain is broken — leave it that way.
5. Follow the incident-response / restore path in OPERATIONS.md; a restore from a known-good backup +
   prior-seal verification (OPERATIONS §1.3) is the recovery.
6. **Common benign cause to rule out:** someone edited the database directly (see the Golden Rule). If a
   DBA/tool touched any protected table, that alone will trip this. Establish whether a person did that
   before assuming an attack.

### 4.5 A `5002` "rejected setting override" fired at startup

An `AppSettings` row exists whose key is **not** an editable operational setting, so the app **ignored** it
on load (it can never override a connection string, auth mode, signing key, or SIEM endpoint). Because the
audited settings path can't write such a row, its presence means it got in **out-of-band** — DB tamper, a
hand-edit, or a restored/merged backup carrying a stray row.

1. Find the row: the Critical log line names the rejected **key**.
2. Determine how it got there (restore? manual edit?). Treat an unexplained one as a tamper signal.
3. Remove it **through a supported path** or, if you must touch SQL, understand you are modifying the DB
   (which the chain protects) — coordinate with engineering. The app already refused to honor it, so there
   is no urgency to "apply" it.

### 4.6 A settings change in Admin "didn't take effect"

1. Confirm it's an **operational** setting (in the in-app editor). Security/infra settings are read-only
   and changed in `appsettings` + restart.
2. Settings **live-reload within a few minutes** (they re-bind through `IOptionsMonitor` after a config
   reload) — some consumers pick up the new value on the **next new circuit** (e.g. idle timeout applies to
   sessions started after saving). Have the user reload their tab.
3. Check the effective value and **source** in Admin (it shows whether a value comes from Default, file, or
   a DB override). If the source is "Default" when you expected an override, the save didn't persist —
   re-save and watch for a validation error.

### 4.7 Evidence or report **won't download** (404/not found)

1. **Need-to-know:** the endpoints apply the same `ForUser` scoping. A user without access to the parent
   case gets "not found" — this is correct. Verify their access to the case first (§4.2).
2. **Inline thumbnail refused:** `/evidence/{id}/inline` serves **only genuine raster images** (PNG/JPEG/
   GIF/WebP by magic bytes). An SVG or a mislabeled file is refused by design (S-04) — the **Download**
   button still works for the real file.
3. **Missing blob on disk:** if the DB has the `Evidence`/`Report` row but the file is gone, the store
   read fails. This means the **file store and DB drifted** — usually a backup/restore that didn't include
   the file stores in lockstep (OPERATIONS §1.2). Restore the blob tree to match the DB point-in-time.
4. **Report integrity:** the workspace can re-verify a stored report's SHA-256 against the recorded hash. A
   mismatch means the stored file changed after generation — preserve and escalate.

### 4.8 Backup/restore health shows **Stale** or **Missing**

The app only **reads** the `BackupStatus:FilePath` JSON; the **backup and restore-verification jobs write
it** (OPERATIONS §1.3.1).

- **Missing** (more serious than stale): the file/value isn't there. Confirm `BackupStatus:FilePath` is set
  and the app-pool identity can **read** it, and that the backup job's final step is actually **writing**
  `lastBackupUtc`.
- **Stale:** the timestamp is older than its threshold (`BackupMaxAgeHours` / `RestoreMaxAgeDays`). The
  **job** stopped running or stopped stamping — investigate the SQL Agent backup job / the monthly restore
  rehearsal, not the app. A **future** timestamp reads as stale (clock skew).

### 4.9 SIEM isn't receiving CaseBook events

1. Is a transport **enabled**? `Siem:Webhook:Enabled` / `Siem:Syslog:Enabled` are **off by default**.
2. Admin → Server configuration shows each transport's status (enabled / endpoint / **token present**) —
   never the token value. Confirm the endpoint and that a token is present for the webhook.
3. Delivery is **best-effort and non-blocking** — a dead collector is **logged as a warning and dropped**,
   never retried forever, and never blocks the app. Check the app log for transport warnings.
4. Remember **5101 (auth failure) is production-only** — it fires on a failed Windows/Negotiate handshake;
   the dev auth handler never fails, so you won't see it in a dev/test instance.
5. The queue is **bounded** (`Siem:QueueCapacity`, default 2048); under a flood, excess events are dropped
   and logged. The audit chain remains the system of record, so a dropped event is not a data problem.

### 4.10 App won't start after a deploy/restart

Cross-reference the **[INSTALL.md Troubleshooting table](INSTALL.md#troubleshooting)** — it covers the
common startup faults precisely. The highlights:

| Symptom | Likely cause |
|---|---|
| Log: *"Auth:Mode is 'Dev' in Production"* | `appsettings.Production.json` not deployed, or environment isn't Production. **This is a fail-safe, not a bug** — prod must be Windows auth. |
| `500.19` and **no app log** | ASP.NET Core Module not registered — install the **.NET 8 Hosting Bundle** (not just the SDK), `iisreset`. |
| `500.30 / 500.31` on first hit | Bad connection string, or the app can't write `App_Data`. Check Application event log + `logs\stdout`. |
| `401` for everyone | Windows Auth not negotiating — missing SPN, or Anonymous still enabled. |
| DB: *CREATE TABLE permission denied* | App account lacks DDL under `AppMigrates`. Re-run the DB step or apply the schema as a DBA. |

---

## 5. Escalation matrix

| Situation | First responder | Escalate to |
|---|---|---|
| App down / won't start | Platform/IIS support (INSTALL troubleshooting) | Engineering if config is correct but it still fails |
| Access/permissions question | Support desk (§4.2/§4.3) + AD team for group membership | Engineering if scoping behaves against spec |
| **Integrity alarm `5001`** | **Security incident process** — preserve, don't touch | Security lead + engineering, per OPERATIONS IR/restore |
| **`5002` rejected setting** | Security triage (§4.5) | Engineering to trace provenance |
| Backup/restore health stale | Backup/DBA team (it's a job problem, not the app) | — |
| Data looks wrong in a record | **Do not edit SQL** — capture the case number + audit rows | Engineering |
| SIEM not ingesting | Support (§4.9) + SIEM team for collector config | — |

---

## 6. Things support must **never** do

- **Never edit the `AuditLog`, business tables, evidence blobs, seals, or `AppSettings` directly in SQL.**
  It breaks tamper-evidence and trips Critical alarms. Change data **through the app**.
- **Never delete or re-create the signing key** to "clear" an integrity error — you destroy the ability to
  verify prior seals. Key rotation is a deliberate, documented op (OPERATIONS §2).
- **Never set `Auth:Mode=Dev` in production**, even temporarily to "get in" — it authenticates everyone as
  a full admin. The app refuses to start this way on purpose.
- **Never restore only the database** without the matching evidence/seal/report blobs — references dangle
  and prior seals fail to verify. Restore the three sets **in lockstep** (OPERATIONS §1).
- **Never disable the integrity background job** to silence a banner — investigate the break instead.
- **Never put a secret (SIEM token, connection string) into the in-app settings** — those stay in
  server-side config; the app will ignore an out-of-band override and alarm on it (`5002`).

---

## 7. Quick reference

**Roles → capability (default system roles):**

| Role | Sees restricted cases | Sees all cases | Edits | Approves reports | Admin |
|---|:--:|:--:|:--:|:--:|:--:|
| Analyst | assigned/IC only | — | ✓ | — | — |
| Incident Commander | ✓ | — | ✓ | ✓ | — |
| Manager (leadership) | — | ✓ | — | — | — |
| Legal/Privacy | ✓ | ✓ | — | — | — |
| SysAdmin | ✓ | ✓ | ✓ | ✓ | ✓ |

**Ports & auth:** HTTPS 443 inbound; TDS 1433 app→SQL (integrated auth); Kerberos/LDAP to AD.

**Default cadences:** integrity verify + alarm every **10 min**; auto-seal every **6h**
(`Integrity:AutoSeal:IntervalHours`); backup freshness thresholds `BackupMaxAgeHours` 24 /
`RestoreMaxAgeDays` 35.

**Key SIEM / log event IDs:** `5001` audit-chain failure · `5002` rejected setting override · `5101`
auth failure (prod only) · `5201` access denied · `53xx` data access · `54xx` admin/config · `55xx` case
governance. Full catalog: OPERATIONS §5.

---

*See also: [ARCHITECTURE.md](ARCHITECTURE.md) for how it works, [OPERATIONS.md](OPERATIONS.md) for
backup/DR/key management, [INSTALL.md](INSTALL.md) for install & startup troubleshooting.*
