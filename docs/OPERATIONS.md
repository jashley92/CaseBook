# CaseBook — Operations & Deployment Guide

Operational runbook for the on-prem production deployment (Windows Server + IIS, SQL Server 2022). Related:
[configuration reference](operations/configuration.md), [troubleshooting](operations/troubleshooting.md),
[integrations](operations/integrations.md), [install](INSTALL.md), [upgrade](UPGRADE.md).
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
| Keys folder | `<DataRoot>\keys` (the seal-signing key, `chain-key.json`, `evidence-key.json`) | File backup with tighter access; the evidence key's envelope is useless without a certificate or the shares, but keep it with the rest ([§2, Evidence key](#evidence-key-encryption-at-rest-backups-and-recovery-prod-57)) |
| Data Protection key ring | `DataProtection:KeyPath` (`DataRoot\dp-keys`) | File backup **with the database**, tight access. Besides keeping sessions across recycles, it decrypts the secrets saved under Administration: the SMTP password (CAP-05), and the team-chat webhook URL and the SIEM webhook token (CAP-40). A database restored without it can't open them: email that signs in is held, chat isn't posted, the SIEM webhook stops rather than sending without its token, and Diagnostics says which to re-enter ([troubleshooting](operations/troubleshooting.md)). The keys are DPAPI-protected to the machine, so on a new server these are re-entered anyway. |
| Report branding logo | `ReportBranding:RootPath` (`DataRoot\branding`, H-07) | File backup (single small image; low churn) |
| Word report templates | `ReportTemplates:RootPath` (`DataRoot\report-templates`, PROD-47; when unset, a `report-templates` folder beside `ReportBranding:RootPath`, so upgraded servers need no config change) | File backup (one .docx per library template, named by its id; low churn) |

**What this server holds (CAP-19).** Administration → Diagnostics → **Backup set** lists the database's name and each
of these paths as this server resolves them (key files set outside the keys folder are listed on their own), with
whether it's there, whether CaseBook's account can write it, its size and its last write. The seal export folder is
judged writable by its last seal copy, never by a test file (it may be WORM), and the evidence store by its own probe.
Each folder's walk is limited to 5 seconds and 200,000 entries, so a share that's down says "didn't answer" and a very
large store says "at least". **`GET /export/backup-manifest.json`** (Administer; access-logged, SIEM 5304) gives the same
as JSON for a backup job to read its folder list from, or a restore drill to compare against: paths and metadata only,
never a key or the connection string. Pull it with the job's Windows account, for example
`Invoke-WebRequest https://casebook.contoso.com/export/backup-manifest.json -UseDefaultCredentials -OutFile manifest.json`.

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
  incremental/file-level backup is sufficient and cheap. The one exception: when evidence encryption is turned on,
  each file stored before is rewritten once, encrypted (§2, Evidence key). Expect one full backup's worth of change.
- Seal exports (`Integrity:ExportPath`) are append-only; include them in every backup — they are the
  out-of-band tamper-evidence anchor and must survive a DB compromise.

### 1.2.1 Evidence storage: limits, large uploads and network shares

**Limits (PROD-55).** Administration › Governance & security › Evidence storage sets the largest file
(`Evidence:MaxUploadMB`, default 500 MB, up to 64 GB), the most all evidence may take (`Evidence:StorageQuotaGB`, no
limit by default) and the free space an upload must leave on the store (`Evidence:MinFreeSpaceGB`, default 10 GB).
Every way evidence arrives (picked, dropped, sent in parts, a pasted screenshot) is checked before a byte is stored
and again once its real size is known. Uploaders are warned at 90 % of the limit. Administration › Diagnostics ›
Evidence storage shows where the store is, whether CaseBook can write and read there, what it holds and what's free.

**Large files (PROD-56).** A file over 100 MB, such as a memory dump, uploads in 8 MB parts with a progress bar, so no
request comes near IIS's 30 MB limit and nothing in IIS needs changing. A part lost on the network is sent again. The
file is read back and its SHA-256 checked before it's recorded (`Evidence:ReadBackCheck`). **An upload that stops
part-way is kept** (PROD-59): a network failure, the page closed, or the app restarting. Its state is saved beside its
parts in `<store>\.incoming`, and the Evidence tab lists it under **Unfinished uploads** for the person who started
it; they pick the same file again to carry on (it's checked by name, size and the SHA-256 of its first megabyte), or
discard it. One resumed after a restart is read back in full when it completes, every part checked against the hash
it arrived with, whatever `ReadBackCheck` says. Only **Cancel** deletes an upload at once; one with nothing sent for a
day is deleted from `<store>\.incoming`.

**The same file twice.** A file already evidence in the same case (by SHA-256) isn't stored again: the upload is
refused, naming the first copy, whose chain of custody stands. In another case it's stored, and the uploader is told
which other cases (among those they can see) hold it.

**A store on a network share.** `EvidenceStore:RootPath` (installer `-EvidencePath`) may be a UNC path such as
`\\files01\casebook$\evidence`.
- The app-pool account needs **Modify** on the folder (NTFS) and **Change** on the share. With a gMSA that's the gMSA;
  with the built-in ApplicationPoolIdentity, the share sees the web server's computer account (`DOMAIN\WEB01$`).
  Remove inherited access for everyone else; keep SYSTEM and Administrators. The installer sets the folder's rights
  when it can and prints what to grant when it can't.
- CaseBook probes the store (writes, reads back and deletes a small file) at every start and hourly, with a time limit
  so a share that's down can't hang it. A failure is logged with the account and the reason and shown on Diagnostics.
- While the share is down, uploads are refused, downloads answer that the store can't be read, and the evidence
  re-check reports **one** finding, "evidence store unreachable", instead of every file missing. Earlier findings
  stand until their files are checked again. `/health` reports Unhealthy. When the share is back, all of it clears
  without a restart.
- **A store that held evidence is never recreated empty.** If the share answers but the store's folder isn't there
  (the share was remapped, a DFS target or drive changed, the folder was moved), CaseBook treats it as the outage
  above rather than making a new, empty folder: otherwise new uploads would land in the stand-in and every recorded
  file would read as missing. Only a fresh install (no evidence recorded) has its folder created at start-up. To move
  a store, follow *Moving an existing store* below.
- Put the share on storage that is backed up with the database (section 1.2), and keep the data root's `keys` folder
  off the share.

**Moving an existing store** to another folder or a share: stop the app pool; copy with
`robocopy <old> <new> /E /COPY:DAT /DCOPY:DAT`; grant the rights above; set `EvidenceStore:RootPath` to the new path in
`appsettings.Production.json`; start the app pool; then run **Verify now** on the Integrity page and check the
evidence re-check on Diagnostics. Stored paths are relative to the store, so the database doesn't change. Keep the
old copy until the re-check is clean.

**Safe download (PROD-58).** A file that can run (a program, script, shortcut, disk image, Office file with
macros or web page, by its name and type) shows **Can run** on the Evidence tab and downloads first as **Download
safely**: a zip holding the file, with the password `infected`, the security field's convention. A double-click can't
run it, and the analyst's antivirus doesn't delete it on arrival; the zip opens in Windows Explorer and every zip tool.
Its encryption is classic zip encryption, there to stop accidents, not to keep the file secret. The plain file is
behind a confirmation; any file can be downloaded as a zip. `Evidence:SafeDownload` makes the zip the first choice for
every file (`Always`) or none (`Off`). A program renamed to look harmless and uploaded with a harmless type isn't caught
by its name; choose `Always` to wrap every file. The chain of custody records which kind of download it was. Every
evidence download is sent as plain bytes (never the type its uploader's browser claimed) with a sandboxing
`Content-Security-Policy`.

**Evidence packages (CAP-12).** *Package evidence…* on the Evidence tab hands many files over at once: one zip with the
password `infected` (the same encryption as the safe download), streamed from the store and decrypted as it's read, so
no plain copy is written on the server, holding the files and a `MANIFEST.txt` (the case, the recipient, method and
purpose, and each file's SHA-256, size, collection, upload and chain of custody so far). It's limited to 500 files and,
in all, the largest single file the store takes (`Evidence:MaxUploadMB`); a larger hand-over is several packages.
Each counts against the `downloads` rate limit.

**How a package is recorded: begun, then sent in full or partial.** The zip streams with a data descriptor after each
file, and such a zip can be read file by file from its local headers even without its closing directory (7-Zip, or any
streaming unzip, recovers every file that arrived), so a package that stops part-way is still a hand-over of what went
out. So it's recorded in steps, each step's custody and its audit entry in one transaction (both or neither):

- **Begun**, before the first byte: a "Transfer begun" custody event on every file, naming the package (its id) and
  the hand-over, and an audit entry with the package id, the hand-over, and each file's name and SHA-256 (for a large package the list is cut to the entry's 2,000 characters; each file's own
  custody event names the package, and its SHA-256 is on its record); with it the
  access-log row and SIEM 5308. If this can't be written, nothing is sent (the download answers 503).
- **Sent in full**: each file gets "Transferred", and the audit trail an entry with the SHA-256 of the zip as sent and
  of its manifest (the recipient can check the zip they received against it), written before the zip's directory goes
  out. (A download cut off in those last bytes keeps this record, since every file and the manifest left; the log says so.)
- **Stopped part-way** (cut off, past its time limit, a store or key outage, a file that doesn't match): each file gets
  how far it got, "Transferred" (sent in full), "Partly transferred" or "Not transferred", and the audit trail an entry
  "stopped after N of M files" naming which went out in full, in part and not at all, and why.

A begun record with nothing after it means the server stopped before it could record the end: treat it as partial
(every file in it may have gone). The log says which happened, and says so when the end couldn't be recorded. "Sent"
means written to the connection: what reached the recipient may be less, never more. Each file is checked against its
SHA-256 before any of it is sent, so a file that no longer matches is never sent ("Not transferred", and the package
stops; the evidence check reports it); this reads each file twice (see integrity.md for the cost). A package that
stopped is prepared again. A download that's sent slower than about 1 MB/s on average (after 15 minutes) is stopped.
The log names the package id and the case.

**Withdrawn evidence (CAP-21).** A file filed on the wrong case is withdrawn from its panel with a reason, not
deleted: its bytes stay in the store (and in backups), its custody gets a "Withdrawn" event, the audit trail an
update, and the SIEM 5516. It drops out of the case's report, gates and packages but can still be downloaded, each
download logged. A withdrawn copy isn't named as "also evidence in" its case elsewhere; Find still finds it, marked
*Withdrawn*. No task is added about it and no transfer of it is recorded. There's no undo; the right file is uploaded again.

**Disk encryption.** Turn on BitLocker (or the storage's own encryption) for the data root's volume and the evidence
store's. With CaseBook's own evidence encryption on (§2, Evidence key) a copied disk or backup no longer exposes
evidence or reports, but the database and the logs are still on those volumes.

### 1.3 Restore verification (do not skip)

A backup that has never been restored is a hypothesis, not a control.

- **Monthly**: restore the latest full + logs to an isolated recovery instance.
- **Restore as a set.** The database, the evidence store and the data root's `keys` folder must come from the same
  point. With evidence encryption on, run `casebook-keytool verify --site <site folder> --cert <thumbprint>` (or a
  recovery certificate, or `--shares`) on the restored server before it serves anyone: it proves the key the files
  need opens there. A database restored from before encryption still finds the key id in the envelope kept beside
  the evidence (`<store>\.key\evidence-key.json`).
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
**re-hashes the stored evidence files** and compares each with its recorded hash.

- **Enable and schedule it** under **Administration → Settings → Integrity**
  (`Integrity:EvidenceVerify:Enabled`, default **off**; `Integrity:EvidenceVerify:IntervalHours`,
  default **24**; `Integrity:EvidenceVerify:PassDays`, default **7**). Each run re-hashes one share of the
  files, so every file is checked at least once in `PassDays` days and a large store is read a seventh at a
  time rather than end to end daily (PROD-53). A run also happens at startup, and a run after an outage or a
  settings change may leave a file for up to twice `PassDays`. A drift found stays reported until that file
  is checked again. Set `PassDays` to 1 to re-hash every file every run. It is off by default because
  re-hashing is I/O-heavy; turn it on where the evidence store's at-rest integrity matters.
- **On drift** (hash mismatch, missing, or unreadable file) it raises the same out-of-band alarm as the
  F-16 chain-break: a `LogLevel.Critical` event **`EventId 5003`** (the SIEM signal, counts only — no
  filenames), the same event on the F-18 stream, and **email** to `Email:IntegrityAlertDistribution`
  (the offender list — case number, evidence id, filename). The alarm fires **once per drift** (an item and
  what's wrong with it): a drift that persists doesn't repeat it, a new one does even while an older one persists,
  and one that clears and comes back alerts again (REV-09).
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

Integrity seals are signed with an RSA key (RSA-3072, RSASSA-PSS-SHA256 with a 32-byte salt). Seals and configuration bundles signed before v1.4.0 (RSASSA-PKCS1-v1_5-SHA256) still verify: each is checked by the algorithm it records. **Only in Development**
does the app generate a missing key at `Integrity:SigningKeyPath` (`App_Data/keys/seal-signing.pem`). In any
other environment a missing key **stops startup** ("The seal-signing key … doesn't exist"), because a key the
app made for itself on the server means a host compromise could re-sign forged seals. Install the production
key **before the app first starts**.

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
  seals: each seal records the `KeyId` and `Algorithm` that produced it, and is checked with that key.
  Keep each retired key's **public** half in the retired seal keys folder (below).

### Where the key lives (F-23)

`Integrity:SigningKey:Source` chooses; it's server configuration only, never an in-app setting.

| Source | Settings | What to know |
|---|---|---|
| `File` (default) | `Integrity:SigningKeyPath` | A PEM private key, readable only by the app account. A copy of the server's disk includes it. |
| `CertificateStore` | `CertificateThumbprint` (spaces allowed, as copied from the certificate console); `StoreLocation` = `LocalMachine` (default) or `CurrentUser`; store `My` | Windows signs with the certificate's private key. Import it **non-exportable** so it can be used but never copied out, and grant the app account **read** on the private key (Manage Private Keys). Any RSA certificate of 2048 bits or more; a self-signed one is fine, since trust comes from the key id you record, not a chain. |
| `CyberArk` | `Secret` = `@cyberark:Safe=…;Object=…`, the PEM private key as the object's content | Needs `Secrets:CyberArk` enabled (§6). The key is fetched once at startup and held only in memory; it's never written to disk. CyberArk's log shows each fetch. |

Whichever the source, a key that can't be loaded stops startup with a message naming the setting. The Integrity
page shows the source and the key id in force. Moving between sources is a key change if the key itself changes:
put the old public key in the retired folder first (below). Moving the **same** key (for example, importing the
existing PEM into the certificate store) keeps its key id, and nothing else is needed.

### The audit chain key (F-25, off by default)

Without it, each audit entry's hash is plain SHA-256, so someone who can write to the database can rewrite the
entries made since the last seal (6 hours by default) and recompute every hash after them. With the chain key on,
new entries are hashed with HMAC-SHA256 under a secret the database doesn't hold, so that no longer works. Entries
written before keep their plain hash and still verify; the first keyed entry marks the switch, and every entry after
it must be keyed.

`Integrity:ChainKey` (server configuration only):

| Setting | Meaning |
|---|---|
| `Enabled` | `false` by default. |
| `Source` | `CyberArk` or `Certificate`. |
| `Secret` | CyberArk: an `@cyberark:Safe=…;Object=…` reference to **32 random bytes, base64-encoded**. |
| `RetiredSecrets` | CyberArk: references to earlier keys, so entries hashed with them still verify. |
| `CertificateThumbprint`, `StoreLocation` | Certificate: the certificate the key is encrypted to (it can be the signing certificate); the app account needs read on its private key. |
| `WrappedKeyPath`, `RetiredWrappedKeysPath` | Certificate: the encrypted key file and a folder of earlier ones. The installer sets them to `<DataRoot>\keys\chain-key.json` and `<DataRoot>\keys\chain-retired`; blank means `chain-key.json` and `chain-retired` beside `SigningKeyPath`, even when the signing key isn't a file. Keep them out of the site folder: an upgrade mirrors it from the new build. If they're blank and that folder is in the site (no `SigningKeyPath`), `Upgrade-CaseBook.ps1` copies any files there to `<DataRoot>\keys` and sets the paths (and `RetiredPublicKeysPath`), and stops instead if a different file is already there. |

Making a CyberArk key (Windows PowerShell or PowerShell 7), then storing the output as the object's content:

```powershell
$b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b)
```

With `Certificate`, CaseBook makes the key on its first start with the chain key on, and keeps only its encrypted
form in `chain-key.json` (which names the certificate). The file is useless without the certificate's private key.

**Before turning it on, back the key up.** Turning it on is one-way in practice: keyed entries can only be checked
while their key is held. If the key is lost, the integrity check reports the first keyed entry as unverifiable
("hashed with chain key …, which this server doesn't hold") and keeps alarming; the seals still prove the history
up to each seal is intact, but the per-entry check can't run. So: for CyberArk, make sure the object is in your
vault backup; for Certificate, back up the certificate with its private key **and** `chain-key.json`. Don't turn the
chain key off afterwards: new entries would get the plain hash, and the check reports that as a break.

A key that can't be loaded stops startup with a message naming the setting. So does a missing `chain-key.json` on a server whose audit log already has entries keyed with a key it doesn't hold (a restore without the keys folder, a moved `WrappedKeyPath`): restore the file rather than letting CaseBook start a new key that would leave those entries unverifiable. So does a missing `chain-key.json` while the database can't be read (unreachable, offline, restoring, or the app account refused): CaseBook can't tell a first start then, so it waits until the database is back. A rotation, with the old file in `chain-retired`, starts normally. The Integrity page shows whether the
chain key is on, where it comes from and its key id (key ids are derived from the key and reveal nothing).

**Rotating it:** CyberArk: put the old reference in `RetiredSecrets`, point `Secret` at a new object, restart.
Certificate: move `chain-key.json` into `chain-retired`, restart (a new key is made; the old file still decrypts,
even if it was encrypted to an earlier certificate that's still in the store).

### Extra seal copies (F-27, each off unless set)

Every seal is already written to the database, to `Integrity:ExportPath` and, with a SIEM transport on, to the SIEM
as event 5004 (§5). The copy that matters is one the people who run CaseBook's database and servers can't change.
Three optional extras:

- **An append-only share.** Point `Integrity:ExportPath` at a share on a server CaseBook's administrators don't
  administer, and let the app account create files there but not change or delete them. On the share's folder,
  give the account the right to create files in the folder itself, and only read on the files it holds:

  ```powershell
  icacls '\\files01\casebook-seals' /grant 'CONTOSO\svc-casebook$:(WD,AD,RA,REA,RC,X)'
  icacls '\\files01\casebook-seals' /grant 'CONTOSO\svc-casebook$:(OI)(IO)(R)'
  ```

  CaseBook writes each seal file in the same call that creates it, so it never needs to reopen one for writing.
  Confirm on your file server that the account can create a file there but not replace or delete one, and that the
  share permissions don't grant more. It isn't WORM: an administrator of that file server can still change files,
  so keep that role apart from CaseBook's.
- **A seal digest by email** (`Integrity:SealCopies:EmailTo`, comma-separated): each seal's sequence, chain-head
  hash, key id, time and signature, to a mailbox under Microsoft 365 retention or a litigation hold. Needs email
  turned on in-app; with email off, the copy is reported as failed rather than skipped.
- **RFC 3161 timestamps** (`Integrity:SealCopies:TimestampAuthorityUrl`): for an organization with its own timestamp
  authority. Only internal addresses are accepted (the host must resolve to private, loopback or link-local
  addresses; anything else stops startup), so CaseBook never sends seals to the internet. Each token is saved beside
  the seal's JSON copy as `seal-<sequence>-<time>-<id>.tsr` (each seal its own file); check one with
  `openssl ts -verify -data payload.txt -in seal-….tsr -token_in -CAfile <your TSA's CA>` (the payload as in
  `VERIFY.txt`). A timestamp proves the seal existed at that time, so even someone holding the signing key can't
  backdate a rewritten history.

A failed copy never undoes the seal: it's logged, sent as SIEM event 5005 naming the destination, and shown under
**Integrity & audit → Keys and seal copies** with its last error.

### Rotating the signing key

1. Export the current key's public half and put it in the **retired seal keys folder**:
   `Integrity:RetiredPublicKeysPath`, or a `retired` folder beside the signing key when that's blank. Any `*.pem`
   file there is read at startup; a private-key file works too (only its public half is kept), but keep private
   keys out of that folder. A file that isn't a readable RSA key stops startup, naming the file.
2. Install the new private key in place of the old one, and restart.
3. On the Integrity page, check the new `KeyId` and re-verify an older seal: it reports authentic. A seal whose
   key isn't held says so ("Signed by key …, which this server doesn't hold"); add that key's public half to the
   folder.

Compliance bundles include every retired public key (`retired-public-keys/<KeyId>.pem`), so an examiner can check
seals from before the rotation offline. Public keys aren't secret; the folder only needs to be protected from
change, like the rest of the data root.
- Back up the key material under the same immutable/offsite regime as the database, but with tighter
  access control.

### Evidence key: encryption at rest, backups and recovery (PROD-57)

With this on, evidence files and generated reports are stored encrypted (AES-256-GCM), so a copied disk or backup
doesn't expose them and the server's antivirus can't delete a malware sample. Why it's built this way:
[ADR 0017](decisions/0017-evidence-encryption-and-key-recovery.md). Off by default.

**Losing the key loses every encrypted file.** Set up the backups below before turning it on, and run a drill.

`Storage:Encryption` (server configuration only, never the in-app settings). It's in `appsettings.Production.json`,
turned off: put there by the installer, or by the upgrade on a server installed before v1.7.0.

| Setting | Meaning |
|---|---|
| `Enabled` | `false` by default. |
| `RecoveryCertificates` | Paths to `.cer` files (public part only). The key is also encrypted to each; their private keys stay offline. |
| `CertificateThumbprint`, `StoreLocation` | Optional: a certificate of its own to protect the key, kept apart from the audit chain's. Blank uses the integrity keys already configured (below). |
| `EnvelopePath` | Optional: where the key's envelope is kept; blank is `evidence-key.json` beside the seal-signing key (`<DataRoot>\keys`). |

**What protects the key on the server.** CaseBook makes the key once and keeps it only encrypted, in an envelope.
The server's copy is protected by, in this order: `CertificateThumbprint` if set, else the chain key's certificate,
else the seal-signing certificate (`Integrity:SigningKey:Source = CertificateStore`), else a key derived from the chain
key in CyberArk. With none of these, Diagnostics says encryption can't start; configure one (this section, above).
When that certificate is renewed and the old one is still in the store, the key is re-encrypted to the new one at
the next check (daily, and at start-up). Leave the old certificate in the store until Diagnostics shows the new one.

**Its backups.** Encryption doesn't start until there's at least one of the first two; until then evidence is stored
as before and Diagnostics says why.

1. **Recovery certificates.** Make two, each with its own custodian, on a machine other than the CaseBook server
   (or issue them from your certificate authority with key-encipherment usage):

   ```powershell
   $c = New-SelfSignedCertificate -Subject "CN=CaseBook evidence recovery (custodian A)" -CertStoreLocation Cert:\CurrentUser\My `
        -KeyAlgorithm RSA -KeyLength 3072 -KeyExportPolicy Exportable -KeyUsage KeyEncipherment -NotAfter (Get-Date).AddYears(10)
   Export-Certificate -Cert $c -FilePath .\casebook-recovery-a.cer
   Export-PfxCertificate -Cert $c -FilePath .\casebook-recovery-a.pfx -Password (Read-Host -AsSecureString "PFX password")
   Remove-Item "Cert:\CurrentUser\My\$($c.Thumbprint)" -DeleteKey
   ```

   Copy the `.cer` to the server (for example `<DataRoot>\keys\recovery\`) and list it in `RecoveryCertificates`. Put
   the `.pfx` and its password in the safe (or keep the key on a smartcard). Any one of them recovers the key, and the
   chain key when it's on, without the server. Expiry doesn't matter for recovery; Diagnostics notes it.
2. **Shares.** On the server, as an administrator: `deploy\keytool\casebook-keytool split --site <site folder>
   [--threshold 3] [--shares 5] [--out <folder>]`. Give each share (one line, `CBS1-…`) to a different person or safe,
   on paper or USB, and delete the output folder (`--out` makes it readable by administrators only). Any 3 rebuild the key; 2 reveal nothing. CaseBook records that
   shares were issued, never the shares. A holder checks theirs, on any machine, with `casebook-keytool check-share`.
3. **The envelope**, kept by CaseBook in three places: the keys folder, the database (`KeyEnvelopes`) and beside the
   evidence (`<store>\.key\evidence-key.json`). A missing or damaged copy is rewritten from a good one at the next
   check. Back them up with everything else (section 1); they're useless without a certificate or the shares.
4. **CyberArk**, when the chain key comes from there: its vault backup covers the server's copy.

**Checks and drills.** Every day, CaseBook checks each envelope copy, the recovery copies and the server's protection,
and alerts the integrity distribution once per problem. Diagnostics shows the state, the copies, the backups and the
last drill. The offline backups can't be tested by the server alone (that would let anyone who took over the server
open them), so drill them at least yearly; Diagnostics reminds after 12 months:

```powershell
casebook-keytool verify --site C:\inetpub\casebook --pfx E:\casebook-recovery-a.pfx   # asks for the password
casebook-keytool verify --site C:\inetpub\casebook --shares                           # asks for the shares
```

**Turning it on.** Configure the backups, set `Enabled` to `true` (or, at install, the answers file's
`EvidenceEncryption`, `RecoveryCertificates` and `EvidenceKeyThumbprint`: INSTALL.md §4), restart the app pool, and
check Diagnostics shows **On**. New files are encrypted from then on. Files stored before are converted in the background, starting 15
minutes after start-up (after `Upgrade-CaseBook.ps1`'s warm-up), or at once with **Convert now** on Diagnostics. Each
is checked against its recorded hash before and after, and only then replaces the original; one that doesn't match
is left as it is and reported. Conversion needs free space for the largest file. **It's one-way:** an earlier
CaseBook version can't read converted files, so a rollback after it also needs the evidence store restored from
before it (or the files exported, below).

**When the key can't be opened** (a certificate removed or its rights changed, CyberArk down, a restore without the
keys folder): CaseBook keeps running. Evidence and report downloads, uploads and report generation answer that the
evidence key isn't available, and nothing is stored unencrypted. One alarm goes out (a Critical log line, the
integrity email, the administrators' banner) and Diagnostics names the cause. The key is retried every 5 minutes,
so fixing the cause clears it without a restart. CaseBook never makes a new key while files or an envelope need one
it can't open.

**Recovering the key onto a new certificate** (the server certificate is lost, or a new server):

1. Install the new certificate (with its private key, not exportable) in `LocalMachine\My` on the server, and give
   the app-pool account read on its private key.
2. As an administrator: `casebook-keytool recover --site <site folder> --pfx <recovery .pfx>` (or `--cert
   <thumbprint>` for one on a smartcard, or `--shares`) `--to-cert <new thumbprint>`. The new certificate's private key
   must be usable there, or nothing is changed. Add `--chain-key` to rebuild `chain-key.json` onto the same certificate
   when the chain key was lost with it. It's refused if `chain-key.json` still opens on that server, or if the backup
   carries a chain key the audit log has since stopped using (a rotation after the backup was made); an existing file
   that doesn't open is kept beside the new one as `chain-key.json.replaced-<time>`.
3. Set `Storage:Encryption:CertificateThumbprint` (or the chain key's or signing certificate's, whichever protected
   it) to the new thumbprint, and restart the app pool. Diagnostics shows **On**; run a drill.

**Getting the files out.** `casebook-keytool export --site <site folder> (--case <number> | --all) --out <folder>`
writes each file under its original name, per case, with `manifest.csv` listing each file's recorded and actual
SHA-256 (exit code 2 if any differ). It's for eDiscovery, moving to another product or a disaster. It opens the key
with the server's certificate by default, or `--pfx`, `--cert` or `--shares`. The exported files are live: export
malware only to a quarantined location.

**What the keytool does is recorded.** The tool runs apart from the app and can't write the audit trail, so `split`,
`verify`, `recover` and `export` each leave a record in the keys folder's `evidence-key.json`. Within a minute (while
CaseBook runs; otherwise at its next start) CaseBook writes each to the audit trail (an export as an Export entry with
the case, file count, folder and the manifest's SHA-256) and sends it to the SIEM (5007, or 5307 for an export). Run
the tool on the server, against the site's own keys folder, or the record waits for the envelope to be copied back.

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
- [ ] SQL Agent backup jobs (full/diff/log) scheduled to a secured, encrypted, offsite target.
- [ ] Evidence / seal / report / branding directories exist outside the webroot, ACL-restricted, and in
      the backup set and the EDR monitoring policy.
- [ ] Web root is **read/execute-only** — on SQL Server the app writes no `App_Data` under the content
      root (H-07); every store lives under `DataRoot`. No Modify carve-out on the site folder is required.
- [ ] Load balancer / uptime monitor points at **`/health`** (readiness) and the app-pool/container probe
      at **`/health/live`** (liveness) — H-09. Both are status-only and anonymous on an installed site
      (CAP-37); `Verify-Install.ps1 -Url` checks it. A monitoring tool alerts on **`Degraded`** from
      **`/health/alarms`** (CAP-18), which is never a readiness signal.
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

CaseBook can emit a single, structured **security-event stream** to a SIEM (or any JSON webhook) so the
SOC can build detection rules over app activity — reads, downloads, exports, authorization denials,
role/mapping changes, and case-governance actions — alongside the existing audit-chain tamper alarm.

**Transports: webhook (JSON), syslog (CEF) and the Windows Event Log.** Events queue in memory once and a
background dispatcher **fans each out to every enabled transport**:
- **Webhook** — HTTPS `POST` of a JSON body to the SIEM's HTTP collector.
- **Syslog** — a **CEF** message over syslog (UDP, TCP or, CAP-33, TLS per RFC 5425) to a syslog collector.
- **Windows Event Log** — one entry per event on the app server, for Windows Event Forwarding or an agent.

Delivery is **best-effort and non-blocking**: a slow or unreachable collector never adds latency to, or
fails, a user action, and one failing transport never stops the others. The tamper-evident audit chain
remains the system of record; a dropped event is not a data-integrity concern. Enable any combination.

### Configuration (`Siem:*`, server-side only)

These carry an endpoint (and, for the webhook, a secret), so they live in `appsettings.json` /
environment — **not** the in-app editable settings. Admin → Server configuration shows each transport's
status (enabled / endpoint / token present) but never the token value. All three transports are **disabled by
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
| `Protocol` | `Udp` (fire-and-forget), `Tcp` (LF-framed) or `Tls` (CAP-33: RFC 5425, octet-counted), by name; any other value (a number too) stops syslog and Diagnostics says why | `Udp` |
| `Facility` | Syslog facility number (16 = local0) | `16` |
| `AppName` | APP-NAME in the RFC 5424 header | `CaseBook` |
| `TimeoutSeconds` | One limit over connect and send (TCP), and connect, handshake and send (TLS) | `5` |
| `ServerCertificateThumbprint` | TLS: pins the collector's certificate (SHA-1 or SHA-256 hex; spaces and colons ignored). The chain and name are checked as well | `""` |
| `ClientCertificateThumbprint` | TLS: a client certificate in `LocalMachine\My` for a collector that wants mutual TLS (the app pool needs read on its key), as CyberArk's | `""` |

**Syslog over TLS (CAP-33).** With `Protocol` `Tls` (the collector usually listens on 6514), each event goes over its own
TLS connection (as TCP has always done), framed `MSG-LEN SP MESSAGE` (RFC 5425), and the connection is closed with
close_notify. The collector's certificate must chain to a root in this server's trusted store and be issued to `Host`
(use a name the certificate lists); revocation isn't checked. For a collector with a self-signed or private-CA
certificate, import its root (or the certificate) into *Local Computer › Trusted Root Certification Authorities*, and pin
its thumbprint to refuse any other. A refused certificate, a handshake that doesn't finish within `TimeoutSeconds`, or a
collector that wants a client certificate it wasn't given shows on Diagnostics → Delivery health with the reason; a
protocol that isn't a name, a pin that isn't a thumbprint, or a client certificate that's missing or has no readable key
shows the transport as **Stopped** (the store is read again every 5 minutes, so installing the certificate needs no
restart). Nothing is retried, as for UDP and TCP.

Syslog emits one **CEF** record per event, wrapped in an RFC 5424 line
(`<PRI>1 TIMESTAMP HOST APP - - - CEF:0|CaseBook|CaseBook|…`). CEF/syslog severities map from the event
severity; the CEF extension carries `suser`, `act`, `outcome`, `cat`, `cs1`=case number, `cs2`=target,
`msg`=detail, `dvchost`.

**Windows Event Log** (`Siem:EventLog`, Windows hosts only):

| Key | Meaning | Default |
|-----|---------|---------|
| `Enabled` | On/off | `false` |
| `Source` | Event source name | `CaseBook` |
| `LogName` | Log the source is registered in | `Application` |

Each event is written with its catalog id (below) as the **Event ID**; entry type is Error for High/Critical,
Warning for Warning or a denied/failed outcome, else Information. The message is a one-line summary followed
by the same JSON body as the webhook. **Register the source once, as an administrator**, before enabling —
the app runs without the rights to create it and won't try:

```powershell
New-EventLog -LogName Application -Source CaseBook
```

If the source is missing, the transport logs one warning and stays off until the app restarts; the other
transports are unaffected.

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
| 5004 | Integrity | Integrity seal recorded: the SIEM's copy of each seal (F-26; see *Seal copies in the SIEM* below) |
| 5005 | Integrity | A copy of a seal failed (export folder, email digest or timestamp; the detail names it); the seal itself is recorded (F-26/F-27) |
| 5006 | Integrity | **Evidence key unavailable**: encrypted evidence and reports are paused (High; once per episode; the detail gives the reason, never key material) |
| 5007 | Integrity | Evidence key changed. Action: `KeyCreated`, `KeyAvailable` (back after 5006), `KeyProtectionChanged` (renewed certificate, recovery certificates changed), `SharesIssued`, `RecoveryDrill`, or **`KeyRecovered`** (moved onto another certificate; High). Target id is the key id |
| 5101 | Authentication | Authentication failure |
| 5201 | Authorization | Access denied (403) on a page or download **GET** (other 403s aren't streamed) |
| 5202 | Authorization | In-app action refused for lack of a permission |
| 5301 | DataAccess | Case opened |
| 5302 | DataAccess | Evidence downloaded |
| 5303 | DataAccess | Report downloaded |
| 5304 | DataAccess | Data exported: metrics, legal register, program report, improvement actions, IOC feed, case audit CSV, compliance bundle, STIX graph, campaign rollup, Word template preview (the access-log CSV and the configuration bundle don't emit it) |
| 5305 | DataAccess | **Restricted** case accessed (elevated severity) |
| 5306 | DataAccess | Download/export refused by the per-user rate limit (F-13; possible bulk-scrape) |
| 5307 | DataAccess | Evidence written out **decrypted** by `casebook-keytool export` (Warning; actor is the Windows account that ran it; detail has the case, count, folder and the manifest's SHA-256) |
| 5308 | DataAccess | **Evidence package** downloaded for hand-over (CAP-12): many evidence files leaving at once. Warning (High on a restricted case). Target is the package id (`EvidencePackage:<id>`), detail the file count and size; the recipient, method and purpose are in the audit trail, not the stream. Sent as the download begins (with its "begun" record), so a package that stops part-way is in the stream too; how it ended is in the audit trail |
| 5401 | Admin | Role created / updated / deleted |
| 5402 | Admin | AD-group → role mapping added / removed |
| 5403 | Admin | Operational setting changed |
| 5404 | Admin | API token created or revoked |
| 5405 | Admin | **Reference data changed** (CAP-06). Action `ReferenceDataCreated`, `ReferenceDataChanged` or `ReferenceDataDeleted`; target type is the kind (`StageGate`, `DataElement`, `DeadlineRule`, `CaseTemplate`, `CaseOutcome`, `TaxonomyLabel`, `TaxonomyOrder`, `ReportProfile`, `ReportTemplate`, `EmailTemplate`, `ConfigurationBundle`, and from CAP-36 `Team`: a team added, changed, retired or restored, or "(members)" when only who is in it changed), target id the row's id, detail its name (an archive or restore says so in brackets). Warning for a stage gate, a deadline rule or any delete; else Info |
| 5501 | Governance | Legal hold placed |
| 5502 | Governance | Legal hold released |
| 5503 | Governance | Case escalated to Breach |
| 5504 | Authorization | Case restricted to need-to-know |
| 5505 | Authorization | Case restriction lifted (widens who can see it) |
| 5506 | Governance | Case created (CAP-06). Detail `classification=… severity=…` (a case filed as a Breach also sends 5503). Info |
| 5507 | Governance | Phase changed, other than closing or reopening. Detail `from=… to=…`. Info |
| 5508 | Governance | Reclassified, other than escalated to Breach (5503). Action `CaseReclassified`, or **`CaseDowngraded`** when the classification goes down (Warning: a lowered case skips the higher rung's checks when it closes) |
| 5509 | Governance | Case closed. Detail `outcome=<key>`, plus `gateOverridden=true` when it was closed past unmet gate requirements (Warning; else Info) |
| 5510 | Governance | Case reopened (by *Reopen*, or by moving a closed case to another phase). Info |
| 5511 | Governance | Case archived (Info), or **restored** from the archive (action `CaseRestored`, Warning) |
| 5512 | Governance | Materiality recorded. Detail `status=…`; `Material` is a Warning (it can start a disclosure clock), the rest Info |
| 5513 | Governance | Regulators recorded as notified: one regulator (`RegulatorNoticeRecorded`, detail `jurisdiction=<code>`), and the case once every regulator in play is notified (`CaseReported`, no detail; CAP-38: a partly reported case sends only the regulators' own events, and *Mark reported* sends one per notice it records, then `CaseReported`). Info. Taking one back sends `ReportedCleared` or `RegulatorNoticeRemoved` at Warning: the deadline clock runs again. Recording or editing how a regulator was notified (method, reference, who, the file: CAP-07) sends nothing more, and the reference text is never sent |
| 5514 | Governance | Report approved; target is the report. Info |
| 5515 | Governance | Case import applied by a reviewer; target is the pending import when it came through the queue (`PendingImport:<id>`), detail `createdCase=true` when it filed a new case. Info |
| 5516 | Governance | **Evidence withdrawn** from a case (CAP-21); target is the file (`Evidence:<id>`). Warning: the file leaves the case's report and gate counts. Ids only: the file's name and the reason are in the audit trail |
| 5901 | Diagnostics | Test event from **Administration → Diagnostics → Send test event**. Safe to ignore; use it to confirm the collector receives the stream |

These ids are a **stable contract** — pin SIEM rules to them; they are only ever appended to, never
renumbered. **5101** fires on a failed **Windows (Negotiate) authentication handshake** (a production-only
signal; the development auth handler never fails) and, with action `ApiTokenRejected`, on an unknown, expired or
revoked **API token** (the detail carries the token's display prefix and source address, never the token).
**5202** fires when an in-app action is refused at the service layer for lack of a permission: the UI normally
hides what a user can't do, so this marks a stale session (access removed while signed in) or a UI defect.
Today it's emitted by case actions and by the role, settings and configuration-bundle services; refusals in other
services (evidence, reports, lessons, imports, tokens) aren't streamed.

**Case lifecycle and reference data (CAP-06).** 5506-5516 carry the case number (`caseNumber` / CEF `cs1`), the actor
and, when the case records one, the detection platform's incident id as `detection=<id>` at the end of `detail`, so a
rule can join CaseBook's record to the platform's incident. They carry ids and labels only (enum names, outcome keys,
jurisdiction codes), never a reason, a summary or any other text from the case. An exercise's `detail` starts
`EXERCISE:`, as its breach escalation's does; unlike 5503, these are always sent for an exercise (they record activity,
not an alert), so filter on that prefix to keep drills out of a rule. Each is sent after the change is saved, best
effort: a stream that's down never fails the action. Reasons and the full before and after are in the audit trail.
A configuration bundle import sends one 5405 (`ConfigurationBundle`, with its counts and signing key) rather than one
per row it replaced, alongside the 5401-5403 it already sends per role, mapping and setting. The detail ends with how
the key was trusted (CAP-16): `signed with this server's key <id>`, `signed with trusted key <id> (<file>)`, or
`signed with key <id> (not this server's or a trusted one), its id typed to confirm`. Alert on the last: someone
imported configuration from a source the server doesn't know.

**Suggested rules:** a `CaseDowngraded` (5508) followed by a 5509 on the same case within a few days; any 5509 with
`gateOverridden=true`; a 5511 `CaseRestored`; a 5512 `status=Material`; and any 5405 with target type `StageGate` or
`DeadlineRule` outside a change window.

### Seal copies in the SIEM (F-26)

Every integrity seal is also sent as event **5004**, so the SIEM keeps a record of each seal that the people who
run CaseBook's database and servers can't change. `targetId` is the sealed sequence; `detail` is
`head=<chain-head hash> key=<key id> sealedAtUtc=<ISO 8601>`. It goes through every enabled transport; with none
enabled, nothing is sent (configure one to get this copy).

**Checking seals against the SIEM.** Compare the seals in a compliance bundle (`seals.csv`) with the 5004 events
for the same sequences: each seal should have one event with the same chain-head hash and key id. A seal with no
event, or with a different hash, was added, altered or re-signed after the fact; an event with no seal means a
seal was deleted. An XSIAM query to list them (adjust the dataset and field names to how your collector maps the
CaseBook JSON):

```
dataset = casebook_raw
| filter eventId = 5004
| alter sequence = to_integer(targetId),
        head = arrayindex(regextract(detail, "head=([0-9a-f]+)"), 0),
        key_id = arrayindex(regextract(detail, "key=([0-9a-f]+)"), 0)
| fields _time, sequence, head, key_id
| sort asc sequence
```

**Suggested rules:** alert on any **5005** (a seal's folder copy failed), and on **no 5004 for longer than twice
the seal interval** (12 hours at the default 6), which means seals have stopped: sealing failed, the chain is
broken (the job won't seal over a break, and 5001 should have fired), or the stream is down.

---

## 6. Secret Management (F-19)

App secrets read from configuration (the SIEM webhook `Token`, the chat `Chat:Webhook:WebhookUrl` and, CAP-05, the
SMTP password `Email:SmtpPassword`; connection strings, `Agenda:FeedKey` and the other SMTP settings must be
literals or environment variables) needn't be kept in plain text. Each is resolved at runtime through one seam, so a
value may be written three ways, chosen per value:

**The SMTP password is usually entered in the app instead** (Administration → Settings → Notifications → Email
sign-in): it's encrypted with Data Protection and kept in the database, with no keytool step. It's write-only, its
changes are audited, and it needs the Data Protection key ring backed up with the database (§1). Setting
`Email:SmtpUsername`/`SmtpPassword` or `Email:SmtpUseDefaultCredentials` in the file, as below, overrides the form
([integrations.md, Email](operations/integrations.md#email-smtp)). Integrated Windows sign-in as the app-pool gMSA
(`Email:SmtpUseDefaultCredentials`, or *Windows* on the form) needs no password at all.

**The chat webhook URL and the SIEM webhook token can be entered in the app too** (CAP-40): Settings → Notifications →
Team chat webhook, and Server configuration → SIEM webhook token. They're kept as the SMTP password is (Data Protection,
a purpose each, the `StoredSecrets` table), write-only and audited, with the same key-ring backup (§1). A value set in
the file, in any of the three forms below, wins and the card shows it read-only. Either way, a SIEM token that's set
but won't resolve or decrypt stops the webhook's sends rather than sending them unauthenticated
([integrations.md, SIEM](operations/integrations.md#siem-security-event-stream)).

**How a secret is selected**

- **Literal (default):** the configured value is the secret, exactly as before. For the SMTP password,
  Diagnostics warns that it's plain text.
- **Protected (`@protected:`, CAP-05, [ADR 0018](decisions/0018-protected-secrets.md)):** the secret encrypted to a
  certificate in `LocalMachine\My` whose private key the app-pool account can read: no CyberArk, and no new key
  material in the file. Make the value on the server with `deploy\keytool\casebook-keytool protect-secret --cert
  <thumbprint>` (or `--site <site folder>` to use the site's evidence, chain-key or signing certificate); it asks for
  the secret twice without echo and prints only `@protected:v1:<thumbprint>:<data>`. Check one with
  `casebook-keytool check-secret <value>` (OK or why not; never the secret). It works whether CyberArk is on or off.
  A value that won't open (the certificate removed or renewed, its key unreadable, the value changed) is unavailable:
  logged once by thumbprint, never the content. When the certificate is renewed, make the values again for the new
  one before removing the old.
- **Reference:** a value of the form `@cyberark:Safe=<safe>;Object=<object>` (any `;`-separated CCP query
  parameters — `Safe`, `Folder`, `Object`, …) is fetched from **CyberArk Central Credential Provider (CCP /
  AIMWebService)** by **AppID + query**. The install-wide **AppID** comes from config, not the reference, so a
  reference names only *where* the secret is, never a credential. The rest of this section is about CyberArk; it's
  opt-in, and nothing changes until you move a specific secret to it.

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

**Candidates.** Applied to `Siem:Webhook:Token`, `Chat:Webhook:WebhookUrl` and `Email:SmtpPassword` (CAP-05); the first
two can be entered in Administration instead (CAP-40). Any future
config-borne credential should resolve through the same seam, which gives it `@protected:` too. The **seal signing key** (F-05b) and **Always-Encrypted column keys**
(F-14) are noted as candidates but generally prefer the Windows certificate store / HSM over CCP.

## 7. SQL Server Ledger (E-10)

An optional, engine-level control under CaseBook's own tamper evidence. CaseBook already hash-chains the audit
log and signs seals over it (§2), so an edit to history is **detectable**. The ledger makes the three
evidentiary tables **append-only inside SQL Server**, so the engine itself refuses the edit, and gives you
digests that prove later nothing was changed:

| Table | Holds |
|---|---|
| `AuditLog` | The hash-chained audit trail |
| `IntegritySeals` | Signed seals over the chain head |
| `ChainOfCustodyEvents` | Evidence custody history |

Once on, `UPDATE`, `DELETE` and `TRUNCATE` on these tables fail for **every** principal, including `db_owner`
and `sysadmin`. A change made below SQL (editing the data files, restoring a doctored copy) fails
verification against a digest taken earlier. Both were tested against SQL Server 2022 CU27: the refusal on
`sa`, and a single byte changed on a raw data page with `DBCC WRITEPAGE`, reported by verification as a hash
mismatch on `AuditLog`.

CaseBook needs no change to run on ledger tables: it only ever inserts into them. **Administration → Server
configuration** and **Integrity & audit** show whether the ledger is on.

### 7.1 Turn it on (one-way)

A ledger table can't be turned back into an ordinary table. Take a full backup first (the script checks for one
from the last 24 hours and refuses otherwise).

1. Stop the CaseBook app pool.
2. As sysadmin or `db_owner`, after the schema exists (after the app's first start):
   ```powershell
   .\Enable-Ledger.ps1 -ConfigFile .\casebook.config.psd1     # SqlInstance, DbName, LedgerDigestPath
   ```
   It runs `deploy/sql/02-Enable-Ledger.sql`: each table is renamed, rebuilt as an append-only ledger table with
   the same columns, keys and indexes, every row copied and counted, and the old table dropped, one transaction
   per table. It also turns on `ALLOW_SNAPSHOT_ISOLATION`, which verification needs (it doesn't change how
   CaseBook reads). Re-running is safe; converted tables are skipped.
3. Start the app pool. Server configuration shows **SQL Server ledger: On**.

No SqlServer module or `sqlcmd.exe` is needed: the ledger scripts use the SqlClient built into Windows
PowerShell 5.1, with Windows integrated authentication (`-SqlCredential` only where that isn't possible).

One schema difference: EF declares a cascade delete from `Evidence` to `ChainOfCustodyEvents`. The ledger
table's foreign key has no cascade, because an append-only table can never delete. CaseBook never hard-deletes
evidence (it's soft-deleted), so nothing changes in practice.

### 7.2 Digests: schedule them, store them where the DBA can't

A digest is a hash over every ledger transaction so far. It's only proof if it lives outside the database
administrator's reach: an immutable (WORM / object-lock) share, or a server owned by security rather than the
DBAs. Set `LedgerDigestPath` in the answers file, then schedule a daily export:

```powershell
schtasks /Create /TN "CaseBook ledger digest" /SC DAILY /ST 02:00 /RU "CONTOSO\svc-casebook-ops" /RP `
  /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\CaseBook\deploy\Export-LedgerDigest.ps1 -ConfigFile C:\CaseBook\deploy\casebook.config.psd1"
```

The account needs `GENERATE LEDGER DIGEST` on the database (`db_owner` has it) and write access to the share.
The script exits 1 on failure so the scheduler can alert. Also take a digest before and after anything
notable (an upgrade, a restore, an examination).

### 7.3 Verify

```powershell
.\Verify-LedgerDigests.ps1 -ConfigFile .\casebook.config.psd1       # all saved digests
.\Verify-LedgerDigests.ps1 -ConfigFile .\casebook.config.psd1 -Latest 30
```

SQL Server recomputes every ledger row and transaction hash and checks them against the digests. **OK** means no
ledger row changed since the digests were taken. **FAIL** (exit 1) names the table and transaction: treat it as
a possible tampering incident, preserve the database, backups and digests, and compare against the app's own
chain check and seals (§2). **Couldn't verify** (exit 2) means the check didn't finish (SQL Server unreachable,
sign-in or permission refused, a timeout): it isn't a tamper finding; fix the cause and run it again. Run it monthly, before an examination, and whenever the in-app chain check fails,
and keep the output with your NYDFS Part 500 evidence.

### 7.4 Upgrades and schema changes

SQL Server allows only some schema changes on a ledger table. Tested on SQL Server 2022:

| Change | Allowed |
|---|---|
| Add a **nullable** column with no default | Yes |
| Add a `NOT NULL` column (with a default) | **No** |
| Widen a column, make it `NOT NULL`, rename or drop a column | Yes |
| Create / drop an index, rename the table | Yes |

CaseBook's build enforces the rule: `LedgerScriptModelTests` fails if a column is added to one of these tables
that isn't nullable, or if the model and `02-Enable-Ledger.sql` disagree. So a release can't ship a migration
that breaks on ledger-enabled sites. Use the `02-Enable-Ledger.sql` shipped with your release; its column guard
refuses to run against a table shape it doesn't expect.

A dropped ledger table isn't deleted: SQL Server keeps it, renamed `MSSQL_DroppedLedgerTable_...`. Nothing in
CaseBook drops these tables.

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

Find and the case-list search match words. Without help, SQL Server does that by reading every row of every text
column (`LIKE '%word%'`), on every keystroke in the command bar, which slows as the record grows. With SQL Server's
**Full-Text Search** feature, CaseBook keeps full-text indexes on the free-text columns and matches words from them.
It's **optional**: without the feature, search works as before, by substring.

| | With Full-Text Search | Without |
|---|---|---|
| How a word matches | Words that **start with** it (`lsa` finds "LSASS", not "salsa") | **Anywhere** in the text |
| Columns | Case title and summary; brief summary, working assessment, known and open questions; record entry text and *why*; working notes; task titles, descriptions and comments; evidence descriptions | All of them |
| Words joined by `_` or `-` (`svc_backup`, `e-mail`) | One word: found by `svc_backup`, `svc`, `e-mail`; **not** by `backup` or `mail` | Found by any part |
| Indicators, case numbers, entities, evidence file names, phase reasons, the review | Anywhere in the text (substring), as without | Anywhere |
| A save | Searchable within seconds (change tracking) | At once |

**The trade-off, precisely (CAP-22 review).** SQL Server's English word breaker splits text at spaces and most
punctuation, but keeps a word joined by `_` or `-` whole: `svc_backup`, `lsass_dump` and `e-mail` are each one entry
in the index, and a search word matches entries that **start with** it. So by word, `svc` and `svc_backup` find
"svc_backup" but `backup` doesn't, and `e-mail` finds "e-mail" but `mail` doesn't. Evidence file names, which are
nearly always joined words, aren't indexed at all and stay a substring match (`dump` finds `lsass_dump.dmp`); the
Evidence table is small. For the other free text, a site whose analysts need the part after the join found can set
**Administration › Settings › Search › How search matches words** (`Search:Mode`) to *Anywhere in the text*
(`Substring`): every search then reads every row of every searched column, as without the feature (on the measured
500-case database, about 340 ms a Find keystroke and 2 s a case-list search instead of 215 ms and 277 ms;
[performance.md](reference/performance.md)), and the indexes stay in place, kept up to date, for switching back.
`Auto` (the default) uses the indexes; the value is read by name, takes effect at the next search, and anything else
means `Auto`. Merging a substring pass into a full-text one when it finds little was considered and not done: it
would bring the scan back for the rare words analysts search for most, and still miss the joined words whenever the
full-text pass found a few results.

**Setting it up.** Install the feature (SQL Server setup, *Full-Text and Semantic Extractions for Search*) before the
app's first start, and CaseBook's migration (`FullTextSearch`) creates the catalog `CaseBookText` and its indexes:
English word breaker, no stoplist (so no word is ignored as a noise word), automatic change tracking, and each table's
primary key as the full-text key. On a server without the feature the migration does nothing and completes.

Added the feature later? In **Administration › Diagnostics**, the *Search* row offers **Create full-text indexes**
(`Administer`, recorded in the audit trail as `FullTextSearch`). It creates whatever is missing and changes nothing
else. It needs the app's database account to be allowed to (`db_owner`, as `AppMigrates` grants). With `DbaApplies`,
the DBA runs the same statements from `deploy\sql\03-Enable-FullText.sql` (idempotent, not in a transaction):

```powershell
sqlcmd -S SQLHOST\INSTANCE -E -b -C -I -d CaseBook -i deploy\sql\03-Enable-FullText.sql
```

SQL Server fills new indexes in the background; until they're filled, search stays substring. `Verify-Install.ps1`
reports whether the instance has the feature, as information.

**Watching it.** Diagnostics' *Search* row shows the mode:

- *Search: full-text (SQL Server)*
- *Search: full-text on some columns, substring on the rest* (it names them)
- *Search: substring (full-text indexes still being filled)*
- *Search: substring (full-text installed, CaseBook's indexes not created)*
- *Search: substring (full-text not installed)*
- *Search: substring (full-text couldn't be checked)*
- *Search: substring (full-text turned off by the Search mode setting)*, with the indexes' own state beside it

A column with no full-text index is named, and *Create full-text indexes* offered, whatever the mode (one still
being filled while another was never made read only as *still being filled* before).

It's checked at startup (and logged), every 5 minutes (30 seconds while filling), when Diagnostics opens, and on
*Check again*. A full-text query the server refuses (an index dropped since the check, an input the word breaker can't
read) runs again by substring, so the person searching still gets their answer. The first of each kind is logged as a
warning ("A full-text search (Find) failed with SQL Server error …"), later ones at Debug. The row counts them, and the
status is checked again at the next search.

**Schema changes.** SQL Server refuses to alter or drop a column that's in a full-text index. A future migration that
changes one of the columns above has to take it out of the index first (`ALTER FULLTEXT INDEX … DROP (…)`) and put it
back after. `FullTextSchema` in `Infrastructure/Persistence` lists them.

**Taking it out.** Drop the indexes (`DROP FULLTEXT INDEX ON …`), then the catalog (`DROP FULLTEXT CATALOG
[CaseBookText]`). CaseBook returns to substring search at its next check; nothing else depends on them.
