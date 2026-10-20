# SIEM security-event stream

Section 5 of the [operations guide](../OPERATIONS.md), which keeps the deploy-time checklist and the host controls. Section numbers are kept, so "OPERATIONS.md section 5" in the app and the scripts means this page.

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
| 5007 | Integrity | Evidence key changed. Action: `KeyCreated`, `KeyAvailable` (back after 5006), `KeyProtectionChanged` (renewed certificate, recovery certificates changed), `SharesIssued`, `RecoveryDrill`, `CustodianRetired`, or **`KeyRecovered`** (moved onto another certificate; High). Target id is the key id |
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
