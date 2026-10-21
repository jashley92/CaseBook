# CaseBook API

CaseBook is primarily a **system of record with a human-gated workflow**, not an automation platform, so
its API surface is deliberately small:

- one inbound integration, the **case-import API**, with a status check for what became of a submission and a public
  schema endpoint;
- one outbound read, the **malicious-IOC feed**, as CSV or STIX 2.1, for a firewall, an EDR or a threat-intel platform
  to pull.

Everything an API submits lands as a **draft a human confirms**; the API never writes case state directly. There's no
general read API ([decision 0001](decisions/0001-blazor-server-on-prem.md)).

## Authentication

The API authenticates with an **API token** presented as a bearer header:

```
Authorization: Bearer <token>
```

Tokens are minted **in-app**, never by the API itself:

- **System token** (for a machine producer — an XSIAM/SOAR playbook, a script — or a feed consumer): *Administration →
  API tokens → New system token*. Give it a name and grant it the roles it needs (the import API requires a role that
  grants **EditCases**; the IOC feed one that grants **ViewCases**). In the audit trail and the access log its actions
  are attributed to `apitoken:<name-as-slug>` (shown with the token's name). Maximum lifetime 365 days.
- **Personal token** (for a user calling the API as themselves): the account menu → *API tokens*. Its
  permissions are a subset of your own, re-checked against the roles you still hold on every call (in Active
  Directory, with Windows sign-in: a disabled account's tokens stop working); actions attribute to you. Maximum
  lifetime 90 days.

Tokens look like `cbk_` followed by 43 characters. They are shown **once** at creation (CaseBook stores only a
SHA-256 hash), carry a **required expiry**, and can be **revoked** anytime by their creator or an administrator.
A rejected token is reported to the SIEM stream (event 5101, with only the token's first 12 characters). On-prem/IIS deployments carve the `/api` path out as anonymous at the web server so the
token scheme applies there while the rest of the site stays Windows-authenticated (the installer does this, for
`<site>/api` and everything below it, so `/api/export/…` is covered too);
always call the API over **HTTPS**.

A token **sees cases as its owner does** (need-to-know): a system token holds what its roles grant, and a personal
token what you grant it of your own roles. Every endpoint under `/api` except the public schema (`GET /api/import/cases/schema`) signs in with a token only; a browser's Windows
sign-in doesn't count there. A refused call is a plain `401` or `403`, never a redirect to a page.

## Endpoints

### `POST /api/import/cases`

Submit a structured case-import document. **Auth:** bearer token with **EditCases**. **Body:** a
`casebook-case-import` JSON document (see the schema below).

The submission is **staged for review** — it is not written to a case until a person opens the
*Import → Pending imports* queue in CaseBook and confirms it (or rejects it). A submission into an existing
restricted case appears only to reviewers who can see that case. Reviewers are told it's there: a *Waiting for
review* item on their Desk, a count beside *Import*, and, when an administrator turns them on, an email, a team chat
post (without the summary for a restricted case) and a digest line (CAP-01). Telling them never changes the response
or fails the submission. Nothing is retried on the server. Resending
the identical document with the same token while the first is still waiting (within 24 hours) returns that one
(`200`, `duplicate: true`) rather than queueing it twice, so a client can retry safely after a timeout; a
changed document is a new submission.

**Responses**

| Status | Meaning |
|---|---|
| `201 Created` | Accepted for review. Body: `{ pendingImportId, status: "pending", duplicate: false, message, itemCount, warnings[] }`. `Location` points at the review URL. |
| `200 OK` | The identical document from the same token is already waiting for review (sent within 24 hours), so a retry isn't queued twice. Same body, `duplicate: true`, with that import's id. |
| `400 Bad Request` | The document isn't valid / not a `casebook-case-import` / a newer schema version than the server supports / carries more than one import takes (2,000 indicators, 1,000 timeline entries, 500 tasks; split it) / gives a `target.caseId` and a `target.detectionCaseId` that name different cases / (v2) has a `newCase.history` that breaks the time checks: a step out of order, in the future, before `detectedAt` (or no `detectedAt`), a `containedAt` or `resolvedAt` the phase change would refuse (in the future, before detection, after its step, resolved before contained, or missing where a later Containment took the resolution back), a close before the last step or without its `outcome` and `conclusion` (CAP-35). Body: `{ error }`. |
| `401 Unauthorized` | Missing, invalid, expired, or revoked token. |
| `403 Forbidden` | The token authenticated but lacks the **EditCases** permission. |
| `413 Payload Too Large` | The body is over 5 MiB (with or without a `Content-Length`). |
| `429 Too Many Requests` | Per-caller rate limit exceeded (default 40 requests burst, 40 per minute; `Retry-After` is set). |
| `500 Internal Server Error` | An unexpected server error. Body: `{ error, ref }`; quote the `ref` value when reporting it. |

**Example**

```bash
curl -X POST https://your-casebook/api/import/cases \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  --data @case.json
```

### `GET /api/import/cases/{pendingImportId}`

What became of a submission (CAP-13). **Auth:** bearer token: the token that sent it, or one with **EditCases** for a
submission it could review in the queue (not one into a restricted case it can't see). Rate-limited with the import
API (the same per-caller budget).

**Body:** `{ status, decidedAtUtc, resolvedCaseNumber, resolvedCaseId }`

| `status` | Meaning |
|---|---|
| `pending` | Waiting for review, or a reviewer is applying it right now. The other fields are `null`. |
| `applied` | Confirmed into a case at `decidedAtUtc`. `resolvedCaseNumber` and `resolvedCaseId` name that case **as it is now** (a Complex Event promoted since has its new number), and only when the token can see the case; otherwise they're `null`. |
| `rejected` | A reviewer rejected it at `decidedAtUtc`. Nothing was written to any case. |

**Responses:** `200 OK` with the body; `401 Unauthorized` (missing, invalid, expired or revoked token); `404 Not Found`
for an id that doesn't exist **or** that this token may not see (the two can't be told apart); `429`.

```bash
curl https://your-casebook/api/import/cases/7f0c2a52-1b7e-4a43-9d11-6c1a2f0b9e31 -H "Authorization: Bearer <token>"
```

```json
{ "status": "applied", "decidedAtUtc": "2026-10-18T14:02:11.483+00:00",
  "resolvedCaseNumber": "2026-42_Impossible_Travel", "resolvedCaseId": "0b9d4c61-5e7a-4f0e-8a51-2d6f3c9e7a14" }
```

A producer that polls should do so sparingly (a review is a person's work, often hours away) and stop at `applied` or
`rejected`.

### `GET /api/import/cases/schema`

Returns the **JSON Schema** (draft 2020-12) for the import document. **No authentication** — it's a public
contract, carries no data, and is generated from the server's own model so it never drifts from what the
importer accepts. `Content-Type: application/json`.

A committed copy also lives at [`case-import.schema.json`](case-import.schema.json).

### `GET /api/export/iocs.csv` and `GET /api/export/iocs.stix.json`

The **malicious-IOC feed** (CAP-09): every indicator a person has marked **Malicious** of an IOC type (IP address,
domain, URL, file hash), across the cases the token can see, one row (or object) per indicator. It's the feed the
*Export → Malicious IOCs* download gives a signed-in user, for a machine to pull on a schedule. **Auth:** bearer token
with **ViewCases**.

- **What's in it:** the token's need-to-know decides. A restricted case's indicators appear only when the token's
  owner could open that case (`ViewAllCases` or `ViewRestricted`, or on the case's team). **A feed token shouldn't hold
  either permission**: give it a role with `ViewCases` alone, so restricted matters stay out of firewalls and partner
  TIPs. Exercise cases never appear.
- **Markings:** each indicator carries its TLP marking: the strictest any of its occurrences has, and the organization's
  default (*Administration → Reporting*, AMBER unless changed) where none is set. The feed includes every marking,
  TLP:RED too; the consumer decides what it may share onward.
- **CSV** (`text/csv; charset=utf-8`, no byte-order mark): `#` comment lines, then the header
  `type,indicator,disposition,first_seen_utc,last_seen_utc,case_count,cases,sources,tlp`. `type` is `ip`, `domain`, `url`
  or `filehash`; `tlp` is `TLP:CLEAR` … `TLP:RED`.
- **STIX** (`application/json`): a STIX 2.1 bundle: the organization's `identity`, a `report` tying it together, the TLP
  2.0 `marking-definition`s it uses, and one cyber-observable per indicator (`ipv4-addr`, `domain-name`, `url`, `file` …)
  with `object_marking_refs` and `x_casebook_cases`, `x_casebook_sources`, `x_casebook_first_seen`,
  `x_casebook_last_seen`. An indicator's id is derived from its type and value, so it's the same object in every pull
  and a TIP updates it rather than adding another.

**Keeping scheduled pulls cheap.** Both are supported:

- **`If-None-Match`**: each response has a weak `ETag` (`W/"csv-…"`, `W/"stix-…"`). Send it back and an unchanged feed
  answers `304 Not Modified` with no body. It changes when anything in the feed does (an indicator added, removed or
  re-marked, a case number, a source), whatever caused it. `If-Modified-Since` isn't honored: an indicator leaving the
  feed (removed, cleared, its case restricted) leaves no newer time behind, so a date can't say nothing changed.
- **`?since=<ISO 8601>`**: only indicators with an occurrence added or changed (a verdict, a marking, an edit) at or
  after that time, for example `?since=2026-10-18T00:00:00Z` (a time without an offset is UTC; write a `+` offset as
  `%2B`). A delta can't list what **left** the feed, so take a full pull (no `since`) now and then to drop those. The
  CSV says the delta's start in a comment line, the STIX report in `x_casebook_since`. `since` picks **which**
  indicators are in the delta, never what a row says: each one is aggregated over all its occurrences, as in a full
  pull, so an indicator marked TLP:RED on an old case and TLP:GREEN on a case changed since comes back TLP:RED, with
  both cases and the old first-seen. The ETag also covers the default TLP (`Reporting:DefaultTlp`) for STIX, so
  changing the default isn't answered `304`.

**Bounds.** A feed reads at most **100,000** indicator occurrences, cut by whole indicators: the most recently changed
indicators first (by their latest change), each with all its occurrences, as many as fit. An indicator is never cut
part-way, so a cut can't loosen its marking or drop one of its cases. Past the bound the feed says it was cut: the
`X-CaseBook-Truncated: true` header, a `# Cut: …` line at the top and the end of the CSV, and
`x_casebook_truncated: true` with a sentence in the STIX report's description. A blocklist that size needs curating in
CaseBook.

**Rate limit.** Per token (by the token itself, not its owner, so two personal tokens of one user each have their own
budget), separately from the other endpoints: a burst of 20 pulls, then one a minute
(`RateLimiting:ApiFeeds`, see [configuration](operations/configuration.md)). Both formats share it. A pull every
few minutes in both formats stays well inside it.

**Recorded.** Each pull with a body is an export: an access-log entry (*Export*, actor `apitoken:<name>`, labelled
"IOC feed (CSV, API)" or "IOC feed (STIX, API)", with the delta's start and ", cut" when they apply) and SIEM event
5304. A `304` sends nothing, so records nothing.

| Status | Meaning |
|---|---|
| `200 OK` | The feed. |
| `304 Not Modified` | `If-None-Match` named the current feed. No body. |
| `400 Bad Request` | `since` isn't an ISO 8601 time. Body: `{ error }`. |
| `401 Unauthorized` | Missing, invalid, expired or revoked token. |
| `403 Forbidden` | The token authenticated but lacks **ViewCases**. |
| `429 Too Many Requests` | The token's feed budget is spent (`Retry-After` is set). |

```bash
# First pull: keep the ETag.
curl -sS -D headers.txt -o iocs.csv https://your-casebook/api/export/iocs.csv -H "Authorization: Bearer <token>"
# Later pulls: 304 when nothing changed.
curl -sS -o iocs.csv -w "%{http_code}\n" https://your-casebook/api/export/iocs.csv \
  -H "Authorization: Bearer <token>" -H 'If-None-Match: W/"csv-3f9a1c0e5b7d42a8e61f0c9d2b4a7e15"'
# What's new since the last pull, as STIX.
curl -sS "https://your-casebook/api/export/iocs.stix.json?since=2026-10-18T00:00:00Z" -H "Authorization: Bearer <token>"
```

```text
# CaseBook malicious-IOC feed: confirmed indicators across your visible cases, generated 2026-10-18 14:05:00 UTC
type,indicator,disposition,first_seen_utc,last_seen_utc,case_count,cases,sources,tlp
domain,evil.example,malicious,2026-10-02 09:14:00,2026-10-11 16:40:12,2,2026-31_Phishing_Wave; 2026-42_Impossible_Travel,SIEM; VirusTotal,TLP:AMBER
ip,203.0.113.66,malicious,2026-10-11 16:40:12,2026-10-11 16:40:12,1,2026-42_Impossible_Travel,XSIAM,TLP:RED
```

## The import document

Minimal example:

```json
{
  "format": "casebook-case-import",
  "schemaVersion": 1,
  "origin": "AI-assisted (Copilot)",
  "target": { "newCase": { "title": "Phishing wave — Finance", "classification": "Incident", "severity": "High" } },
  "summary": "Assembled from the reporting email thread.",
  "timeline": [
    { "occurredAt": "2026-09-19T13:05:00Z", "kind": "Investigation", "type": "Communication",
      "description": "User reported a suspicious email to the SOC." }
  ],
  "entities": [
    { "value": "hxxp://evil[.]example[.]com/login" },
    { "type": "EmailAddress", "value": "attacker@evil.example.com", "disposition": "Malicious" }
  ],
  "actionItems": [ { "title": "Reset credentials for affected users", "owner": "soc-analyst" } ]
}
```

Notes:
- Set `target.newCase` to open a new case, or `target.caseId` to add to an existing one. A new case with no
  `classification` files as a **Complex Event** (intake) for a person to classify; `newCase.detectionCaseId`
  carries the source platform's id (for example the XSIAM incident id) as the case's back-link. `newCase.exercise: true`
  makes it a **tabletop / exercise case** (a drill: badged, kept out of dashboards, reminders, the IOC feed and
  correlation with live cases; fixed once created).
- **Two "origin" fields.** The top-level `origin` is where the *import* came from (`"XSIAM"`, `"manual"`): it becomes
  the source of each imported item. **`newCase.origin`** is who found the *case*: `InternalDetection` (our monitoring
  or staff) or `ThirdParty` (a vendor told us), with `newCase.vendorName`. Left out, the case is third-party when
  `vendorName` is given and internal detection when it isn't; the reviewer's preview says which, and can change it. A
  top-level `origin` that reads like a case origin (`"ThirdParty"`) with none in `newCase` gets a warning. A case
  imported as the wrong origin can be corrected afterwards on its Briefing tab (*Origin* → *Change to …*, with a reason).
- **Attack steps on a third-party case.** A third-party case's event steps (`kind: "Event"`) are of two kinds: the
  vendor's **disclosure milestones** (what the vendor told us and what we confirmed: `type` `Notified`,
  `ScopeConfirmed`, `DataConfirmed`, `Remediation`, `RegulatoryNotification`), and the attacker's **attack steps**. An
  event step with any of `tactics` (ATT&CK names, such as `InitialAccess`), `techniqueId` (`T1566.001`) or
  `environment` (`Vendor`, or `Ours` when the attacker reached our environment) is an attack step; one with none is a
  disclosure milestone. On an internal case every event step is an attack step in our environment, and `environment`
  is ignored.

  ```json
  "timeline": [
    { "occurredAt": "2026-09-02T00:00:00Z", "timePrecision": "Day", "kind": "Event", "environment": "Vendor",
      "tactics": ["InitialAccess"], "techniqueId": "T1190", "description": "Attacker exploited the vendor's file transfer server." },
    { "occurredAt": "2026-09-10T14:00:00Z", "kind": "Event", "type": "Notified",
      "description": "Vendor emailed us that our files were in the exposed set." }
  ]
  ```
- **`target.detectionCaseId`** (CAP-14, optional, up to 100 characters) adds to an existing case by the detection
  platform's incident id rather than a CaseBook GUID: the one **open** case carrying that detection case id (compared
  without regard to letter case), found among the cases the **reviewer** can see when it's reviewed, not the cases
  your token sees. With no such case, `target.newCase` is prepared (send both, and the reviewer gets a new case when the
  incident has none yet); with several, the reviewer picks. Closed and archived cases don't count. The response's
  `warnings` say the target is decided at review.

  ```json
  "target": { "detectionCaseId": "4812", "newCase": { "title": "Impossible travel for jdoe", "detectionCaseId": "4812" } }
  ```

  With `target.caseId` as well, both must name the same case: when the case with that id (one your token can see)
  carries a different detection case id, or none, the document is refused with `400`. When they agree, `caseId` is the
  target.
- **Versions** (CAP-35): `schemaVersion` is `1` or `2`; a higher one is refused with `400`. A v1 document is read exactly
  as before. **v2** lets a new case carry how it went, for a historical or closed case: `newCase.history` (phase
  transitions, oldest first), `newCase.outcome` and `newCase.conclusion` (when the history ends in Closed),
  `newCase.incidentCommander` and `newCase.assignments` (users by id or UPN). In a v1 document these are ignored, with a
  warning. The history is checked by the phase change's own rules before queueing. A closing step's `reason` is what the
  close records (without one, the `conclusion`); when the close gate asks for a reason of a minimum length, the reviewer's
  preview refuses a shorter one. A name two users share as a UPN isn't added (a warning). A history that closes the case
  is confirmed on its own, never by *Confirm all from this submitter*, and its team isn't emailed "assigned" (CAP-35
  review).

  ```json
  "schemaVersion": 2,
  "target": { "newCase": {
    "title": "Wire fraud attempt", "classification": "Incident", "detectedAt": "2026-03-02T10:00:00Z",
    "history": [
      { "phase": "Containment", "at": "2026-03-02T15:00:00Z", "reason": "Mailbox rule removed" },
      { "phase": "Closed", "at": "2026-03-09T12:00:00Z" }
    ],
    "outcome": "Confirmed", "conclusion": "Stopped before any payment left.",
    "incidentCommander": "dana.lee@contoso.example",
    "assignments": [ { "user": "analyst9", "role": "Analyst" } ] } }
  ```

  The history needs `detectedAt`; no step may be in the future, before it, or before the step before it, and only the
  last step may close the case; a step past Containment or Recovery without it says `containedAt` /
  `containmentNotNeeded` or `resolvedAt`. A step that moves on from Containment may say `containedAt` (from v1.15.0
  entering Containment no longer sets the contained time); left out, it's the Containment step's time, as before. Such a document is refused with `400`. Each step is applied at its time when
  a reviewer confirms it (a missing reason reads "imported record: &lt;origin&gt;", and a close whose gate checks can't be
  met is overridden with that reason). People the reviewer's directory doesn't know are a warning and aren't added. A
  history only applies to a new case: one that lands in an existing case leaves it out, with a warning.
- **Team** (CAP-36, v2, no version change): `newCase.team` names the team that owns the new case, by its key (as the
  Cases list's team filter shows it, `SocTier1`) or its name, ignoring case, up to 100 characters. It's matched when a
  reviewer reviews the import (the reviewer can change it): one that isn't an active team is a warning and the case is
  opened without a team; in a v1 document it's ignored, with a warning; an import into an existing case leaves that
  case's team as it is. A team never changes who can see the case. An import waiting for review is posted to the
  target's team's chat channel when it has one.

  ```json
  "schemaVersion": 2,
  "target": { "newCase": { "title": "Beacon from a laptop", "team": "SocTier1" } }
  ```
- **Times**: ISO 8601. A time with an offset (`2026-09-18T09:05:00-04:00`) or `Z` is kept as stated. A time without one
  is read in the document's top-level `timeZone` (an IANA id such as `America/New_York`), or as UTC when it has none.
  (On the Import page the reviewer picks the zone for such times instead, the organization's by default; a document's
  own `timeZone` still wins.)
- Indicators may be **defanged** (`hxxp://`, `1.1.1[.]1`) — CaseBook refangs and auto-types them; the entity
  `type` is optional.
- `origin` is recorded as the provenance (source) of imported indicators and timeline entries.
- A timeline entry of `type` **`Decision`** records something the team decided: the decision in `description`,
  why in `rationale` (required for a decision), and optionally `optionsConsidered` and `decidedBy`. A decision
  without a `rationale` is imported as `Communication`, flagged in the preview so the reviewer can add the why.
  `Handoff` isn't an importable type (a handoff is made in CaseBook, to a person).
- An **`Event`** entry can give its time as it was stated, instead of a guessed one: `timePrecision` `Day` (the date
  in `occurredAt`), `Window` (from `occurredAt` to `occurredUntil`), `OnOrBefore`, or `NotStated` (no time:
  it's placed right after the event entry before it in the document, or first). Omitted means `Exact`. A date-based
  precision without a date imports as `NotStated`, and a window without a later end as `Day`, each flagged in the
  preview. List event entries in the order the source gives them.
- Enum fields (classification, severity, kind, type, disposition, …) and their allowed values are defined in
  the schema; unknown values fall back to a safe default and are flagged in the review preview.

**What happens on review** is described in [workflows/case-lifecycle.md](workflows/case-lifecycle.md#2-importing-a-case)
(the preview's rules for untrusted input, provenance, and how imported entries are marked).

**XSIAM hand-off.** A ready-to-adapt XSIAM automation script and set-up guide for elevating an incident into
CaseBook live in [`integrations/xsiam/`](../integrations/xsiam/README.md).

To have an AI produce a valid document from raw material (emails, chat logs, notes), use the
**"Generate a prompt for your AI"** step on the *Import* page — it emits a prompt embedding this exact schema.
