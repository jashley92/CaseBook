# CaseBook API

CaseBook is primarily a **system of record with a human-gated workflow**, not an automation platform, so
its API surface is deliberately small. Today it exposes one inbound integration — the **case-import API** —
plus a public schema endpoint. Everything an API submits lands as a **draft a human confirms**; the API never
writes case state directly.

## Authentication

The API authenticates with an **API token** presented as a bearer header:

```
Authorization: Bearer <token>
```

Tokens are minted **in-app**, never by the API itself:

- **System token** (for a machine producer — an XSIAM/SOAR playbook, a script): *Administration → API tokens →
  New system token*. Give it a name and grant it the roles it needs (the import API requires a role that
  grants **EditCases**). In the audit trail its actions are attributed to `apitoken:<name-as-slug>` (shown with
  the token's name). Maximum lifetime 365 days.
- **Personal token** (for a user calling the API as themselves): the account menu → *API tokens*. Its
  permissions are a subset of your own, re-checked against the roles you still hold on every call (in Active
  Directory, with Windows sign-in: a disabled account's tokens stop working); actions attribute to you. Maximum
  lifetime 90 days.

Tokens look like `cbk_` followed by 43 characters. They are shown **once** at creation (CaseBook stores only a
SHA-256 hash), carry a **required expiry**, and can be **revoked** anytime by their creator or an administrator.
A rejected token is reported to the SIEM stream (event 5101, with only the token's first 12 characters). On-prem/IIS deployments carve the `/api` path out as anonymous at the web server so the
token scheme applies there while the rest of the site stays Windows-authenticated (the installer does this);
always call the API over **HTTPS**.

## Endpoints

### `POST /api/import/cases`

Submit a structured case-import document. **Auth:** bearer token with **EditCases**. **Body:** a
`casebook-case-import` JSON document (see the schema below).

The submission is **staged for review** — it is not written to a case until a person opens the
*Import → Pending imports* queue in CaseBook and confirms it (or rejects it). A submission into an existing
restricted case appears only to reviewers who can see that case. Nothing is retried on the server. Resending
the identical document with the same token while the first is still waiting (within 24 hours) returns that one
(`200`, `duplicate: true`) rather than queueing it twice, so a client can retry safely after a timeout; a
changed document is a new submission.

**Responses**

| Status | Meaning |
|---|---|
| `201 Created` | Accepted for review. Body: `{ pendingImportId, status: "pending", duplicate: false, message, itemCount, warnings[] }`. `Location` points at the review URL. |
| `200 OK` | The identical document from the same token is already waiting for review (sent within 24 hours), so a retry isn't queued twice. Same body, `duplicate: true`, with that import's id. |
| `400 Bad Request` | The document isn't valid / not a `casebook-case-import` / a newer schema version than the server supports / carries more than one import takes (2,000 indicators, 1,000 timeline entries, 500 tasks; split it). Body: `{ error }`. |
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

### `GET /api/import/cases/schema`

Returns the **JSON Schema** (draft 2020-12) for the import document. **No authentication** — it's a public
contract, carries no data, and is generated from the server's own model so it never drifts from what the
importer accepts. `Content-Type: application/json`.

A committed copy also lives at [`case-import.schema.json`](case-import.schema.json).

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
  carries the source platform's id (for example the XSIAM incident id) as the case's back-link. A new case with
  `origin: "ThirdParty"` needs `newCase.vendorName` (the vendor that disclosed it). `newCase.exercise: true` makes it a
  **tabletop / exercise case** (a drill: badged, kept out of dashboards, reminders, the IOC feed and correlation with
  live cases; fixed once created).
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
