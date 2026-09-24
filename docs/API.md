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
  grants **EditCases**). Actions attribute to the token's name in the audit trail.
- **Personal token** (for a user calling the API as themselves): the account menu → *API tokens*. Its
  permissions are a subset of your own; actions attribute to you.

Tokens are shown **once** at creation (CaseBook stores only a hash), carry a **required expiry**, and can be
**revoked** anytime. On-prem/IIS deployments carve the `/api` path out as anonymous at the web server so the
token scheme applies there while the rest of the site stays Windows-authenticated (the installer does this);
always call the API over **HTTPS**.

## Endpoints

### `POST /api/import/cases`

Submit a structured case-import document. **Auth:** bearer token with **EditCases**. **Body:** a
`casebook-case-import` JSON document (see the schema below).

The submission is **staged for review** — it is not written to a case until a person opens the
*Import → Pending imports* queue in CaseBook and confirms it.

**Responses**

| Status | Meaning |
|---|---|
| `201 Created` | Accepted for review. Body: `{ pendingImportId, status: "pending", message, itemCount, warnings[] }`. `Location` points at the review URL. |
| `400 Bad Request` | The document isn't valid / not a `casebook-case-import` / a newer schema version than the server supports. Body: `{ error }`. |
| `401 Unauthorized` | Missing, invalid, expired, or revoked token. |
| `403 Forbidden` | The token authenticated but lacks the **EditCases** permission. |
| `429 Too Many Requests` | Per-caller rate limit exceeded. |

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
    { "occurredAtUtc": "2026-09-19T13:05:00Z", "kind": "Investigation", "type": "Communication",
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
  carries the source platform's id (for example the XSIAM incident id) as the case's back-link.
- Indicators may be **defanged** (`hxxp://`, `1.1.1[.]1`) — CaseBook refangs and auto-types them; the entity
  `type` is optional.
- `origin` is recorded as the provenance (source) of imported indicators and timeline entries.
- Enum fields (classification, severity, kind, type, disposition, …) and their allowed values are defined in
  the schema; unknown values fall back to a safe default and are flagged in the review preview.

**XSIAM hand-off.** A ready-to-adapt XSIAM automation script and set-up guide for elevating an incident into
CaseBook live in [`integrations/xsiam/`](../integrations/xsiam/README.md).

To have an AI produce a valid document from raw material (emails, chat logs, notes), use the
**"Generate a prompt for your AI"** step on the *Import* page — it emits a prompt embedding this exact schema.
