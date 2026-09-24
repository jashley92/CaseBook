# Elevating an XSIAM incident into CaseBook (PROD-05)

When an analyst decides an XSIAM incident needs a CaseBook case, they run a playbook that hands the incident
over as a **draft**. CaseBook never pulls from XSIAM and never opens a case on its own: the hand-off lands in
**Import → Pending imports**, where a person reviews it (edit, drop items, check the "already seen on open
cases" suggestions) and confirms it. That keeps the elevation decision and the case opening with people.

> **This is a template.** It has not been run against your tenant. Review it, adjust the field and type
> mappings to your incident layout, and test it on a non-production incident first.

## What gets sent

| XSIAM | CaseBook |
|---|---|
| Incident name | Case title |
| Severity (Low … Critical) | Severity |
| Created time | Detected time |
| Occurred time | Activity-began time (dwell) |
| Details | Case summary |
| Incident id | Detection case id (the back-link from the case to XSIAM) |
| Indicators on the incident (value, type, DBot score) | Entities with CaseBook type and verdict (Malicious / Suspicious / Benign / Unknown) |
| — | A timeline entry: "Elevated from XSIAM incident N by *analyst*" |

The case files as a **Complex Event**; the analyst classifies it in CaseBook. The provenance of every imported
indicator and timeline entry reads "XSIAM incident N".

## Set up

1. **CaseBook:** *Administration → API tokens → New system token*. Name it (for example "XSIAM elevation"),
   give it a role that grants **EditCases**, and set an expiry. Copy the token (it's shown once).
2. **XSIAM credentials store:** save the token as a credential (for example `casebook-api`). Don't paste it
   into the playbook.
3. **Automation:** create a script from [`CaseBookElevate.py`](CaseBookElevate.py) (Python 3, docker image with
   `requests`). Arguments: `casebook_url`, `api_token`, optional `max_indicators` and `verify_tls`.
4. **Playbook:** add a manual, analyst-run playbook (for example "Elevate to CaseBook") with one task calling
   `CaseBookElevate`, passing `casebook_url` and `api_token` from the credential. Run it from the incident
   when you decide to elevate. The task's output includes the review link.
5. **Network:** XSIAM (or its engine) needs HTTPS access to CaseBook's `/api` path. On IIS, the installer
   carves `/api` out for token auth while the rest of the site stays on Windows authentication.

## Adding to an existing case

To enrich a case that's already open instead of opening a new one, change `target` in `build_document` to
`{"caseId": "<CaseBook case GUID>"}`. The same review step applies.

## Reference

- API and authentication: [docs/API.md](../../docs/API.md)
- Import document schema: `GET /api/import/cases/schema`, or [docs/case-import.schema.json](../../docs/case-import.schema.json)
