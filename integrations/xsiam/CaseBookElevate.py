"""CaseBookElevate — XSIAM / XSOAR automation script (PROD-05). TEMPLATE: review and test in your tenant.

Sends the current incident to CaseBook as a *pending import*: a draft case a person reviews and confirms in
CaseBook (Import → Pending imports). It never creates or changes a case by itself, and it runs only when an
analyst runs the playbook that calls it, i.e. at the moment they decide to elevate the event.

What it sends (a `casebook-case-import` document, schema: GET <casebook>/api/import/cases/schema):
  - a new case: the incident name as the title, the XSIAM severity, occurred / created times, the incident's
    details as the summary, and the XSIAM incident id as the case's detection-case id (the back-link);
    classification is left out, so the case files as a Complex Event and the analyst classifies it in CaseBook
  - the incident's indicators (value, CaseBook type, verdict from the XSIAM score)
  - one timeline entry recording the hand-off, and who elevated it

Arguments (set them in the playbook task; keep the token in the XSIAM credentials store, not in the playbook):
  casebook_url   Base URL, e.g. https://casebook.corp.example (HTTPS only)
  api_token      A CaseBook *system* API token with a role granting EditCases (Administration → API tokens)
  max_indicators Optional cap on indicators sent (default 500)
  verify_tls     Optional, default true. Leave on.

Outputs: CaseBook.Elevation.PendingImportId, CaseBook.Elevation.ReviewUrl, CaseBook.Elevation.Warnings
"""
import demistomock as demisto  # noqa: F401  (provided by the XSIAM / XSOAR runtime)
from CommonServerPython import *  # noqa: F401,F403

import requests

# XSIAM incident severity → CaseBook severity.
SEVERITY = {0: "Informational", 0.5: "Informational", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# XSIAM indicator type → CaseBook entity type. Anything else is sent without a type and CaseBook auto-detects it.
INDICATOR_TYPE = {
    "ip": "IpAddress", "ipv6": "IpAddress", "domain": "Domain", "url": "Url", "email": "EmailAddress",
    "file": "FileHash", "file sha-256": "FileHash", "file sha256": "FileHash", "file sha-1": "FileHash",
    "file md5": "FileHash", "account": "Account", "host": "Host", "hostname": "Host",
    "registry key": "RegistryKey", "process": "Process",
}

# XSIAM indicator score (DBot score) → CaseBook disposition.
VERDICT = {3: "Malicious", 2: "Suspicious", 1: "Benign", 0: "Unknown"}


def iso(value):
    """XSIAM timestamps are ISO-8601 strings; pass them through, dropping empty / zero-date values."""
    if not value or str(value).startswith("0001-"):
        return None
    return str(value)


def incident_indicators(incident_id, cap):
    res = demisto.executeCommand("findIndicators", {"query": f"investigationIDs:{incident_id}", "size": cap})
    if is_error(res):
        demisto.debug(f"findIndicators failed: {get_error(res)}")
        return []
    found = res[0].get("Contents") or []
    entities = []
    for ind in found[:cap]:
        value = ind.get("value")
        if not value:
            continue
        entity = {"value": value, "source": "XSIAM"}
        mapped = INDICATOR_TYPE.get(str(ind.get("indicator_type", "")).lower())
        if mapped:
            entity["type"] = mapped
        entity["disposition"] = VERDICT.get(ind.get("score", 0), "Unknown")
        entities.append(entity)
    return entities


def build_document(incident, entities, elevated_by):
    incident_id = str(incident.get("id", ""))
    name = incident.get("name") or f"XSIAM incident {incident_id}"
    details = (incident.get("details") or "").strip()
    new_case = {
        "title": name[:300],
        "severity": SEVERITY.get(incident.get("severity", 2), "Medium"),
        "origin": "InternalDetection",
        "detectionCaseId": incident_id[:100],
    }
    if details:
        new_case["summary"] = details[:8000]
    occurred = iso(incident.get("occurred"))
    created = iso(incident.get("created"))
    if created:
        new_case["detectedAtUtc"] = created
    if occurred:
        new_case["occurredAtUtc"] = occurred

    return {
        "format": "casebook-case-import",
        "schemaVersion": 1,
        "origin": f"XSIAM incident {incident_id}",
        "target": {"newCase": new_case},
        "timeline": [{
            "occurredAtUtc": created,
            "kind": "Investigation",
            "type": "Escalation",
            "description": f"Elevated from XSIAM incident {incident_id} by {elevated_by}.",
            "source": "XSIAM",
        }],
        "entities": entities,
    }


def main():
    args = demisto.args()
    base = (args.get("casebook_url") or "").rstrip("/")
    token = args.get("api_token") or ""
    cap = int(args.get("max_indicators") or 500)
    verify = argToBoolean(args.get("verify_tls", "true"))
    if not base.lower().startswith("https://"):
        return_error("casebook_url must be an https:// URL.")
    if not token:
        return_error("api_token is required (use a CaseBook system token from the XSIAM credentials store).")

    incident = demisto.incident()
    user = demisto.executeCommand("getUsers", {"current": True})
    elevated_by = "an analyst"
    if not is_error(user) and user[0].get("Contents"):
        elevated_by = user[0]["Contents"][0].get("name") or user[0]["Contents"][0].get("username") or elevated_by

    doc = build_document(incident, incident_indicators(incident.get("id"), cap), elevated_by)

    resp = requests.post(
        f"{base}/api/import/cases",
        json=doc,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        timeout=30,
        verify=verify,
    )
    if resp.status_code != 201:
        return_error(f"CaseBook refused the hand-off ({resp.status_code}): {resp.text[:500]}")

    body = resp.json()
    review_url = f"{base}/cases/import?pending={body.get('pendingImportId')}"
    outputs = {
        "PendingImportId": body.get("pendingImportId"),
        "ReviewUrl": review_url,
        "Warnings": body.get("warnings") or [],
    }
    readable = (f"Sent to CaseBook for review ({body.get('itemCount', 0)} item(s)). "
                f"A person confirms it at {review_url} before any case is written.")
    return_results(CommandResults(outputs_prefix="CaseBook.Elevation", outputs=outputs, readable_output=readable))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
