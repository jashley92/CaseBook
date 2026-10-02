# Glossary

| Term | Meaning |
|---|---|
| **Access log** | The record of who read a case or downloaded an artifact. Outside the audit chain; coalesced into view sessions; prunable. |
| **Action item** | The code name for a **task** (`ActionItem`, table `ActionItems`). |
| **Adverse Event** | The first rung of the classification ladder. |
| **Attack chain** | A case's event steps in order, drawn across ATT&CK tactic lanes. |
| **Attestation** | A stage-gate requirement that a person ticks at the moment of the transition. |
| **Audit chain / audit trail** | The `AuditLog` table: every change, each row hashing the previous one. |
| **Brief** | "Where it stands": the versioned summary, working assessment, known, open questions and next steps. |
| **Breach** | The top rung of the ladder. Escalating to it notifies Legal and runs the Breach gate. |
| **Campaign** | A connected group of cases linked "part of campaign". Not a stored record. |
| **Canonical content** | The ordered fields an entity's row hash is computed over. |
| **Case** | One escalated matter, the root of everything else. |
| **Chain of custody** | Per-evidence log of uploaded, viewed, downloaded and transferred. |
| **Circuit** | A Blazor Server connection: one per open browser tab, with its state on the server. |
| **Classification** | Position on the ladder: Complex Event (none), Adverse Event, Incident, Breach. |
| **Complex Event** | A case not yet classified. Numbered `CE-YYYY-MM-DD_Name`; promoted onto the ladder. |
| **Compromised** | An entity disposition: a legitimate asset taken over by an attacker. |
| **Data element** | A category of personal or non-public data (SSN, payment card…) recorded in a case's impact assessment, with notification jurisdictions. |
| **Decision** | A timeline entry type that records what was decided, why (required), options considered and who decided. |
| **Defang / refang** | Writing an indicator so it can't be clicked (`hxxp://evil[.]com`) / converting it back. CaseBook stores refanged values and defangs them in reports. |
| **Derived milestone** | A timeline item computed from a record (phase change, gate passage…), not stored. |
| **Detection case id** | The SIEM or detection platform's id for the alert or incident behind a case. |
| **Disclosure** | The event lens for third-party cases: what the vendor told you and when. |
| **Disposition** | An entity's verdict: Unknown, Benign, Suspicious, Malicious, Compromised. |
| **Effective time** | When a transition actually happened, as opposed to when it was recorded. |
| **Entity** | Anything an investigation refers to: account, host, IP, domain, URL, hash, file, email address, process, registry key. Includes IOCs. |
| **Event step** | A timeline entry describing what the adversary or vendor did. |
| **Exercise case** | A tabletop case, excluded from metrics, reminders, feeds and correlation. |
| **Gate passage** | The stored record that a stage gate was passed or overridden. |
| **Handoff** | A structured transfer of a case from one person to another, recorded on the timeline. |
| **Human-gated** | The rule that no job or API changes a case; people make every transition. |
| **Improvement action** | A follow-up from the post-incident review, tracked to closure. |
| **Incident** | The middle rung of the ladder. |
| **Incident commander (IC)** | The person leading a case. One per case. |
| **Investigation entry** | A timeline entry describing what the team did. |
| **IOC** | Indicator of compromise: an entity with a Malicious (or Suspicious) disposition. |
| **IRP** | Incident response plan. The ladder and phases follow it. |
| **Ledger** | SQL Server's append-only ledger tables, optionally used for the audit log, seals and custody. |
| **Legal hold** | A flag that prevents archiving until released (optionally by two people). |
| **Materiality** | Legal's or a committee's determination of whether an incident is material; can start notification clocks. |
| **Need-to-know** | Restriction: a restricted case is visible only to its team and cleared roles. |
| **Notification deadline** | The regulatory clock per jurisdiction (for example NYDFS Part 500, 72 hours). |
| **Pending import** | A document submitted through the API, waiting for a person to confirm or reject it. |
| **Permission** | One of eight code-defined capabilities (`ViewCases`, `EditCases`…). |
| **Phase** | NIST SP 800-61 lifecycle position: New, Triage, Containment, Eradication, Recovery, Post-Incident, Closed. |
| **Playbook** | A case template's steps, applied as tasks. |
| **Post-incident review** | The structured lessons-learned record for a case. |
| **Recorded time** | When something was entered. Never changes. |
| **Report profile** | A named report layout a case can use. |
| **Restricted** | See need-to-know. |
| **Role** | A bundle of permissions, mapped to AD groups. Five system roles plus custom ones. |
| **Row hash** | SHA-256 of an entity's canonical content, stored on the row. |
| **Seal** | An RSA signature over the audit chain head, stored in the database and exported. |
| **SLA** | Response targets per severity: detected to contained, detected to resolved (and optionally occurred to detected). |
| **Stage gate** | An admin-defined checklist on promotion, escalation or closure. |
| **Supersede** | (1) Saving a new version of a note, entry or brief. (2) Marking a case as a duplicate of another. |
| **T+** | Time since detection, as a timeline display mode. |
| **Task** | Follow-up work with an owner, due date and kind. |
| **Taxonomy labels** | Admin-editable display names for enums (classification, phase, types). |
| **Third-party case** | A case originating from a vendor's notification. |
| **TLP** | Traffic Light Protocol 2.0 marking (CLEAR, GREEN, AMBER, AMBER+STRICT, RED). |
| **Transition time correction** | A recorded re-dating of a classification, phase or severity change. |
| **Backlog tags** (`F-16`, `INV-43`, `PROD-07`…) | References in code comments to internal planning items. Not needed to understand the code. |
