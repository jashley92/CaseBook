# Workflows

End-to-end descriptions of what people do in CaseBook and what happens behind each action.

| Page | Covers |
|---|---|
| [case-lifecycle.md](case-lifecycle.md) | Opening (form, import, API), promotion and reclassification, severity, phases, the close gate, correcting transition times, reopening, superseding duplicates, archiving |
| [investigation.md](investigation.md) | The brief, timeline entries and decisions, event steps, citations, entities and IOCs, evidence, notes, tasks, team and handoff, ATT&CK, case links and campaigns, the Desk and Agenda |
| [governance.md](governance.md) | Stage gates and their checks, materiality, regulatory notification deadlines, legal referral, legal hold, restriction |
| [reporting.md](reporting.md) | The case report, Word templates, approval, lessons learned and improvement actions, cross-case exports |
| [administration.md](administration.md) | Settings, roles and AD mappings, templates, gates, data elements, API tokens, configuration bundle, integrity operations, access log |

Every write follows the same path (permission check, need-to-know load, domain rules, audited save, then
notifications), described in [architecture/backend.md](../architecture/backend.md#the-write-path). The rules
behind each workflow are collected in [reference/business-rules.md](../reference/business-rules.md).
