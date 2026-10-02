# 0005. CaseBook never calls an AI

- **Status:** Accepted
- **Recorded:** 2026-10-02

## Context

Analysts want help turning email threads and chat logs into a structured case. Sending case content to an
external model is an egress of regulated data, and deployments are often air-gapped.

## Decision

CaseBook makes **no** calls to an LLM or any other AI service. AI help is *bring your own*:

1. The Import page generates a prompt that embeds the import JSON schema.
2. The analyst runs it in a tool their organization already approved (for example Copilot).
3. They paste the JSON back. CaseBook validates it and shows an editable preview, and a person confirms it.

Where content came from is recorded as data: the import's `origin` becomes the provenance of the imported
entries. Features such as "Draft from the case record" in lessons learned are template-based.

## Consequences

- Never add an outbound call to a model provider. The only outbound connections go to operator-configured
  endpoints: the SIEM collector, a chat webhook and CyberArk CCP, plus SMTP and syslog.
- The import schema is a public contract (`GET /api/import/cases/schema`, `docs/case-import.schema.json`). A
  test fails if the committed copy drifts from the code.
