# CaseBook documentation

Start with the question you have.

## Where do I go to learn…

| I want to know… | Read |
|---|---|
| What CaseBook is, who uses it, and what it deliberately doesn't do | [product/overview.md](product/overview.md) |
| What the screens look like and what each control does | [product/screens.md](product/screens.md) |
| What a term means | [reference/glossary.md](reference/glossary.md) |
| How the system is put together | [architecture/overview.md](architecture/overview.md) |
| Where a piece of code lives | [architecture/codebase-map.md](architecture/codebase-map.md) |
| What's stored, in which table, and how it relates | [architecture/data-model.md](architecture/data-model.md) |
| How the timeline is built | [architecture/timeline.md](architecture/timeline.md) |
| Who can see and do what, and where it's enforced | [architecture/security.md](architecture/security.md) |
| How tamper evidence works | [architecture/integrity.md](architecture/integrity.md) |
| How the UI is structured | [architecture/frontend.md](architecture/frontend.md) |
| Services, HTTP endpoints, background jobs, notifications | [architecture/backend.md](architecture/backend.md) |
| What happens when a user does X | [workflows/](workflows/README.md) |
| Which rules I must not break, and why | [reference/business-rules.md](reference/business-rules.md) |
| Why something was built the way it was | [decisions/](decisions/README.md) |
| What's broken, fragile, or missing | [reference/known-issues.md](reference/known-issues.md) |
| Performance and scale limits | [reference/performance.md](reference/performance.md) |
| How to get it running on my machine | [development/getting-started.md](development/getting-started.md) |
| How to add a field, page, entity, permission, setting… | [development/recipes.md](development/recipes.md) |
| How tests and CI work, and what isn't covered | [development/testing.md](development/testing.md) |
| UI styling and copy rules | [STYLE-GUIDE.md](STYLE-GUIDE.md) |
| How to install a production instance | [INSTALL.md](INSTALL.md) |
| How to upgrade one | [UPGRADE.md](UPGRADE.md) |
| Backups, keys, host controls, SIEM, CyberArk, ledger | [OPERATIONS.md](OPERATIONS.md) |
| Every configuration setting | [operations/configuration.md](operations/configuration.md) |
| How each integration works | [operations/integrations.md](operations/integrations.md) |
| What to do when something breaks | [operations/troubleshooting.md](operations/troubleshooting.md) |
| How to call the import API | [API.md](API.md) and [case-import.schema.json](case-import.schema.json) |
| The deploy scripts | [../deploy/README.md](../deploy/README.md) |
| How to keep these docs current | [MAINTAINING-DOCS.md](MAINTAINING-DOCS.md) |

## Reading paths

- **New developer:** [product/overview.md](product/overview.md) → [product/screens.md](product/screens.md) →
  [architecture/overview.md](architecture/overview.md) → [development/getting-started.md](development/getting-started.md)
  → [reference/business-rules.md](reference/business-rules.md) → [architecture/codebase-map.md](architecture/codebase-map.md).
- **Operator / system administrator:** [architecture/overview.md](architecture/overview.md#runtime-topology-production)
  → [INSTALL.md](INSTALL.md) → [OPERATIONS.md](OPERATIONS.md) → [operations/configuration.md](operations/configuration.md)
  → [operations/troubleshooting.md](operations/troubleshooting.md).
- **Security reviewer or examiner:** [architecture/security.md](architecture/security.md) →
  [architecture/integrity.md](architecture/integrity.md) → [reference/known-issues.md](reference/known-issues.md#security)
  → [OPERATIONS.md §5](OPERATIONS.md#5-siem-security-event-stream-f-18).
- **Investigator using the app:** [product/screens.md](product/screens.md) → [workflows/](workflows/README.md).

## Layout

```
docs/
  README.md               this index
  product/                what it is; the screens
  architecture/           how it's built: overview, code map, data, timeline, security, integrity, frontend, backend
  workflows/              what users do and what happens
  development/            getting started, recipes, testing
  operations/             configuration, integrations, troubleshooting
  reference/              business rules, known issues, performance, glossary
  decisions/              architecture decision records
  screenshots/            generated images (tools/screenshots/capture.mjs)
  INSTALL.md, UPGRADE.md, OPERATIONS.md, API.md, STYLE-GUIDE.md, case-import.schema.json
                          kept at these paths because the app, the deploy scripts and tests link to them
  MAINTAINING-DOCS.md     how to keep this current
```

Code comments refer to internal planning items by tag (`F-16`, `INV-43`, `PROD-07`, …). The planning files are
private; you don't need them to understand the code.
