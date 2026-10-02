# Maintaining the documentation

The docs describe what the code does today. They're only useful while that stays true, so they change in the
same commit as the code.

## The rule

> If a change alters how another developer or operator would **understand, configure, troubleshoot, deploy or
> use** CaseBook, the relevant documentation is updated **in the same change**.

A pull request that changes behaviour without touching docs should say why no doc applies ("internal
refactor, no behaviour change").

## What to update when

| You changed… | Update |
|---|---|
| An entity, column, index or enum (any migration) | [architecture/data-model.md](architecture/data-model.md) (tables, ERD, enums), and [UPGRADE.md](UPGRADE.md) *Notes* if the upgrade has a visible effect (data moved, rows added or dropped) |
| A rule in a domain method (what's allowed, what throws) | [reference/business-rules.md](reference/business-rules.md) and the workflow page that covers it |
| What appears on the timeline, or how it's ordered or edited | [architecture/timeline.md](architecture/timeline.md) |
| A page, tab, dialog or route | [architecture/frontend.md](architecture/frontend.md) (route table), the matching [workflows/](workflows/) page, and the screenshot manifest (below) |
| A permission, role, policy or the need-to-know filter | [architecture/security.md](architecture/security.md); the role table in [product/overview.md](product/overview.md) |
| A service-layer action (`CaseService` etc.) | Register it in `CaseActionPermissions` (the app refuses unregistered actions) and update [architecture/backend.md](architecture/backend.md) if it's a new capability |
| An HTTP endpoint (download, export, API, health) | [architecture/backend.md](architecture/backend.md) endpoint table; [API.md](API.md) if it's under `/api` |
| A configuration key (`appsettings`, `SettingsCatalog`, an `*Options` class) | [operations/configuration.md](operations/configuration.md); `deploy/appsettings.Production.template.json` if production needs it; [UPGRADE.md](UPGRADE.md) if existing installs must add it |
| A background job, its cadence or what it touches | [architecture/backend.md](architecture/backend.md) (jobs) and [OPERATIONS.md](OPERATIONS.md) if operators schedule or monitor it |
| A SIEM event id | [OPERATIONS.md §5](OPERATIONS.md#5-siem-security-event-stream-f-18) (append only; ids are a contract) |
| An integration (email, chat, SIEM, CyberArk, import formats, XSIAM) | [operations/integrations.md](operations/integrations.md) |
| A deploy script, the release bundle or CI | [INSTALL.md](INSTALL.md) / [UPGRADE.md](UPGRADE.md) / [development/testing.md](development/testing.md) and `deploy/README.md` |
| A failure mode you diagnosed | Add a *Symptom → Cause → Where to look → Fix* entry to [operations/troubleshooting.md](operations/troubleshooting.md) |
| A deliberate design choice someone might reverse | A new record in [decisions/](decisions/) |
| A known bug, workaround or debt (found or fixed) | [reference/known-issues.md](reference/known-issues.md) |
| UI styling, tokens, components | [STYLE-GUIDE.md](STYLE-GUIDE.md) |

## Screenshots

All images in `docs/screenshots/` are generated, never hand-edited:

```bash
node tools/screenshots/capture.mjs                  # everything
ONLY=doc-timeline,doc-tasks node tools/screenshots/capture.mjs
```

Run against a freshly seeded demo database (see [tools/screenshots/README.md](../tools/screenshots/README.md)).
The `doc-*` shots carry numbered callouts defined in the manifest in `capture.mjs` (`annotate: [[selector, n]]`).
The doc that embeds the image holds the legend, so if you renumber a callout, update the legend too. When a
selector stops matching, the script prints `annotation target(s) not found`: fix the selector rather than
committing an image with a missing callout.

Refresh the affected shots after any visible UI change. Review the PNG diff before committing.

## Diagrams

Diagrams are Mermaid blocks inside the Markdown, so they're edited like text and render on GitHub. Keep them
at the level of the doc they live in (no class-level detail in the architecture overview). When you rename a
class or table that a diagram names, search the docs for it.

## Style

- Describe what exists. Planned work goes in the internal backlog, not here. If behaviour differs from
  what was intended, describe the behaviour and note the difference.
- Cite code as `path/File.cs` (and a member name) rather than line numbers, which rot fast.
- Mark anything you couldn't confirm as **Needs verification**, with what would confirm it.
- Follow the UI copy rules in [STYLE-GUIDE.md §6](STYLE-GUIDE.md#6-microcopy-voice) for wording (US spelling,
  "case", "task", sentence case).
- Don't duplicate: link to the one place a fact lives. The [index](README.md) says where that is.

## Periodic review

Before each release tag, skim the [index](README.md) questions and check that each still leads to a correct
answer. In particular:

1. Run the screenshot tool; recapture anything that changed.
2. Check `docs/operations/configuration.md` against `appsettings.json`, the production template and
   `SettingsCatalog`.
3. Check the route table against `@page` directives (`git grep -n "@page" src/IncidentManager.Web`).
4. Move fixed items out of [reference/known-issues.md](reference/known-issues.md).
