# CaseBook documentation

The documentation set, by audience and question.

| If you need to… | Read |
|---|---|
| Understand what CaseBook is and see it in action | **[../README.md](../README.md)** (overview + screenshots) |
| **Install** a fresh production instance | **[INSTALL.md](INSTALL.md)** — Windows Server 2022 + SQL Server 2022, step by step |
| **Operate** it: backup/DR, key management, host controls, SIEM stream | **[OPERATIONS.md](OPERATIONS.md)** |
| **Understand how it's built** — layers, the integrity spine, access control, data model, diagrams | **[ARCHITECTURE.md](ARCHITECTURE.md)** |
| **Support / troubleshoot** it at runtime (support desk, SRE) | **[SUPPORT.md](SUPPORT.md)** |
| Understand the deploy tooling/scripts | **[../deploy/README.md](../deploy/README.md)** |

### Other assets

- `screenshots/` — the images used in the top-level README.
- `Event_Template_YYYY-##_Subject_of_Event.docx` — the Word event-report template.

---

**Reading order for a new team member:** the top-level README (what it is) → **ARCHITECTURE.md** (how it
works) → **SUPPORT.md** (how to keep it running) → **INSTALL.md** / **OPERATIONS.md** when you actually
deploy or operate an instance.
