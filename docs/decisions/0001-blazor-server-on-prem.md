# 0001. Blazor Server, on-prem, single-tenant

- **Status:** Accepted
- **Recorded:** 2026-10-02 (the decision predates the public repository, 2026-09-09)

## Context

CaseBook holds breach investigations for a regulated insurer: affected-individual data, legal referrals,
materiality decisions. The deployment target is a Windows Server domain with IIS, SQL Server and Active
Directory, often with no general internet egress. The team supporting it is small.

## Decision

One ASP.NET Core application, rendered with **Blazor Server** (interactive server components), hosted
in-process under IIS, one instance per organization. All business logic runs on the server; the browser
receives rendered UI over a SignalR circuit. Users sign in with Windows Integrated Authentication.

## Alternatives considered

- **SPA + JSON API** (React, Blazor WebAssembly): needs a public API covering every operation, CORS and token
  handling, and ships logic to the client. More to secure and maintain for no user benefit here.
- **Multi-tenant SaaS:** out of scope; regulated data stays on the organization's own servers.

## Consequences

- Each open browser tab holds a circuit and its state in server memory. Size the app host for concurrent
  users; a dropped connection shows the reconnect UI.
- The data-protection keyring must persist (`DataProtection:KeyPath`) or every app-pool recycle ends all
  sessions. A web farm would need sticky sessions and a shared keyring (not done today).
- There is no general REST API. The only machine API is the case-import endpoint ([API.md](../API.md)), and it
  stages drafts ([0004](0004-human-gated-automation.md)).
- `DbContext` is created per operation from `IAppDbContextFactory`, never held per circuit (a circuit is one DI
  scope that lives as long as the tab).
