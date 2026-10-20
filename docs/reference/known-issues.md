# Known issues and technical debt

A living list. Each entry says what happens today, why it matters, and what a fix might look like. Move an entry
out when it's fixed (and mention it in the release notes). Last reviewed: 2026-10-09, at v1.4.0.

Severity: **High** (security or data-integrity impact), **Medium** (wrong behavior users will hit), **Low**
(rough edge, misleading text, or debt).

## Security

| Sev | Current behavior | Why it matters | Possible fix |
|---|---|---|---|
| Low | **A bundle signed with an unknown key still imports once an administrator types its key id** (CAP-16; this server's key and the keys in `Config:TrustedBundleKeys` import without asking). Typing the id is a deliberate act, audited and sent to the SIEM, but it's the administrator's check against the source, not the server's. | An administrator persuaded to type a stranger's key id can import their bundle. | Turn off the typed-id route where every source's key is in the trusted folder (not built). |
| Low | Only `CaseService`, three admin services, the access log and API tokens emit SIEM 5202 on refusal; other services (including the compliance bundle) refuse silently. | Gaps in detection of stale sessions or UI defects. | Emit from the shared `ForbiddenException` path. |
| Low | The audit chain is unkeyed unless the chain key is turned on (off by default). Without it, up to one seal interval (6 h by default) of the newest entries is protected only by database access control. | See [integrity.md](../architecture/integrity.md#known-limitation). | Turn on `Integrity:ChainKey` once the key's backup is in place ([OPERATIONS.md §2](../OPERATIONS.md#the-audit-chain-key-f-25-off-by-default)). |
| Low | PII at rest relies on SQL Server TDE; Always Encrypted isn't used. | Column-level protection for the most sensitive fields. | Always Encrypted on selected columns. |

## Data and behavior

| Sev | Current behavior | Why it matters | Possible fix |
|---|---|---|---|
| Medium | **Blank number settings restore the file value instead of meaning "off"**, contrary to the SLA settings' descriptions. | An admin who clears an SLA target still has one. | Store blank as an explicit "none"; fix the text meanwhile. |
| Low | The composer doesn't reject a **future** occurred time on the server (only the browser does). | Possible bad data via a crafted request. | Validate in `AddTimelineEntryAsync`/`AddEventStepAsync`. |
| Low | Import: an **unknown classification** warns "Using Adverse Event instead." but opens a Complex Event. | Misleading message. | Fix the message or the fallback. |
| Low | Report version numbers are "count + 1" with no unique index. | Two simultaneous generations can share a number. | Unique index or sequence. |
| Low | Uniqueness of entity values, relationships, case links, active gates and others is enforced only in code. | Concurrent writes can create duplicates. | Unique indexes where possible. |
| Low | Applying a pending import and marking it applied are separate saves. | If the second fails, the case is written but the import stays pending (re-applying is resume-safe). | One unit of work. |
| Low | The Program overview flags a brief that predates a decision, handoff, phase, classification or materiality change; the case page also counts timeline entries since the brief. | The overview can miss a brief that's behind only on entries. | Share one freshness query with the case page. |

## Operations

| Sev | Current behavior | Why it matters | Possible fix |
|---|---|---|---|
| Medium | **Install-CaseBook without `-AppPoolCredential`** for a non-gMSA account sets a blank password; several messages claim it prompts. | The app pool won't start. | Prompt or refuse. |
| Medium | **Re-running Install-CaseBook overwrites `appsettings.Production.json`** and doesn't update an existing site's bindings. | Manual configuration is lost; adding a certificate by re-running doesn't work. | Merge config; update bindings. |
| Low | `Upgrade-CaseBook.ps1` uses `robocopy /MIR`, which replaces `web.config` with the release's and removes other files in the site folder (`appsettings.Production.json`, `VERSION.txt` and `logs` are kept). | Hand edits to `web.config` (stdout logging) are lost on each upgrade. | Re-apply them after upgrading, or keep them in `appsettings.Production.json` where a setting exists. |
| Low | Upgrades never add new non-path settings to `appsettings.Production.json`. | New server-side settings take their `appsettings.json` defaults. | List new settings in release notes (done in UPGRADE notes). |
| Low | The 5002 rejected-setting log line has no event id, and the check runs only at startup. | Harder to alert on from the Windows log. | Add the event id; re-check on reload. |
| Low | Unknown or hidden evidence and report ids return 500 and the error page rather than 404; API errors redirect to an HTML page. | Noise in monitoring; unhelpful for API callers. | Map not-found to 404; JSON errors under `/api`. |

## Architecture and debt

| Item | Notes |
|---|---|
| **Single instance only** | In-process audit lock, live refresh, presence, trackers and SIEM queue. Scaling out needs a distributed lock, a backplane, shared trackers and a shared data-protection keyring. |
| **Large classes** | `CaseService` (~2,400 lines), `Case` (~1,400), `CaseTimelineTab.razor` (~2,400). `CaseWorkspace` is split into partial files. Split by area when adding substantially. |
| **Test gaps** | No browser, component or HTTP-level tests; little SQL Server coverage; deploy scripts untested ([testing.md](../development/testing.md#what-is-not-covered)). |
| **Release workflow doesn't test** | It relies on CI having passed for the tagged commit. |
| **Floating package versions** | Microsoft packages use `10.*`, so builds at different times can differ. |
| **FluentAssertions 8 license** | Commercial use needs a license (test-only dependency). |
| **CI step label** | "Set up .NET 8" installs .NET 10 (cosmetic). |
| **Stale build output** | Old `bin/obj/*/net8.0` folders can linger in working copies (ignored by git); harmless, but confusing when searching. |
| **Per-user graph layouts** | Graph positions are shared, last write wins. |

## Not implemented (sometimes assumed)

- No SOAR actions, no SIEM queries, no automatic case creation from alerts.
- No per-user chat (Slack/Teams app); the webhook is a shared channel.
- No read-only API for case status back to the detection platform.
- No retention automation or purge. Closed cases past `Retention:CaseYears` are listed for an administrator to archive
  (Administration › Retention, CAP-10); nothing is archived or deleted by a job, and purging waits for two-person control.
- No configurable severity *levels* (only labels).
- No case-type-specific workspace layouts.
