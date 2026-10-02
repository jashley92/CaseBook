# Known issues and technical debt

A living list. Each entry says what happens today, why it matters, and what a fix might look like. Move an entry
out when it's fixed (and mention it in the release notes). Last reviewed: 2026-10-02, at v1.2.4.

Severity: **High** (security or data-integrity impact), **Medium** (wrong behavior users will hit), **Low**
(rough edge, misleading text, or debt).

## Security

| Sev | Current behavior | Why it matters | Possible fix |
|---|---|---|---|
| Medium | **Configuration-bundle signatures are checked against the key inside the file.** It proves integrity, not origin. (`ImportAsync` does refuse a bundle whose signature doesn't verify.) | A self-signed bundle from anywhere imports if an admin accepts it. | Pin trusted key ids. |
| Low | Only `CaseService`, three admin services, the access log and API tokens emit SIEM 5202 on refusal; other services (including the compliance bundle) refuse silently. | Gaps in detection of stale sessions or UI defects. | Emit from the shared `ForbiddenException` path. |
| Low | The audit chain is unkeyed; seals are the anchor (S-05 partial). | See [integrity.md](../architecture/integrity.md#known-limitation). | HMAC key; off-box seal anchoring (WORM, RFC 3161). |
| Low | PII at rest relies on SQL Server TDE; Always Encrypted isn't used. | Column-level protection for the most sensitive fields. | Always Encrypted on selected columns. |

## Data and behavior

| Sev | Current behavior | Why it matters | Possible fix |
|---|---|---|---|
| Medium | **Removing an entity used as an event step's actor or target fails at the database** (Restrict foreign key) with a generic error; `Case.RemoveEntity` doesn't check first. Tasks "about" a removed entity keep a dangling reference. | Confusing failure. | Pre-check and explain, or clear the references. |
| Medium | **Closed and archived cases can still be edited.** No service checks phase or archive state. | May surprise examiners expecting a locked record (the audit trail still shows every change). | Decide on a lock policy; enforce in `LoadTrackedAsync`. |
| Medium | **One reported time stops every jurisdiction's notification clock.** | Multi-jurisdiction cases can't record staggered notifications. | Per-jurisdiction reported times. |
| Medium | **Blank number settings restore the file value instead of meaning "off"**, contrary to the SLA settings' descriptions. | An admin who clears an SLA target still has one. | Store blank as an explicit "none"; fix the text meanwhile. |
| Medium | **The settings form shows catalog defaults, not effective values** (e.g. the production template's 24 h auto-seal shows as 6). | Misleading; the *Setting sources* page is correct. | Show the effective value. |
| Low | `Retention:CaseYears` is editable but nothing reads it; nothing flags cases past retention. | Implies a control that doesn't exist. | Remove the setting, or build the review queue. |
| Low | The composer doesn't reject a **future** occurred time on the server (only the browser does). | Possible bad data via a crafted request. | Validate in `AddTimelineEntryAsync`/`AddEventStepAsync`. |
| Low | **Gate passages are timed when recorded**, even when the transition was backdated. | The two appear at different points on the timeline. | Use the transition's effective time. |
| Low | Import: an **unknown classification** warns "Using Adverse Event instead." but opens a Complex Event. | Misleading message. | Fix the message or the fallback. |
| Low | Notes tab: the composer hint says notes aren't in the report by default; the empty state says "Notes print in the case report". | Contradictory copy (the hint is right). | Fix the empty state. |
| Low | Report version numbers are "count + 1" with no unique index. | Two simultaneous generations can share a number. | Unique index or sequence. |
| Low | Uniqueness of entity values, relationships, case links, active gates and others is enforced only in code. | Concurrent writes can create duplicates. | Unique indexes where possible. |
| Low | Applying a pending import and marking it applied are separate saves. | If the second fails, the case is written but the import stays pending (re-applying is resume-safe). | One unit of work. |
| Low | Hard deletes are recorded with audit action `SoftDelete`. | Confusing label. | Rename the label (display only; the stored value stays). |

## Operations

| Sev | Current behavior | Why it matters | Possible fix |
|---|---|---|---|
| Medium | **Anonymous endpoints aren't reachable on an IIS install** (`/health*`, `/branding/logo`, `/agenda/feed.ics`) because the installer disables anonymous authentication outside `/api`. | Load-balancer probes, email logos and calendar subscriptions fail. | Installer carve-outs for those paths. |
| Medium | **Install-CaseBook without `-AppPoolCredential`** for a non-gMSA account sets a blank password; several messages claim it prompts. | The app pool won't start. | Prompt or refuse. |
| Medium | **Re-running Install-CaseBook overwrites `appsettings.Production.json`** and doesn't update an existing site's bindings. | Manual configuration is lost; adding a certificate by re-running doesn't work. | Merge config; update bindings. |
| Low | `Upgrade-CaseBook.ps1` uses `robocopy /MIR`, which replaces `web.config` and removes other files in the site folder (and the `/XF VERSION.txt.bak` exclusion looks like a typo for `VERSION.txt`). Warm-up treats 401/403 from the site root as healthy rather than probing `/health`. | Hand edits to `web.config` (stdout logging) are lost; non-bundle upgrades lose the version marker. | Exclude `web.config` tweaks; probe readiness. |
| Low | Upgrades never add new non-path settings to `appsettings.Production.json`. | New server-side settings take their `appsettings.json` defaults. | List new settings in release notes (done in UPGRADE notes). |
| Low | Reminder "already sent" trackers are in memory: a restart re-sends one reminder per qualifying item. The executive report marks a quarter sent before sending, so a failed send isn't retried. | Duplicate or missed emails. | Persist trackers. |
| Low | Seal-export failures are swallowed without logging. | A failing out-of-band export goes unnoticed. | Log a warning; show in Diagnostics. |
| Low | The 5002 rejected-setting log line has no event id, and the check runs only at startup. | Harder to alert on from the Windows log. | Add the event id; re-check on reload. |
| Low | Unknown or hidden evidence and report ids return 500 and the error page rather than 404; API errors redirect to an HTML page. | Noise in monitoring; unhelpful for API callers. | Map not-found to 404; JSON errors under `/api`. |
| Low | SMTP has no authentication or timeout settings. | Needs an anonymous or IP-allowed relay. | Credential support via the secret provider. |

## Architecture and debt

| Item | Notes |
|---|---|
| **Single instance only** | In-process audit lock, live refresh, presence, trackers and SIEM queue. Scaling out needs a distributed lock, a backplane, shared trackers and a shared data-protection keyring. |
| **Large classes** | `CaseService` (~2,000 lines), `Case` (~1,300), `CaseWorkspace.razor` (~2,500). Split by area when adding substantially. |
| **Integrity check loads the whole chain every 10 minutes** | See [performance.md](performance.md). |
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
- No retention automation or purge.
- No configurable severity *levels* (only labels).
- No case-type-specific workspace layouts.
