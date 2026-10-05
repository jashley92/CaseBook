# Frontend architecture

The UI is Blazor Server: Razor components rendered on the server, with the browser connected over a SignalR
circuit. There's no separate SPA or client build step. Styling conventions and the component vocabulary are in
[STYLE-GUIDE.md](../STYLE-GUIDE.md); this page covers structure and behavior.

All paths are under `src/IncidentManager.Web/`.

## Rendering model

- **One render mode for everything:** `Components/App.razor` renders `<Routes @rendermode="InteractiveServer">`,
  so every page is interactive over the circuit. No page sets its own render mode.
- Because pages render inside the circuit, `HttpContext` isn't available in components. Code that needs the
  user uses `ICurrentUser` or the cascading `AuthenticationState`.
- `App.razor` is the static host document. It writes the user's saved display preferences onto `<html>`
  (theme, sidebar, density, time zone, clock) so the right theme applies before first paint. It loads CSS and
  scripts from `wwwroot` (nothing from a CDN), injects the white-label brand palette, and holds the reconnect
  dialog.
- **Cache busting:** every CSS and JS reference carries `?v=…`. When you change `app.css` or a script, bump its
  `?v=` in `App.razor` in the same commit, or browsers keep the old file.

## Routing

`Components/Routes.razor` uses `AuthorizeRouteView` with `MainLayout`; unauthorized in-circuit navigation
renders `AccessDenied`, and focus moves to the page's `<h1>` after navigation. A refused first GET of a page is
caught by the server and redirected to `/access-denied?from=…`; an unknown page goes to `/not-found?from=…`.

| Route | Page | Policy | Purpose |
|---|---|---|---|
| `/` | `Home` | ViewCases | Leadership dashboard. Users without `ViewAllCases` are sent to `/work` |
| `/team` | `TeamWorkloadPage` | ViewAllCases | Open caseload per analyst, unassigned queue |
| `/work`, `/my` | `MyWorkPage` | ViewCases | My open cases and tasks, recent escalations |
| `/agenda` | `AgendaPage` | ViewCases | Open tasks by due date; calendar feed link. `?owner=` |
| `/cases`, `/cases/mine` | `Cases` | ViewCases | Case list ([query parameters](#lists-filters-and-url-state)) |
| `/cases/new` | `CreateCase` | EditCases | New case form |
| `/cases/import` | `CaseImport` | EditCases | Structured import; pending-import queue. `?into=` (existing case), `?pending=` |
| `/cases/{Id:guid}` | `CaseWorkspace` | ViewCases | The case workspace. `?tab=`, `?entity=`, `?note=` |
| `/cases/{Number}` | `CaseByNumber` | ViewCases | Resolves `2026-14` or `2026-14_Name` and redirects |
| `/campaigns`, `/campaigns/{Id}` | `CampaignsPage`, `CampaignPage` | ViewCases | Campaign list and rollup |
| `/indicators` | `IndicatorsPage` | ViewCases | Cross-case indicators. `?entity=` |
| `/attack-coverage` | `AttackCoveragePage` | ViewCases | ATT&CK heatmap |
| `/improvement-actions` | `ImprovementActionsPage` | ViewCases | Improvement-action register |
| `/integrity` | `Integrity` | ViewCases | Verify chain, seals, audit trail, compliance bundle |
| `/access-log` | `AccessLogPage` | Administer | Read and download log |
| `/exports` | `Exports` | ViewCases | Download CSVs and bundles |
| `/program-report` | `ProgramReportPage` | ViewCases | Quarterly program metrics |
| `/account/access`, `/account/api-tokens`, `/account/notifications` | `Account*` | signed in | My access; personal tokens; notification preferences |
| `/admin`, `/admin/settings/{Section?}` | `Admin` | Administer | Settings sections (below) |
| `/admin/templates`, `/admin/gates`, `/admin/taxonomy`, `/admin/data-elements`, `/admin/outcomes`, `/admin/roles`, `/admin/api-tokens`, `/admin/email-templates`, `/admin/config-bundle`, `/admin/style` | `Admin*`, `StyleGuide` | Administer | Case templates, stage gates, labels, data elements, roles and AD mappings, system tokens, email wording, configuration bundle, live style guide |
| `/access-denied`, `/not-found` | `NoAccess`, `NotFoundPage` | signed in | Friendly 403 and 404 |
| `/Error`, `/session-expired` | `Error`, `SessionExpired` | anonymous (blank layout) | Error with a reference id; idle lock landing |

**Admin sections.** `AdminLayout` adds a left rail. `/admin/settings/{section}` maps to groups in
`SettingsCatalog`: `identity` (organization), `reporting`, `notifications`, `integrations`,
`regulatory-deadlines`, `governance`, `sla`, plus the system views `server` (read-only server configuration),
`source` (where each setting's value comes from) and `diagnostics`. A catalog group not claimed by a section
appears under `/admin/settings/other`. Each section has one Save bar; leaving with unsaved changes prompts.

## Layout and navigation

- **`Layout/MainLayout.razor`**: skip link, sidebar, top bar (command-palette button, activity bell, account
  menu), integrity and evidence-drift banners for administrators, an `ErrorBoundary` around the page (reset on
  navigation), and the singletons rendered once per circuit: `ToastHost`, `CommandPalette`, `IdleGuard`.
- **`Layout/NavMenu.razor`**: groups and items as in [the screen tour](../product/screens.md#navigation-shell),
  each gated with `AuthorizeView`. Collapses to icons on desktop (state saved per user); below 641 px it becomes
  a top bar with a CSS-only menu toggle.
- **Command palette** (`Shared/CommandPalette.razor`): `Ctrl+K`, `⌘K` or `/`. Shows pinned and recent cases,
  navigation, the open case's actions (published by the workspace through `Services/CaseCommandRegistry`), "go
  to tab" for the open case, and live case search.
- **Activity bell** (`Shared/NotificationBell.razor`): recent changes by others on cases you can see, updated
  live; unread state per browser.
- **Account menu** (`Shared/ProfileMenu.razor`): identity and roles, links to account pages, *Lock now*, and
  segmented controls for theme, density, UTC or local time, and 24- or 12-hour clock.

## The case workspace

`Pages/CaseWorkspace.razor` (about 2,500 lines) is the shell; each tab is a component in `Pages/CaseTabs/`.

| Concern | How it works |
|---|---|
| Loading | `CaseService.GetDetailAsync(id)` loads the whole case with its children. Each load records a case open in the access log. A missing or hidden case shows "Case not found". |
| Tabs | Keys `Overview, Timeline, Entities, Evidence, Tasks, Review, Report, Audit` (shown as "IOCs & entities" and "Lessons learned"); `?tab=Notes` opens the Timeline's Working notes lens. `?tab=` selects one; switching uses `history.replaceState`, so the case isn't reloaded. Each tab is wrapped in its own `ErrorBoundary`. |
| Dialogs | All case dialogs (reclassify, phase, severity, handoff, assign, restrict, legal, materiality, supersede, archive, reopen, legal-hold release) live in the shell, so they work from any tab. One generic confirm dialog is offered to tabs through a `RequestConfirm` callback. Shared fragments: the gate checklist with override justification, "when it happened" with nudges, open-task and notification warnings. Apply buttons are disabled exactly when the server would reject the input. |
| Live updates | The shell subscribes to `ICaseChangeNotifier`. When someone else saves, it reloads, flashes the new items in that person's color, puts a dot on other tabs, shows a toast, and shows a "N new entries" pill on the timeline. Your own changes don't flash. Presence avatars (`Shared/CasePresence.razor`) show who else is viewing. All of this is in-process (one server only). |
| Unsaved text | Composer drafts survive tab switches (kept in server memory). Leaving the case with unsaved editor text asks first. |
| Permissions | Checked when the case loads and again when they change mid-session; editing controls are hidden for view-only users, with a "View only" note. |
| Keyboard | `1`–`9` switch tabs; `l` opens the composer, `n` in Working note mode, `t` the task form; `Ctrl+Enter` submits the active composer. |
| Now/Next pane | `CaseNowNext.razor`: the brief (`CaseBriefCard` with `Pane`), obligations, open tasks with their why (`WhyChip`), next-gate readiness, team, key entities. Shown beside every tab when the viewport is at least 1200 px wide, which `js/media.js` (`imMedia.watch`) reports to the workspace (`OnMediaChanged`). Narrower, the Overview keeps the brief and `CaseContextRail` as a strip. |
| Entity panel | `EntityPanel.razor`: a side panel opened from any entity chip, tag or `?entity=`; the verdict picker with its reason, where the case refers to it, tasks, relationships and Seen before. |
| Evidence panel | `EvidencePanel.razor`: opened from an evidence row, a cited-file chip or `?evidence=`; preview on request (`EvidenceService.PreviewTextAsync` for text), integrity, custody, cited by, transfer. |
| State marks | `Shared/SeverityMark`, `RungMark`, `VerdictMark`, `ClockMark`, `PhaseSteps`, `WhyChip`: a word plus a form that isn't colour. Shown on the style guide. |
| Brief | `CaseBriefCard.razor`: the versioned "Where it stands". |

| Tab | Component | Main actions |
|---|---|---|
| Overview | `CaseOverviewTab` | Brief, recent timeline, scope and impact, notification deadlines and *Mark reported*, next-gate readiness, case details, restriction, ATT&CK techniques, related cases |
| Timeline | `CaseTimelineTab` | Lenses (including Working notes, which hosts `CaseNotesTab`), filters, the five-mode composer with follow-ups, edit, versions, cite evidence, raise task, correct time, screenshot paste |
| IOCs & entities | `CaseEntitiesTab` | Add, paste, edit, remove; relationships; graph; also-in; related-case suggestions; defang view; STIX |
| Evidence | `CaseEvidenceTab` | Upload, paste, drag and drop; custody; transfer; preview; raise task |
| Tasks | `CaseTasksTab` | Add, apply playbook, complete with result, comments, bulk select, "about" chips |
| Lessons learned | `CaseReviewTab` | Review, improvement actions, lessons-learned report |
| Report | `CaseReportTab` | Profile, TLP, preview, generate, approve |
| Audit | `CaseAuditTab` | Filtered audit trail, CSV export, "Viewed by" |

## Shared components

Use these rather than writing new ones. All are in `Components/Shared/`.

| Component | Use it for |
|---|---|
| `PageHeader` | The single `<h1>` of every page, a factual subtitle, and an actions slot |
| `StatTile` | Summary number tiles (optionally a link) |
| `LoadingBlock`, `SkeletonTable` | Anything that loads after the page connects. Never a bare "Loading…" |
| `ErrorFallback` | Content for an `ErrorBoundary` (page or section scope) |
| `ConfirmDialog` | "Are you sure?" for destructive actions, with the verb on the button |
| `Breadcrumbs` | Trail on deep routes |
| `CasePeek` | Read-only case preview beside a list or in a drawer (counts as a case open) |
| `OwnerSelect` | Pick a directory user, Unassigned, or type an external name |
| `QuickTask` | Raise a task about an entity, evidence file or timeline entry |
| `PromoteToTimeline` | Put a note or task comment on the timeline |
| `GateChecklist` | Stage-gate readiness |
| `TimeNudges` | "Now / −1 h / −15 min / +15 min" buttons beside a time input |
| `ComposerHint`, `WhyThisMatters` | One-line purpose hint under a composer; collapsed explainer on compliance screens |
| `AttackMatrixPicker`, `AttackStepPicker`, `AttackTacticPicker` | MITRE ATT&CK selection |
| `ReportPreview`, `RichBlocksView`, `StoredReportTable`, `ReportTemplateLibrary`, `ReportProfilesEditor` | Report preview, stored reports, admin report setup |
| `RegulatoryDeadlineRules`, `TeamWorkloadPanel` | Admin deadline rules; workload panel |
| `AccessDenied`, `AccessSummary` | 403 content; "what my roles allow" |
| `IdleGuard`, `IntegrityAlertBanner`, `EvidenceIntegrityBanner`, `ToastHost` | Hosted once by the layout |
| `Ui.cs` | Badge classes and labels for every enum (`Ui.ClassificationBadge`, `Ui.Label(...)`, SLA wording, tactic colors, glyphs). **Always show enum values through `Ui.Label`**: it applies the administrator's taxonomy labels. |
| `AuditLabels.cs` | Readable names for audit actions |

## State

| State | Where it lives |
|---|---|
| Case data | Fetched from services on load and after each change; no client cache |
| Per-circuit UI state | Scoped services in `Web/Services`: `ToastService`, `TimeDisplay` (UTC or local, 24- or 12-hour), `CommandPaletteController`, `CaseCommandRegistry`, `CaseListMemory` (the case list's last filters, for the breadcrumb) |
| Display preferences | `UserDisplayPreferences` table, rendered into `<html>` on load; mirrored to `localStorage` for the pre-paint script. A first visit with nothing saved follows the OS dark/light setting |
| Activity "last seen" | `localStorage` per browser |
| Filters and sort | The URL query string |
| Drafts | Server memory for the life of the circuit |

## Errors, loading and empty states

- A component that throws shows `ErrorFallback` in place; navigating away resets it. A circuit-fatal error
  shows the framework's "Something went wrong. Reload" bar.
- Service exceptions are turned into messages by `Services/UserFacingError.Describe`: validation, permission,
  stale-edit, gate and argument errors are shown as written; anything else is logged and replaced with a
  generic message. Shown as toasts or inline in dialogs.
- Empty states say what would be there and the next step ("No tasks yet. Add the first one above.").
- When the connection drops, the reconnect dialog in `App.razor` appears; after reconnect failure the page
  offers a reload.

## Forms and validation

Most forms are plain inputs bound to component fields, with the Apply button disabled until the input is valid.
`CreateCase.razor` uses `EditForm`; its request is validated on the server by FluentValidation
(`CreateCaseValidator`). **Client-side checks are for convenience only**: domain methods and services
re-validate everything, and their messages are written to be shown as-is.

## Lists, filters and URL state

- `/cases` keeps every filter in the URL: `classification`, `phase`, `sev` (minimum), `origin`, `q`, `closed`,
  `exercises`, `overdue`, `sla`, `notify`, `referred`, `hold`, `opened`, `scope`, `assignee`, `page`, `sort`,
  `dir`, `size`. Dashboard tiles link to pre-filtered lists. Saved views store the query string.
- List tables use the `im-list` pattern from the style guide: one-line rows, sticky header, sortable headers as
  buttons, severity edge on High and Critical rows.
- Paging is server-side on the case list; other lists load in full (sized for a single team's volume).
- Indicator values never go in URLs; link by entity id instead.

## JavaScript

Scripts are plain files in `wwwroot/js` (the content-security policy forbids inline script), loaded from
`App.razor` and called through `IJSRuntime`.

| File | Does | Used by |
|---|---|---|
| `theme-init.js` | Applies theme, sidebar and density before first paint | `App.razor` `<head>` |
| `theme.js` | Theme, density and sidebar toggles; reports changes to the server | Account menu, nav |
| `time.js` | Display time zone and clock preference | `TimeDisplay`, account menu |
| `markdown-editor.js` | Wraps EasyMDE: value sync, `@` mentions, `[[` entity tags, dirty tracking | Notes, timeline, review, overview editors |
| `entity-graph.js` | vis-network relationship graph; reports dragged positions | Entities tab |
| `hotkeys.js` | Global shortcuts: `Ctrl+K`/`/` palette, `?` help, `g`+key go-to | `CommandPalette` |
| `case-hotkeys.js` | Workspace shortcuts (tabs, composers, `Ctrl+Enter`) | `CaseWorkspace` |
| `modal-a11y.js` | Focus trap and focus return for dialogs | Workspace and admin dialogs |
| `paste-drop.js` | Paste a screenshot, drag and drop files | Evidence and timeline tabs |
| `idle-timeout.js` | Inactivity detection for the idle lock | `IdleGuard` |
| `motion.js` | Smooth scroll, sticky header, reveal the active tab | Workspace |
| `activity.js` | Per-browser "last seen" for the bell | `NotificationBell` |
| `docx-view.js` | Renders a filled Word template in the browser (docx-preview) | Report preview |
| `brand.js` | Applies a brand-color change live | Admin branding |

Vendored libraries are in `wwwroot/lib` (EasyMDE, vis-network, docx-preview with JSZip, Bootstrap Icons) and
`wwwroot/bootstrap`.

## Theme and design tokens

- Light and dark themes switch on `data-bs-theme` on `<html>`. The choice is saved per user; with nothing saved
  yet, the first visit follows the OS setting.
- Colors, spacing, radius, elevation and type sizes are CSS custom properties (`--im-*`) in `wwwroot/app.css`.
  Every color token is defined for both themes. An administrator can override the accent and ink colors
  (`Branding:*`), injected as a `<style id="im-brand">` block.
- Density: comfortable (40 px rows) or compact (34 px), via `data-density`.
- Breakpoints: 641 px (sidebar becomes the top bar), 720 px (tile grid), 980 px (wide splits stack), 1200 px
  (the Now/Next pane beside the tabs).

## Accessibility

Skip link; one `<h1>` per page with focus moved to it on navigation; dialogs trap focus and return it;
segmented controls use `aria-pressed` (through `Ui.Aria`) or radio semantics; icons are `aria-hidden` with text
labels; loading states announce to screen readers; keyboard shortcuts don't fire inside inputs or editors;
severity and status are never conveyed by color alone (badges carry text).
