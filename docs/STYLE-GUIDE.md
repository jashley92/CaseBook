# CaseBook Design System Style Guide

Developer-facing conventions for the CaseBook UI (a .NET 8 Blazor Server SOC
incident/breach case-management app). This is the single source of truth for how
pages, badges, colors and copy should look. Every new or changed page must conform.

---

## 1. Purpose & scope

CaseBook has one design system: brand tokens, a shared page skeleton, and a small
family of badge/tile helpers. This guide documents what already exists so screens
stay visually consistent without re-inventing styles per page. If you are adding a
page, a panel, a table or a status chip, use the primitives below rather than
hand-rolling markup or reaching for raw Bootstrap utilities.

Where to look in the code:

- Tokens and component CSS: `src/IncidentManager.Web/wwwroot/app.css`
- Presentation helpers: `src/IncidentManager.Web/Components/Shared/Ui.cs`
- Shared components: `PageHeader.razor`, `StatTile.razor` (same folder)
- Canonical pages: `Components/Pages/Home.razor`, `Components/Pages/Cases.razor`

---

## 2. Theming

CaseBook themes switch on the `data-bs-theme` attribute (Bootstrap's mechanism),
light by default and `data-bs-theme="dark"` for dark. Theme is a deliberate user
choice, not `prefers-color-scheme`; do not gate colors on the OS media query.

Rules:

- All colors come from `--im-*` custom properties. Never hardcode a hex value in a
  component (saturated hex belongs only in graph/bar fills; see section 4).
- Never use Bootstrap semantic colors (`bg-primary`, `text-danger`, `bg-info-subtle`)
  for domain UI. They do not follow the brand tokens and drift between themes.
- Every token you rely on must be defined for both themes. Light values live on
  `:root`; dark overrides live under `[data-bs-theme="dark"]`. If you add a token,
  add it in both blocks.

```css
:root            { --im-surface: #ffffff; --im-text: #1f2733; }
[data-bs-theme="dark"] { --im-surface: #1a212a; --im-text: #e6edf5; }
```

The brand is charcoal + gold: gold (`--im-gold`) is the single accent (links,
focus, active state); charcoal ink (`--im-ink`) carries structure and the primary
button. A Bootstrap bridge in `:root` retints `--bs-primary`, `--bs-link-color` and
`--bs-border-radius` so global components inherit the brand without per-element work.

---

## 3. Color tokens

The main `--im-*` roles. Semantic severity/phase/classification tints are
`[bg / fg / border]` triples; the guide lists the family, not every member.

| Token | Role |
|-------|------|
| `--im-gold`, `--im-gold-strong` | Brand accent fill; deeper gold for hover on dark |
| `--im-ink`, `--im-ink-hover` | Charcoal structure color and primary button |
| `--im-bg` | Page background |
| `--im-surface`, `--im-surface-2` | Card / raised surface, and a subtler second surface |
| `--im-border`, `--im-border-strong` | Default and heavier hairline borders |
| `--im-text`, `--im-text-muted` | Body text and secondary/muted text |
| `--im-accent`, `--im-accent-strong` | Brand fill / active indicator; deeper accent for data-ink |
| `--im-accent-text` | AA-legible gold for links and emphasis |
| `--im-accent-bg`, `--im-focus` | Soft accent wash; focus ring |
| `--im-danger` / `--im-danger-bg` | Problem foreground / soft background |
| `--im-warn` / `--im-warn-bg` | Attention foreground / soft background |
| `--im-ok` / `--im-ok-bg` | Healthy foreground / soft background |
| `--im-neutral` / `--im-neutral-bg` | Neutral state foreground / soft background |
| `--im-sev-{info,low,med,high,crit}-{bg,fg,bd}` | Severity tint triples |
| `--im-phase-{open,active,closed}-{bg,fg,bd}` | Case-phase tint triples |

---

## 4. Badges

The key rule: never use a raw Bootstrap badge (`badge bg-*`, `bg-info-subtle
text-info-emphasis`, etc.). Every chip in CaseBook is an `.im-badge` (soft tint,
AA-legible same-hue text, theme-aware border) plus one modifier class.

Two ways to get one:

1. Domain concepts go through the `Ui.*Badge(...)` helpers in `Ui.cs`. They return
   a full `im-badge ...` class string, so you spread the result onto a `<span>` and
   pair it with the matching `Ui.Label(...)`/`Ui.SlaLabel(...)` text.

   | Helper | Returns (example) | For |
   |--------|-------------------|-----|
   | `Ui.ClassificationBadge(c)` | `im-badge im-cls-breach` | Adverse / Incident / Breach / intake |
   | `Ui.SeverityBadge(s)` | `im-badge im-sev-high` | Informational → Critical |
   | `Ui.PhaseBadge(p)` | `im-badge im-phase-open` | Case lifecycle phase |
   | `Ui.SlaBadge(s)` (+ `Ui.SlaLabel(s)`) | `im-badge im-sla-atrisk` | Response-SLA state |
   | `Ui.CaseLinkBadge(t)` | `im-badge im-b-info` | Case-to-case link type |
   | `Ui.DispositionBadge(d)` | `im-badge im-b-danger` | Entity disposition |

   ```razor
   <span class="@Ui.ClassificationBadge(c.Classification)">@Ui.Label(c.Classification)</span>
   <span class="@Ui.SeverityBadge(c.Severity)">@c.Severity</span>
   <span class="@Ui.SlaBadge(sla.State)">
       <span class="bi @Ui.SlaGlyph(sla.State)" aria-hidden="true"></span> @Ui.SlaLabel(sla.State)
   </span>
   ```

2. Generic state/status/count chips (no dedicated helper) use `im-badge` plus one of
   the five tone modifiers directly in markup:

   | Tone class | Meaning |
   |------------|---------|
   | `im-b-neutral` | State / label / count (default, no signal) |
   | `im-b-info` | Informational (blue) |
   | `im-b-ok` | Healthy / complete (green) |
   | `im-b-warn` | Needs attention (amber) |
   | `im-b-danger` | Problem (red) |

Do / don't:

```razor
@* Don't: raw Bootstrap badge (off-brand, drifts between themes) *@
<span class="badge bg-info-subtle text-info-emphasis">Opened today</span>

@* Do: token-driven im-badge tone *@
<span class="im-badge im-b-info">Opened today</span>
```

Note on saturated hex: `Ui.SeverityColor(...)` and `Ui.DispositionColor(...)` return
solid hex (e.g. `#dc3545`). These are ONLY for graph node and bar/chart fills where a
strong opaque color is needed. They are not for badges or text; use the tint tokens
and badge helpers for anything chip-shaped.

---

## 5. Page structure

Every top-level page follows the same skeleton.

1. Open with `<PageHeader>`. It renders the page's single `<h1>` plus an optional
   subtitle and an optional right-aligned actions slot.

   ```razor
   <PageHeader Title="Cases" Subtitle="@_asOf">
       <Actions>
           <a class="btn btn-sm btn-outline-secondary" href="export/metrics.csv" download>
               <span class="bi bi-download" aria-hidden="true"></span> Export metrics (CSV)
           </a>
       </Actions>
   </PageHeader>
   ```

   `PageHeader` parameters:

   | Parameter | Type | Notes |
   |-----------|------|-------|
   | `Title` | `string` | Required. Becomes the page `<h1>`. |
   | `Subtitle` | `string?` | Optional. Rendered only when non-blank. |
   | `Actions` | `RenderFragment?` | Optional right-side slot for buttons/labels. |

2. Summary rows use an `im-tiles` grid of `<StatTile>` (4 across, 2 across on narrow).

   ```razor
   <div class="im-tiles">
       <StatTile Icon="bi-folder2-open" Value="d.OpenCount" Label="Open cases" Tone="accent" Href="cases" />
       <StatTile Icon="bi-shield-exclamation" Value="d.Breaches" Label="Open breaches"
                 Tone="@(d.Breaches > 0 ? "danger" : "accent")" Href="cases?classification=Breach" />
   </div>
   ```

   `StatTile` parameters:

   | Parameter | Type | Notes |
   |-----------|------|-------|
   | `Icon` | `string` | Required. Bootstrap-icon class, e.g. `bi-folder2-open`. |
   | `Value` | `object?` | Required. The number/text shown large. |
   | `Label` | `string` | Required. Caption under the value. |
   | `Tone` | `string` | `accent` (default), `danger`, `warn`, `ok`, `neutral` (maps to `im-tone-*`). |
   | `Href` | `string?` | Optional. Renders the tile as a drill-in link. |
   | `TitleText` | `string?` | Optional. Hover title; defaults to `View {Label}`. |

3. Content sits in `im-card` panels, each headed by an `im-section-head` (with an
   optional muted `im-section-note` on the right). Tables carry `im-table` alongside
   the Bootstrap table classes.

   ```razor
   <div class="im-card">
       <div class="im-section-head">
           <span><span class="bi bi-folder2-open" aria-hidden="true"></span> Case list</span>
           <span class="im-section-note">@_page.Total cases</span>
       </div>
       <table class="table table-hover align-middle im-table">
           <thead><tr><th>Case #</th><th>Classification</th><th>Severity</th></tr></thead>
           ...
       </table>
   </div>
   ```

---

## 6. Microcopy voice

CaseBook reads like a modern security tool: terse, functional, informative. Write
for an analyst mid-investigation, not a marketing page.

- No narrative or marketing subtitles. A subtitle states a fact ("As of 14:30 UTC",
  a filter summary), never mood copy like "Your day at a glance".
- No em-dashes in prose or guiding text. They read as an AI tell. Use a period,
  semicolon, colon, or parentheses instead. (This applies to labels, help text,
  tooltips and titles.)
- Functional separators are exempt: a bare empty-value cell placeholder, a
  middot count caption (`3 open breaches`), and dropdown placeholder glyphs are
  fine as-is.
- Sentence case for page titles, section heads and buttons ("Open cases", "Export
  metrics", not "Open Cases" / "EXPORT METRICS"). Proper nouns and enum labels keep
  their own casing.

```razor
@* Avoid: marketing subtitle (and note the em-dash, both banned) *@
<PageHeader Title="Dashboard" Subtitle="Your incidents at a glance, updated live" />

@* Prefer: factual, no em-dash *@
<PageHeader Title="Leadership Dashboard" Subtitle="@(_asOf is null ? null : $"As of {_asOf}")" />
```

---

## 7. Conformance checklist

Run this against any new or changed page before review:

- [ ] Page opens with `<PageHeader Title="...">` (single `<h1>`); subtitle is factual, not marketing.
- [ ] No raw Bootstrap badges (`badge bg-*`, `bg-*-subtle text-*-emphasis`). Domain chips use `Ui.*Badge(...)`; generic chips use `im-badge im-b-{neutral|info|ok|warn|danger}`.
- [ ] All colors come from `--im-*` tokens; no hardcoded hex (saturated hex only in graph/bar fills via `Ui.SeverityColor`/`DispositionColor`); no Bootstrap semantic colors.
- [ ] No em-dashes in prose, labels, tooltips or titles.
- [ ] Content uses `im-card` + `im-section-head`; summary rows use `im-tiles` + `<StatTile>`; tables carry `im-table`.
- [ ] Verified in both light and dark (`data-bs-theme` toggle), no drift or unreadable contrast.
