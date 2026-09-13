# README screenshot capture (H-10)

`capture.mjs` regenerates the screenshots in `docs/screenshots/` consistently — one viewport (1440×900,
dashboard captured full-page), **dark theme**, dev-auth (all roles), against the **seeded demo data**. It
drives headless Chrome over the DevTools Protocol using only Node's built-in `fetch` + `WebSocket`
(Node 18+), so there are **no dependencies to install**.

## Run

1. Start the app locally on `http://localhost:5103` with a **freshly-seeded** dev database (so the shots
   show clean demo data, not your working state):

   ```bash
   # optional but recommended for pristine demo data — reseeds on next start:
   rm src/IncidentManager.Web/App_Data/incidentmanager.db
   dotnet run --project src/IncidentManager.Web
   ```

2. In another shell, from the repo root:

   ```bash
   node tools/screenshots/capture.mjs
   ```

The PNGs are written straight into `docs/screenshots/`. Review the diff before committing.

## Options (env vars)

| Var        | Default                     | Purpose |
|------------|-----------------------------|---------|
| `BASE_URL` | `http://localhost:5103`     | Where the app is running |
| `OUT_DIR`  | `docs/screenshots`          | Output directory (relative to repo root) |
| `CHROME`   | auto-detected               | Path to `chrome.exe` / `chrome` (falls back to Edge on Windows) |
| `ONLY`     | *(all)*                     | Comma-separated shot names, e.g. `ONLY=dashboard,timeline` |

## How it works / maintenance

- Case- and campaign-scoped shots resolve their ids **at runtime** by reading `/cases?q=Phishing` and
  `/campaigns`, so the tool keeps working after a reseed assigns new GUIDs.
- Each shot is a manifest entry in `capture.mjs` (`SHOTS`): `path` (may contain `{caseId}` /
  `{campaignId}`), an optional `ready` CSS selector to wait for, an optional `before` snippet to run just
  before capture (e.g. opening the report preview), a `settle` delay, and `fullPage`.
- If you add a screenshot to the README, add a matching entry here and rerun.
