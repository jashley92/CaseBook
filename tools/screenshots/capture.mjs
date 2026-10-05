// CaseBook README screenshot capture (H-10) — a reusable, dependency-free driver.
//
// Regenerates docs/screenshots/*.png consistently: one viewport size, dark theme, dev-auth (all roles),
// against the seeded demo data. It drives headless Chrome over the DevTools Protocol using only Node's
// built-in fetch + WebSocket (Node 18+), so there is nothing to npm install.
//
// USAGE
//   1. Run the app locally on http://localhost:5103 with a freshly-seeded dev database, e.g.:
//         (delete src/IncidentManager.Web/App_Data/incidentmanager.db for pristine demo data, then)
//         dotnet run --project src/IncidentManager.Web
//   2. node tools/screenshots/capture.mjs
//
// Options (env vars):
//   BASE_URL   default http://localhost:5103
//   OUT_DIR    default docs/screenshots (relative to repo root)
//   CHROME     path to chrome.exe / chrome; auto-detected on Windows/macOS/Linux if unset
//   ONLY       comma-separated shot names to capture just a subset (e.g. ONLY=dashboard,timeline)
//
// Case/campaign ids are discovered at runtime (seeding assigns fresh GUIDs), so this keeps working after
// a reseed. If the demo data changes, adjust the resolvers / shots below.

import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const BASE_URL = (process.env.BASE_URL || 'http://localhost:5103').replace(/\/$/, '');
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT_DIR = resolve(REPO_ROOT, process.env.OUT_DIR || 'docs/screenshots');
const ONLY = process.env.ONLY ? new Set(process.env.ONLY.split(',').map(s => s.trim())) : null;

const VIEWPORT = { width: 1440, height: 900 };
const PORT = 9222 + Math.floor(Math.random() * 500);

// --- The shot manifest -------------------------------------------------------------------------------
// path may contain {caseId} / {campaignId}, filled from the resolvers below.
// ready: optional CSS selector to wait for before capturing (in addition to the load event).
// before: optional JS evaluated in the page just before capture (e.g. open a panel).
// settle: extra ms to wait after load/ready (animations, async renders). fullPage: capture whole document.
const SHOTS = [
  { name: 'dashboard',          path: '/program',                       settle: 1400, fullPage: true },
  // RD-16..RD-21 (Casefile): the Desk, Find, the Briefing, the Close-out view, and a case open beside another.
  { name: 'desk',               path: '/desk',                          settle: 1400 },
  { name: 'find',               path: '/find?q=203.0.113.66',           settle: 1400, viewport: { width: 1440, height: 1250 } },
  { name: 'briefing',           path: '/cases/{caseId}?tab=Briefing',   settle: 1400, viewport: { width: 1440, height: 1250 } },
  { name: 'closeout',           path: '/cases/{caseId}',                settle: 1600, viewport: { width: 1440, height: 1300 },
    before: `(async () => {
      [...document.querySelectorAll('#ws-head button')].find(b => b.textContent.trim().startsWith('Actions'))?.click();
      await new Promise(r => setTimeout(r, 500));
      [...document.querySelectorAll('.dropdown-menu.show button')].find(b => b.textContent.includes('Change phase'))?.click();
      await new Promise(r => setTimeout(r, 900));
      const s = document.getElementById('ws-status');
      if (s) { s.value = 'Closed'; s.dispatchEvent(new Event('change', { bubbles: true })); }
      await new Promise(r => setTimeout(r, 1200));
      document.querySelector('.im-co-outcome')?.click();
      window.scrollTo(0, 0);
    })()` },
  { name: 'case-workspace',     path: '/cases/{caseId}',                settle: 1000 },
  { name: 'create-case',        path: '/cases/new',                     settle: 900 },
  { name: 'case-import',        path: '/cases/import',                  settle: 900,
    before: `(() => { const b=[...document.querySelectorAll('button')].find(x=>x.textContent.trim()==='Show'); if (b) b.click(); })()` },
  { name: 'timeline',           path: '/cases/{caseId}?tab=Timeline',   settle: 1200 },
  { name: 'relationship-graph', path: '/cases/{caseId}?tab=Entities',   ready: '.tabbody .vis-network canvas', settle: 2000 },
  { name: 'campaign-rollup',    path: '/intel/campaigns/{campaignId}',  settle: 1200 },
  { name: 'report',             path: '/cases/{caseId}?tab=Report',     settle: 1500,
    before: `(() => { const b=[...document.querySelectorAll('.tabbody button')].find(x=>x.textContent.trim()==='Preview'); if (b) b.click(); })()` },
  { name: 'integrity-audit',    path: '/integrity',                     settle: 1100 },
  { name: 'access-log',         path: '/access-log',                    settle: 1000 },
  { name: 'admin-settings',     path: '/admin',                         settle: 1000 },
  { name: 'data-elements',      path: '/admin/data-elements',           settle: 1000 },
  { name: 'regulatory-deadlines', path: '/admin/settings/regulatory-deadlines', settle: 1000 },
  { name: 'config-bundle',      path: '/admin/config-bundle',           settle: 1000 },
  // PROD-47: the Word template library. On an empty (throwaway) library it uploads the starter template twice under
  // two names; then it opens a preview panel and scrolls the card to the top of the viewport.
  { name: 'report-templates',   path: '/admin/settings/reporting',      settle: 1200,
    before: `(async () => {
      const card = () => [...document.querySelectorAll('.card')].find(c => c.querySelector('.card-header')?.textContent.includes('Word templates'));
      if (card()?.querySelector('table') == null) {
        const bytes = await (await fetch('/export/report-template-starter.docx')).arrayBuffer();
        for (const [name, file] of [['Examiner pack', 'examiner-pack.docx'], ['Board summary', 'board-summary.docx']]) {
          const box = document.getElementById('tpl-new-name');
          box.value = name; box.dispatchEvent(new Event('input', { bubbles: true }));
          await new Promise(r => setTimeout(r, 300));
          const input = card().querySelector('input[type=file]');
          const dt = new DataTransfer(); dt.items.add(new File([bytes], file));
          input.files = dt.files; input.dispatchEvent(new Event('change', { bubbles: true }));
          await new Promise(r => setTimeout(r, 1500));
        }
      }
      document.querySelectorAll('.toast .btn-close, [aria-label="Dismiss"]').forEach(b => b.click());
      const c = card();
      if (c && !c.textContent.includes('Download preview'))
        [...c.querySelectorAll('table button')].find(b => b.textContent.trim() === 'Preview')?.click();
      await new Promise(r => setTimeout(r, 600));
      if (c) window.scrollTo(0, c.getBoundingClientRect().top + window.scrollY - 70);
    })()` },
  { name: 'roles-access',       path: '/admin/roles',                   settle: 1000 },
  { name: 'cases-filtered',     path: '/cases?classification=Breach',   settle: 1000 },
  // 2026-09-24 additions: post-incident review, the cross-case pages, and the quarterly program report.
  { name: 'lessons-learned',    path: '/cases/{vendorCaseId}?tab=Review', settle: 1200 },
  { name: 'improvement-actions', path: '/program/improvement-actions',  settle: 1000,
    before: `(() => { const s=document.getElementById('ia-scope'); if (s) { s.value='All'; s.dispatchEvent(new Event('change',{bubbles:true})); } })()` },
  { name: 'indicators',         path: '/intel/indicators',              settle: 1200,
    before: `(() => { const s=document.getElementById('ind-type'); if (s) { s.value='all'; s.dispatchEvent(new Event('change',{bubbles:true})); } })()` },
  { name: 'attack-coverage',    path: '/intel/attack',                  settle: 1200,
    before: `(() => { const s=document.getElementById('atk-period'); if (s) { s.value='all'; s.dispatchEvent(new Event('change',{bubbles:true})); }
                      setTimeout(() => document.querySelector('.atkh-cell')?.click(), 600); })()` },
  { name: 'program-report',     path: '/program/report',                settle: 1200 },
  // S-24: what the signed-in user's roles let them do.
  { name: 'my-access',          path: '/account/access',                settle: 900 },
  // After the vendor case's shot, so it's an open tab to put beside the phishing case.
  { name: 'beside',             path: '/cases/{caseId}?tab=Timeline',   settle: 1600, viewport: { width: 1680, height: 1000 },
    before: `(async () => {
      // Make the second demo case a tab, then open it beside this one.
      const other = [...document.querySelectorAll('.im-casetab')].find(t => !t.classList.contains('is-active'));
      other?.querySelector('.im-casetab-split')?.click();
      await new Promise(r => setTimeout(r, 2200));
    })()` },

  // --- Annotated shots for docs/ (numbered callouts; each doc carries the legend) -------------------
  // Selector-driven, so a UI change that moves or renames an element shows up as an "annotation target
  // not found" warning here rather than as a silently wrong picture.
  { name: 'doc-navigation', path: '/desk', settle: 1400,
    annotate: [['.nav-group-label', 1, 0], ['.nav-group-label', 2, 1], ['.nav-group-label', 3, 2],
               ['.palette-trigger', 4], ['.im-casetabs', 5], ['.notif-btn', 6], ['.profile-btn', 7]] },
  { name: 'doc-workspace', path: '/cases/{caseId}', settle: 1600,
    annotate: [['#ws-head .im-casehead-line', 1], ['.im-casehead-state', 2], ['.im-ch-acts', 3],
               ['.im-workspace-tabs', 4], ['.im-nownext', 5]] },
  { name: 'doc-workspace-actions', path: '/cases/{caseId}', settle: 1600, crop: '.dropdown-menu.show',
    before: `(() => { [...document.querySelectorAll('#ws-head button')].find(b => b.textContent.trim().startsWith('Actions'))?.click(); })()` },
  { name: 'doc-timeline', path: '/cases/{caseId}?tab=Timeline', settle: 1800, viewport: { width: 1440, height: 1250 },
    // Oldest first, so the opening adversary steps, the response and the decision are in view.
    before: `(async () => {
      [...document.querySelectorAll('.tl-toolbar button')].find(b => b.textContent.trim() === 'Newest')?.click();
      await new Promise(r => setTimeout(r, 900));
    })()`,
    annotate: [['.tl-toolbar .im-seg', 1, 0], ['.tl-toolbar .btn-outline-secondary', 2, 0], ['.tl-toolbar .im-seg', 3, 1],
               ['.tl-toolbar .btn-primary', 4], ['.killchain-strip', 5], ['.tl-mini', 6], ['.tl-day', 7],
               ['li.tl-kind-event', 8], ['li.tl-kind-ms', 9]] },
  { name: 'doc-timeline-add', path: '/cases/{caseId}?tab=Timeline', settle: 1800, crop: '#timeline-dropzone',
    viewport: { width: 1440, height: 1200 },
    before: `(async () => {
      document.querySelector('.tl-toolbar .btn-primary')?.click();
      await new Promise(r => setTimeout(r, 700));
      [...document.querySelectorAll('.im-modes button')].find(b => b.textContent.includes('Adversary'))?.click();
      await new Promise(r => setTimeout(r, 900));
    })()`,
    annotate: [['.im-modes', 1], ['#tl-atk-when', 2], ['#tl-atk-actor', 3], ['.atk-field', 4], ['.im-then', 5]] },
  { name: 'doc-tasks', path: '/cases/{caseId}?tab=Tasks', settle: 1800,
    annotate: [['.tabbody .btn-outline-primary', 1], ['#task-add-form', 2], ['tr.im-task-group', 3], ['.im-about-chip', 4],
               ['.tabbody tbody td.text-end', 5]] },
  { name: 'doc-evidence', path: '/cases/{caseId}?tab=Evidence', settle: 1800,
    annotate: [['#evidence-dropzone .card', 1], ['#evidence-dropzone tbody tr', 2]] },
  { name: 'doc-entities', path: '/cases/{caseId}?tab=Entities', settle: 2400, viewport: { width: 1440, height: 2000 },
    annotate: [['.tabbody > .card.border-info', 1], ['.tabbody > .card', 2, 1], ['.tabbody > .card', 3, 2],
               ['.tabbody .vis-network', 4], ['.tabbody > .card', 5, 4]] },
  // RD-15: a phase change is a sheet under the header (choosing Closed opens the Close-out view instead).
  { name: 'doc-phase-dialog', path: '/cases/{caseId}', settle: 1600, viewport: { width: 1440, height: 1100 }, crop: '#ws-sheet',
    before: `(async () => {
      document.querySelector('#ws-head .btn-primary')?.click();
      await new Promise(r => setTimeout(r, 1200));
    })()`,
    annotate: [['#ws-status', 1], ['#ws-when', 2], ['#ws-sheet .alert-warning', 3]] },
  { name: 'doc-closeout', path: '/cases/{caseId}', settle: 1600, viewport: { width: 1440, height: 1400 },
    before: `(async () => {
      [...document.querySelectorAll('#ws-head button')].find(b => b.textContent.trim().startsWith('Actions'))?.click();
      await new Promise(r => setTimeout(r, 500));
      [...document.querySelectorAll('.dropdown-menu.show button')].find(b => b.textContent.includes('Change phase'))?.click();
      await new Promise(r => setTimeout(r, 900));
      const s = document.getElementById('ws-status');
      if (s) { s.value = 'Closed'; s.dispatchEvent(new Event('change', { bubbles: true })); }
      await new Promise(r => setTimeout(r, 1200));
      window.scrollTo(0, 0);
    })()`,
    annotate: [['.im-co-outcomes', 1], ['#ws-close-summary', 2], ['#ws-close-conclusion', 3], ['.im-co-side', 4]] },
  { name: 'doc-handoff', path: '/cases/{caseId}', settle: 1600, crop: '.modal-content',
    before: `(async () => {
      document.querySelector('#ws-head button[aria-label="Hand off"]')?.click();
      await new Promise(r => setTimeout(r, 900));
    })()` },
  { name: 'doc-create-case', path: '/cases/new', settle: 1200, fullPage: true,
    annotate: [['#nc-template', 1], ['#cc-classification', 2], ['#isRestricted', 3], ['#nc-detected', 4], ['#nc-indicators', 5]] },
  { name: 'doc-cases-list', path: '/cases', settle: 1400,
    annotate: [['.im-page-actions .im-seg', 1], ['.im-counts', 2], ['.im-filter-row', 3], ['.im-case-list tbody tr', 4]] },
  // RD-25: a case on a phone opens on Now, with its tabs along the bottom; Next shows the obligations and tasks.
  { name: 'doc-mobile-workspace', path: '/cases/{caseId}', settle: 1800, viewport: { width: 390, height: 844, mobile: true } },
  { name: 'doc-mobile-next', path: '/cases/{caseId}', settle: 1800, viewport: { width: 390, height: 844, mobile: true },
    before: `(async () => {
      [...document.querySelectorAll('.im-phone-casetabs button')].find(b => b.textContent.trim().endsWith('Next'))?.click();
      await new Promise(r => setTimeout(r, 900));
    })()` },
];

// Resolve {caseId} to the rich hand-authored demo case (the phishing wave) and {campaignId} to the first
// campaign, by reading the live pages — robust to reseeds that assign new GUIDs.
const RESOLVERS = {
  caseId: {
    url: '/cases?q=Phishing&closed=true',
    eval: `(() => { const a=document.querySelector('table tbody tr a[href^="cases/"]'); return a ? a.getAttribute('href').split('/')[1].split('?')[0] : null; })()`,
  },
  vendorCaseId: {
    url: '/cases?q=Claims-processing&closed=true',
    eval: `(() => { const a=document.querySelector('table tbody tr a[href^="cases/"]'); return a ? a.getAttribute('href').split('/')[1].split('?')[0] : null; })()`,
  },
  campaignId: {
    url: '/intel/campaigns',
    eval: `(() => { const a=document.querySelector('a[href^="intel/campaigns/"]'); return a ? a.getAttribute('href').split('/')[2].split('?')[0] : null; })()`,
  },
};

// --- Annotations (numbered callouts for the docs) ----------------------------------------------------
// A shot's `annotate` is a list of [selector, number] (or [selector, number, nth] to pick the nth match).
// Each target gets an outline and a numbered badge at its top-left corner; the doc that embeds the image
// carries the legend for the numbers. Drawn in document coordinates, so it works for full-page shots too.
function annotateJs(items) {
  return `(() => {
    const items = ${JSON.stringify(items)}, missed = [];
    document.getElementById('docs-annot')?.remove();
    const layer = document.createElement('div');
    layer.id = 'docs-annot';
    layer.style.cssText = 'position:absolute;left:0;top:0;width:0;height:0;z-index:2147483647;pointer-events:none';
    for (const [sel, n, nth] of items) {
      const el = [...document.querySelectorAll(sel)][nth ?? 0];
      if (!el) { missed.push(sel); continue; }
      const r = el.getBoundingClientRect(), x = r.left + scrollX, y = r.top + scrollY;
      const box = document.createElement('div');
      box.style.cssText = 'position:absolute;border:2px solid #ff3d8b;border-radius:6px;box-shadow:0 0 0 2px rgba(0,0,0,.35)';
      Object.assign(box.style, { left: (x - 3) + 'px', top: (y - 3) + 'px', width: (r.width + 6) + 'px', height: (r.height + 6) + 'px' });
      const tag = document.createElement('div');
      tag.textContent = n;
      tag.style.cssText = 'position:absolute;min-width:24px;height:24px;padding:0 6px;border-radius:12px;background:#ff3d8b;color:#fff;'
        + 'font:700 13px/24px Segoe UI,Arial,sans-serif;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.5)';
      Object.assign(tag.style, { left: Math.max(2, x - 14) + 'px', top: Math.max(2, y - 14) + 'px' });
      layer.append(box, tag);
    }
    document.body.append(layer);
    return missed;
  })()`;
}

// --- Minimal CDP client over the raw WebSocket -------------------------------------------------------
function findChrome() {
  if (process.env.CHROME) return process.env.CHROME;
  const candidates = process.platform === 'win32'
    ? ['C:/Program Files/Google/Chrome/Application/chrome.exe',
       'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
       'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe']
    : process.platform === 'darwin'
      ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome']
      : ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  const hit = candidates.find(p => existsSync(p));
  if (!hit) throw new Error('Chrome/Edge not found — set CHROME=/path/to/chrome');
  return hit;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

class Cdp {
  constructor(ws) { this.ws = ws; this.id = 0; this.pending = new Map(); this.listeners = new Set();
    ws.addEventListener('message', e => {
      const m = JSON.parse(e.data);
      if (m.id && this.pending.has(m.id)) {
        const { resolve, reject } = this.pending.get(m.id); this.pending.delete(m.id);
        m.error ? reject(new Error(m.error.message)) : resolve(m.result);
      } else if (m.method) { for (const l of this.listeners) l(m); }
    });
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params, sessionId }));
      setTimeout(() => { if (this.pending.has(id)) { this.pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); } }, 30000);
    });
  }
  once(method, sessionId) {
    return new Promise(resolve => {
      const l = m => { if (m.method === method && (!sessionId || m.sessionId === sessionId)) { this.listeners.delete(l); resolve(m.params); } };
      this.listeners.add(l);
    });
  }
}

async function getJson(path) {
  const r = await fetch(`http://127.0.0.1:${PORT}${path}`);
  return r.json();
}

async function main() {
  // Fail fast if the app isn't up — this tool captures, it doesn't host.
  try { const r = await fetch(BASE_URL, { redirect: 'manual' }); if (r.status >= 500) throw 0; }
  catch { console.error(`\n  The app isn't responding at ${BASE_URL}.\n  Start it first:  dotnet run --project src/IncidentManager.Web\n`); process.exit(1); }

  mkdirSync(OUT_DIR, { recursive: true });
  const chrome = findChrome();
  const profile = mkdtempSync(join(tmpdir(), 'casebook-shots-'));
  const proc = spawn(chrome, [
    '--headless=new', `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`,
    `--window-size=${VIEWPORT.width},${VIEWPORT.height}`, '--hide-scrollbars', '--force-device-scale-factor=1',
    '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-gpu', 'about:blank',
  ], { stdio: 'ignore' });

  try {
    // Wait for the debugging endpoint, then open a controllable page target.
    let ver; for (let i = 0; i < 50; i++) { try { ver = await getJson('/json/version'); break; } catch { await sleep(200); } }
    if (!ver) throw new Error('Chrome DevTools endpoint never came up');
    const { WebSocket } = globalThis;
    const browser = new Cdp(new WebSocket(ver.webSocketDebuggerUrl));
    await new Promise(r => browser.ws.addEventListener('open', r, { once: true }));

    const { targetId } = await browser.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await browser.send('Target.attachToTarget', { targetId, flatten: true });
    const S = sessionId;
    await browser.send('Page.enable', {}, S);
    await browser.send('Runtime.enable', {}, S);
    await browser.send('Emulation.setDeviceMetricsOverride',
      { width: VIEWPORT.width, height: VIEWPORT.height, deviceScaleFactor: 1, mobile: false }, S);

    const goto = async (url) => {
      const loaded = browser.once('Page.loadEventFired', S);
      await browser.send('Page.navigate', { url }, S);
      await Promise.race([loaded, sleep(15000)]);
    };
    const evalJs = async (expr) => (await browser.send('Runtime.evaluate',
      { expression: expr, returnByValue: true, awaitPromise: true }, S)).result?.value;

    // Persist the dark theme on the origin so theme-init applies it before paint on every shot.
    await goto(BASE_URL + '/');
    await evalJs(`try{localStorage.setItem('im-theme','dark')}catch(e){}`);

    // Resolve dynamic ids.
    const ctx = {};
    for (const [key, r] of Object.entries(RESOLVERS)) {
      await goto(BASE_URL + r.url);
      await sleep(700);
      ctx[key] = await evalJs(r.eval);
      if (!ctx[key]) console.warn(`  ! could not resolve {${key}} — shots using it will be skipped`);
    }

    let ok = 0, skipped = 0;
    for (const shot of SHOTS) {
      if (ONLY && !ONLY.has(shot.name)) continue;
      // Skip only when a placeholder this shot needs didn't resolve.
      const missing = [...shot.path.matchAll(/\{(\w+)\}/g)].some(m => !ctx[m[1]]);
      if (missing) { console.warn(`  - skip ${shot.name} (unresolved id)`); skipped++; continue; }
      const path = shot.path.replace(/\{(\w+)\}/g, (_, k) => ctx[k]);
      const vp = shot.viewport || VIEWPORT;
      if (shot.viewport) await browser.send('Emulation.setDeviceMetricsOverride',
        { width: vp.width, height: vp.height, deviceScaleFactor: 1, mobile: !!vp.mobile }, S);
      await goto(BASE_URL + path);
      if (shot.ready) {
        let seen = false;
        for (let i = 0; i < 40; i++) { if (await evalJs(`!!document.querySelector(${JSON.stringify(shot.ready)})`)) { seen = true; break; } await sleep(150); }
        if (!seen) console.warn(`  ! ${shot.name}: ready selector never appeared (${shot.ready})`);
      }
      await sleep(shot.settle ?? 800);
      if (shot.before) { try { await evalJs(shot.before); } catch {} await sleep(700); }
      if (shot.annotate) {
        const missed = await evalJs(annotateJs(shot.annotate));
        if (missed?.length) console.warn(`  ! ${shot.name}: annotation target(s) not found: ${missed.join(', ')}`);
        await sleep(150);
      }

      let clip;
      if (shot.fullPage) {
        const m = await browser.send('Page.getLayoutMetrics', {}, S);
        const h = Math.ceil(m.cssContentSize?.height || m.contentSize?.height || VIEWPORT.height);
        clip = { x: 0, y: 0, width: vp.width, height: h, scale: 1 };
      } else if (shot.crop) {
        // Crop to one element (a dialog, a panel) plus a margin, in viewport coordinates.
        const r = await evalJs(`(() => { const e=document.querySelector(${JSON.stringify(shot.crop)}); if (!e) return null;
          const b=e.getBoundingClientRect(); return { x:b.x, y:b.y, w:b.width, h:b.height }; })()`);
        if (r) {
          const pad = 16, x = Math.max(0, r.x - pad), y = Math.max(0, r.y - pad);
          clip = { x, y, width: Math.min(vp.width - x, r.w + pad * 2), height: Math.min(vp.height - y, r.h + pad * 2), scale: 1 };
        } else console.warn(`  ! ${shot.name}: crop target not found (${shot.crop})`);
      }
      const { data } = await browser.send('Page.captureScreenshot',
        { format: 'png', captureBeyondViewport: !!shot.fullPage, ...(clip ? { clip } : {}) }, S);
      const file = join(OUT_DIR, `${shot.name}.png`);
      writeFileSync(file, Buffer.from(data, 'base64'));
      console.log(`  ✓ ${shot.name}.png`);
      if (shot.viewport) await browser.send('Emulation.setDeviceMetricsOverride',
        { width: VIEWPORT.width, height: VIEWPORT.height, deviceScaleFactor: 1, mobile: false }, S);
      ok++;
    }
    console.log(`\nDone — ${ok} captured${skipped ? `, ${skipped} skipped` : ''} → ${OUT_DIR}`);
  } finally {
    proc.kill();
  }
}

main().catch(e => { console.error(e); process.exit(1); });
