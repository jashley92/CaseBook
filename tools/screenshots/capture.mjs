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
  { name: 'dashboard',          path: '/',                              settle: 1400, fullPage: true },
  { name: 'case-workspace',     path: '/cases/{caseId}',                settle: 1000 },
  { name: 'create-case',        path: '/cases/new',                     settle: 900 },
  { name: 'timeline',           path: '/cases/{caseId}?tab=Timeline',   settle: 1200 },
  { name: 'relationship-graph', path: '/cases/{caseId}?tab=Entities',   ready: '.tabbody .vis-network canvas', settle: 2000 },
  { name: 'campaign-rollup',    path: '/campaigns/{campaignId}',        settle: 1200 },
  { name: 'report',             path: '/cases/{caseId}?tab=Report',     settle: 1500,
    before: `(() => { const b=[...document.querySelectorAll('.tabbody button')].find(x=>x.textContent.trim()==='Preview'); if (b) b.click(); })()` },
  { name: 'integrity-audit',    path: '/integrity',                     settle: 1100 },
  { name: 'access-log',         path: '/admin/access-log',              settle: 1000 },
  { name: 'admin-settings',     path: '/admin',                         settle: 1000 },
  { name: 'data-elements',      path: '/admin/data-elements',           settle: 1000 },
  { name: 'config-bundle',      path: '/admin/config-bundle',           settle: 1000 },
  { name: 'roles-access',       path: '/admin/roles',                   settle: 1000 },
  { name: 'cases-filtered',     path: '/cases?classification=Breach',   settle: 1000 },
];

// Resolve {caseId} to the rich hand-authored demo case (the phishing wave) and {campaignId} to the first
// campaign, by reading the live pages — robust to reseeds that assign new GUIDs.
const RESOLVERS = {
  caseId: {
    url: '/cases?q=Phishing&closed=true',
    eval: `(() => { const a=document.querySelector('table tbody tr a[href^="cases/"]'); return a ? a.getAttribute('href').split('/')[1].split('?')[0] : null; })()`,
  },
  campaignId: {
    url: '/campaigns',
    eval: `(() => { const a=document.querySelector('a[href^="campaigns/"]'); return a ? a.getAttribute('href').split('/')[1].split('?')[0] : null; })()`,
  },
};

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
      await goto(BASE_URL + path);
      if (shot.ready) {
        let seen = false;
        for (let i = 0; i < 40; i++) { if (await evalJs(`!!document.querySelector(${JSON.stringify(shot.ready)})`)) { seen = true; break; } await sleep(150); }
        if (!seen) console.warn(`  ! ${shot.name}: ready selector never appeared (${shot.ready})`);
      }
      await sleep(shot.settle ?? 800);
      if (shot.before) { try { await evalJs(shot.before); } catch {} await sleep(700); }

      let clip;
      if (shot.fullPage) {
        const m = await browser.send('Page.getLayoutMetrics', {}, S);
        const h = Math.ceil(m.cssContentSize?.height || m.contentSize?.height || VIEWPORT.height);
        clip = { x: 0, y: 0, width: VIEWPORT.width, height: h, scale: 1 };
      }
      const { data } = await browser.send('Page.captureScreenshot',
        { format: 'png', captureBeyondViewport: !!shot.fullPage, ...(clip ? { clip } : {}) }, S);
      const file = join(OUT_DIR, `${shot.name}.png`);
      writeFileSync(file, Buffer.from(data, 'base64'));
      console.log(`  ✓ ${shot.name}.png`);
      ok++;
    }
    console.log(`\nDone — ${ok} captured${skipped ? `, ${skipped} skipped` : ''} → ${OUT_DIR}`);
  } finally {
    proc.kill();
  }
}

main().catch(e => { console.error(e); process.exit(1); });
