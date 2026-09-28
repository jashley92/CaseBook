// U-29: on-screen local-time toggle. These helpers are read by the server (Blazor Server) via JS
// interop. The stored value is ONLY a display preference; all persisted data stays UTC. CSP-safe
// (self-hosted, no inline, no eval), mirroring theme.js. The signed-in user's saved value arrives on
// <html data-pref-time / data-pref-clock> and theme-init.js copies it into the browser store; the
// attributes are also the fallback when the store is unavailable (private mode).
window.imTime = (function () {
    const TIME_PREF = 'im-time-mode';
    const root = document.documentElement;
    function mode() {
        try { return localStorage.getItem(TIME_PREF) === 'local' ? 'local' : 'utc'; }
        catch (e) { return root.getAttribute('data-pref-time') === 'local' ? 'local' : 'utc'; }
    }
    function setMode(m) {
        const v = m === 'local' ? 'local' : 'utc';
        root.setAttribute('data-pref-time', v);
        try { localStorage.setItem(TIME_PREF, v); } catch (e) { /* private mode */ }
        if (window.imPrefs) window.imPrefs.changed();
    }
    // U-48: 12h / 24h clock preference (display only; default 24h).
    const CLOCK_PREF = 'im-time-clock';
    function clock() {
        try { return localStorage.getItem(CLOCK_PREF) === '12' ? '12' : '24'; }
        catch (e) { return root.getAttribute('data-pref-clock') === '12' ? '12' : '24'; }
    }
    function setClock(c) {
        const v = c === '12' ? '12' : '24';
        root.setAttribute('data-pref-clock', v);
        try { localStorage.setItem(CLOCK_PREF, v); } catch (e) { /* private mode */ }
        if (window.imPrefs) window.imPrefs.changed();
    }
    function zone() {
        try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch (e) { return 'UTC'; }
    }
    return { mode: mode, setMode: setMode, zone: zone, clock: clock, setClock: setClock };
})();
