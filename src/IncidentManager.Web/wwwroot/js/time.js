// U-29: on-screen local-time toggle. These helpers are read by the server (Blazor Server) via JS
// interop. The stored value is ONLY a display preference; all persisted data stays UTC. CSP-safe
// (self-hosted, no inline, no eval), mirroring theme.js.
window.imTime = (function () {
    const TIME_PREF = 'im-time-mode';
    function mode() {
        try { return localStorage.getItem(TIME_PREF) === 'local' ? 'local' : 'utc'; } catch (e) { return 'utc'; }
    }
    function setMode(m) {
        try { localStorage.setItem(TIME_PREF, m === 'local' ? 'local' : 'utc'); } catch (e) { /* private mode */ }
    }
    function zone() {
        try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch (e) { return 'UTC'; }
    }
    return { mode: mode, setMode: setMode, zone: zone };
})();
