// Per-browser "last seen activity" marker for the notification bell (U-17).
// Kept in localStorage so the unread badge survives reloads; read/written via JS interop
// (CSP-safe — no inline script).
window.imActivity = {
    getSeen: function () {
        try { return localStorage.getItem('im.activitySeen'); } catch (e) { return null; }
    },
    setSeen: function (value) {
        try { localStorage.setItem('im.activitySeen', value); } catch (e) { /* ignore */ }
    }
};
