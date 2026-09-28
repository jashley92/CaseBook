// Runs in <head> before first paint (external file, so it complies with the strict CSP that
// blocks inline scripts). Applies the theme, sidebar state and list density so there is no flash
// of the wrong theme or an un-collapsed sidebar.
//
// When the server rendered the signed-in user's saved preferences onto <html> (data-prefs="server"),
// those win and the browser's copy is refreshed from them, so time.js and theme.js read the same
// values. Otherwise (no saved preferences yet, or signed out) the browser's copy is used as before.
(function () {
    var root = document.documentElement;
    if (root.getAttribute('data-prefs') === 'server') {
        try {
            localStorage.setItem('im-theme', root.getAttribute('data-bs-theme') || 'light');
            localStorage.setItem('im-nav', root.getAttribute('data-nav') === 'collapsed' ? 'collapsed' : 'expanded');
            localStorage.setItem('im-density', root.getAttribute('data-density') === 'compact' ? 'compact' : 'comfortable');
            localStorage.setItem('im-time-mode', root.getAttribute('data-pref-time') === 'local' ? 'local' : 'utc');
            localStorage.setItem('im-time-clock', root.getAttribute('data-pref-clock') === '12' ? '12' : '24');
        } catch (e) { /* private mode — the attributes already carry the preferences */ }
        return;
    }
    try {
        var t = localStorage.getItem('im-theme');
        if (!t) { t = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light'; }
        root.setAttribute('data-bs-theme', t);
    } catch (e) {
        root.setAttribute('data-bs-theme', 'light');
    }
    try {
        if (localStorage.getItem('im-density') === 'compact') {
            root.setAttribute('data-density', 'compact');
        }
    } catch (e) { /* private mode — comfortable rows */ }
    try {
        if (localStorage.getItem('im-nav') === 'collapsed') {
            root.setAttribute('data-nav', 'collapsed');
        }
    } catch (e) { /* private mode — leave the sidebar expanded */ }
})();
