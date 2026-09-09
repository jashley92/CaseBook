// Runs in <head> before first paint (external file, so it complies with the strict CSP that
// blocks inline scripts). Applies the saved or preferred theme, and the saved sidebar state, so
// there is no flash of the wrong theme or an un-collapsed sidebar.
(function () {
    try {
        var t = localStorage.getItem('im-theme');
        if (!t) { t = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light'; }
        document.documentElement.setAttribute('data-bs-theme', t);
    } catch (e) {
        document.documentElement.setAttribute('data-bs-theme', 'light');
    }
    try {
        if (localStorage.getItem('im-nav') === 'collapsed') {
            document.documentElement.setAttribute('data-nav', 'collapsed');
        }
    } catch (e) { /* private mode — leave the sidebar expanded */ }
})();
