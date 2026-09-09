// Light/dark theme toggle. The initial theme is set by an inline script in the <head> (before
// paint, to avoid a flash); this just flips and persists it. Bootstrap 5.3 reads data-bs-theme.
window.imTheme = (function () {
    const THEME_PREF = 'im-theme';
    function current() { return document.documentElement.getAttribute('data-bs-theme') || 'light'; }
    function apply(t) {
        document.documentElement.setAttribute('data-bs-theme', t);
        try { localStorage.setItem(THEME_PREF, t); } catch (e) { /* private mode */ }
    }
    function toggle() { apply(current() === 'dark' ? 'light' : 'dark'); }
    return { toggle: toggle, apply: apply, current: current };
})();

// Sidebar collapse (icons-only). The initial state is applied by theme-init.js in <head> before
// paint; this flips and persists it. CSS keys off documentElement's data-nav="collapsed".
window.imNav = (function () {
    const NAV_PREF = 'im-nav';
    function collapsed() { return document.documentElement.getAttribute('data-nav') === 'collapsed'; }
    function apply(isCollapsed) {
        if (isCollapsed) { document.documentElement.setAttribute('data-nav', 'collapsed'); }
        else { document.documentElement.removeAttribute('data-nav'); }
        try { localStorage.setItem(NAV_PREF, isCollapsed ? 'collapsed' : 'expanded'); } catch (e) { /* private mode */ }
    }
    function toggle() { apply(!collapsed()); }
    return { toggle: toggle, apply: apply, collapsed: collapsed };
})();

// Delegated handlers (attached from an external file so they satisfy the strict CSP that blocks
// inline event handlers).
document.addEventListener('click', function (e) {
    if (!e.target || !e.target.closest) return;
    // Flip the theme when the toggle is clicked.
    if (e.target.closest('#theme-toggle')) {
        window.imTheme.toggle();
        return;
    }
    // Collapse or expand the desktop sidebar.
    if (e.target.closest('#nav-collapse-toggle')) {
        window.imNav.toggle();
        return;
    }
    // Collapse the mobile nav after a link is chosen.
    if (e.target.closest('.nav-scrollable a')) {
        var toggler = document.querySelector('.navbar-toggler');
        if (toggler && toggler.checked) toggler.checked = false;
    }
    // Blazor circuit-disconnect modal (U-10): retry the SignalR connection, or hard-reload when the
    // server rejected reconnection (circuit state lost). Wired here to satisfy the strict CSP.
    if (e.target.closest('#components-reconnect-retry')) {
        if (window.Blazor && window.Blazor.reconnect) window.Blazor.reconnect();
        return;
    }
    if (e.target.closest('#components-reconnect-reload')) {
        location.reload();
        return;
    }
});
