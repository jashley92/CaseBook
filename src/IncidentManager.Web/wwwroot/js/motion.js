// U-32/U-33: small UI-motion helpers (CSP-safe, self-hosted, no eval).
window.imMotion = {
    // Smooth-scroll an element into view by id (used by the timeline "jump to new" pill).
    // Falls back to an instant jump when the viewer prefers reduced motion.
    // Case workspace (design review P4): mark the sticky tab strip data-stuck once the case header has scrolled
    // under it, so CSS can show the one-line identity bar. Re-arming for another case replaces the observer.
    watchHead: function (headId, barId) {
        try {
            var head = document.getElementById(headId), bar = document.getElementById(barId);
            if (!head || !bar || !('IntersectionObserver' in window)) return;
            if (window._imHeadObs) window._imHeadObs.disconnect();
            var top = Number.parseFloat(getComputedStyle(bar).top) || 0;
            var obs = new IntersectionObserver(function (entries) {
                entries.forEach(function (e) {
                    if (e.isIntersecting) bar.removeAttribute('data-stuck'); else bar.setAttribute('data-stuck', '');
                });
            }, { rootMargin: '-' + top + 'px 0px 0px 0px', threshold: 0 });
            obs.observe(head);
            window._imHeadObs = obs;
        } catch (e) { /* no-op */ }
    },
    // Bring a form field into view and put the caret in it (e.g. the first field a submit found missing).
    focusId: function (id) {
        try {
            var el = document.getElementById(id);
            if (!el) return;
            el.focus({ preventScroll: true });
            var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'center' });
        } catch (e) { /* no-op */ }
    },
    scrollToId: function (id) {
        try {
            var el = document.getElementById(id);
            if (!el) return;
            var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'center' });
        } catch (e) { /* no-op */ }
    },
    // Scroll a horizontally overflowing tab strip so its active tab is visible (phones), without moving the page.
    revealActiveTab: function (selector) {
        try {
            var strip = document.querySelector(selector);
            var tab = strip && strip.querySelector('.nav-link.active');
            if (!tab || strip.scrollWidth <= strip.clientWidth) return;
            var t = tab.getBoundingClientRect(), st = strip.getBoundingClientRect();
            var target = strip.scrollLeft + (t.left - st.left) - (strip.clientWidth - t.width) / 2;
            strip.scrollLeft = Math.max(0, target);
        } catch (e) { /* no-op */ }
    }
};
