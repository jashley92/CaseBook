// U-32/U-33: small UI-motion helpers (CSP-safe, self-hosted, no eval).
window.imMotion = {
    // Smooth-scroll an element into view by id (used by the timeline "jump to new" pill).
    // Falls back to an instant jump when the viewer prefers reduced motion.
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
