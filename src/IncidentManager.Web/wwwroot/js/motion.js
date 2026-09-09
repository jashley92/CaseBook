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
    }
};
